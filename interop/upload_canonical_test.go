package interop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCanonicalUploadRawBytesAndScope(t *testing.T) {
	t.Setenv("AHP_CANONICAL_UPLOAD", "upload-only")
	t.Setenv("AHP_CANONICAL_OTHER", "other-principal")
	auth := &UploadAuth{Type: "bearer", TokenEnv: "AHP_CANONICAL_UPLOAD"}
	receiver := &lifecycleReceiver{changed: make(chan struct{}), uploads: map[string]string{}, eventScopes: []string{"granted"}}
	bindings := map[string]UploadBinding{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/bytes?scope=exact" {
			t.Errorf("changed endpoint: %s", r.URL.RequestURI())
		}
		for _, name := range []string{"AHP-Content-Ref", "AHP-Subscription"} {
			if r.Header.Get(name) != "" {
				t.Errorf("unexpected wire identity %s", name)
			}
		}
		receiver.upload(w, r, bindings)
	}))
	defer server.Close()
	binding := UploadBinding{Endpoint: server.URL + "/bytes?scope=exact", Auth: auth}
	bindings["granted"] = binding
	bindings["other"] = UploadBinding{Endpoint: binding.Endpoint, Auth: &UploadAuth{Type: "bearer", TokenEnv: "AHP_CANONICAL_OTHER"}}
	seen := map[string]bool{}
	for _, body := range [][]byte{{0, 255, 128, '\r', '\n'}, {0, 255, 128, '\r', '\n'}, {}, []byte("changed")} {
		descriptor, status, err := UploadContent(context.Background(), binding, "other", "caller-ref", body)
		if err != nil || status != 201 {
			t.Fatalf("upload: status=%d error=%v", status, err)
		}
		ref := str(descriptor["ref"])
		if ref == "caller-ref" || seen[ref] {
			t.Fatalf("reference not newly allocated: %q", ref)
		}
		seen[ref] = true
		receiver.mu.Lock()
		stored, present := receiver.uploads[contentKey("granted", ref)]
		_, crossScope := receiver.uploads[contentKey("other", ref)]
		eventContent := receiver.eventContent()
		receiver.mu.Unlock()
		if !present || stored != string(body) || crossScope {
			t.Fatal("incorrect bytes or credential-derived scope")
		}
		event := Object{"items": []any{Object{"body": descriptor}}}
		if err := checkContent(event, "", eventContent); err != nil {
			t.Fatal(err)
		}
		if err := checkContent(event, "other", receiver.uploads); err == nil {
			t.Fatal("cross-scope descriptor accepted")
		}
	}
	// Omitted upload auth does not inherit the event or upload principal.
	anonymous := binding
	anonymous.Auth = nil
	if _, status, err := UploadContent(context.Background(), anonymous, "granted", "unused", nil); status != 401 || err == nil {
		t.Fatalf("anonymous: %d %v", status, err)
	}
}

func TestCanonicalUploadConfirmationNegatives(t *testing.T) {
	body := []byte{0, 255, 128}
	sum := fmt.Sprintf("%x", sha256.Sum256(body))
	valid := fmt.Sprintf(`{"ref":"allocated","size":3,"sha256":%q}`, sum)
	cases := []struct {
		name            string
		status          int
		media, response string
	}{
		{"accepted", 202, "application/json", valid},
		{"no-content", 204, "application/json", ""},
		{"missing", 201, "application/json", ""},
		{"wrong-media", 201, "text/plain", valid},
		{"empty-ref", 201, "application/json", strings.Replace(valid, "allocated", "", 1)},
		{"wrong-size", 201, "application/json", strings.Replace(valid, `"size":3`, `"size":2`, 1)},
		{"wrong-hash", 201, "application/json", strings.Replace(valid, sum, strings.Repeat("0", 64), 1)},
		{"uppercase-hash", 201, "application/json", strings.Replace(valid, sum, strings.ToUpper(sum), 1)},
		{"trailing-json", 201, "application/json", valid + "{}"},
		{"invalid-utf8", 201, "application/json", strings.Replace(valid, "allocated", string([]byte{255}), 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{tc.media}}, Body: io.NopCloser(strings.NewReader(tc.response))}
			descriptor, status, err := confirmUpload(res, body)
			if err == nil || descriptor != nil || status != tc.status {
				t.Fatalf("invalid confirmation accepted: %v %d %v", descriptor, status, err)
			}
		})
	}
}

func TestCanonicalUploadReceiverNegatives(t *testing.T) {
	body := []byte("abc")
	hash := fmt.Sprintf("%x", sha256.Sum256(body))
	receiver := &lifecycleReceiver{changed: make(chan struct{}), uploads: map[string]string{}}
	max := int64(3)
	bindings := map[string]UploadBinding{"anonymous": {Endpoint: "http://127.0.0.1/upload", MaxBytes: &max}}
	cases := []struct {
		name   string
		status int
		mutate func(*http.Request)
	}{
		{"method", 400, func(r *http.Request) { r.Method = "PUT" }},
		{"media", 400, func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }},
		{"encoding", 400, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{"chunked", 400, func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }},
		{"missing-length", 400, func(r *http.Request) { r.Header.Del("Content-Length") }},
		{"wrong-length", 400, func(r *http.Request) { r.ContentLength = 2; r.Header.Set("Content-Length", "2") }},
		{"missing-hash", 400, func(r *http.Request) { r.Header.Del("AHP-Content-SHA256") }},
		{"wrong-hash", 400, func(r *http.Request) { r.Header.Set("AHP-Content-SHA256", strings.Repeat("0", 64)) }},
		{"duplicate-hash", 400, func(r *http.Request) { r.Header.Add("AHP-Content-SHA256", hash) }},
		{"size-limit", 413, func(r *http.Request) { r.ContentLength = 4; r.Header.Set("Content-Length", "4") }},
		{"unknown-route", 404, func(r *http.Request) { r.URL.Path = "/unknown" }},
		{"event-token", 401, func(r *http.Request) { r.Header.Set("Authorization", "Bearer event-only") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://127.0.0.1/upload", bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/octet-stream")
			r.Header.Set("Content-Length", "3")
			r.Header.Set("AHP-Content-SHA256", hash)
			tc.mutate(r)
			w := httptest.NewRecorder()
			receiver.upload(w, r, bindings)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
			if len(receiver.uploads) != 0 {
				t.Fatal("failed upload allocated content")
			}
		})
	}
}

func TestCanonicalUploadFixtureNegativesReachReceiver(t *testing.T) {
	receiver := &lifecycleReceiver{changed: make(chan struct{}), uploads: map[string]string{}}
	bindings := map[string]UploadBinding{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { receiver.upload(w, r, bindings) }))
	defer server.Close()
	binding := UploadBinding{Endpoint: server.URL + "/upload", TimeoutMs: 1000}
	bindings["anonymous"] = binding
	for _, step := range []Object{{"size": float64(4)}, {"size": float64(2)}, {"sha256": strings.Repeat("0", 64)}} {
		descriptor, status, err := uploadFixture(context.Background(), binding, "ignored", "ignored", []byte("abc"), step)
		if status != 400 || err == nil || descriptor != nil {
			t.Fatalf("fixture negative did not receive rejection: %d %v %v", status, descriptor, err)
		}
	}
	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	if len(receiver.entries) != 3 || len(receiver.uploads) != 0 {
		t.Fatal("negative fixtures did not reach receiver without allocating content")
	}
}

func TestCanonicalUploadRejectsCredentialFraming(t *testing.T) {
	t.Setenv("AHP_CANONICAL_MALFORMED", "secret\r\nInjected: value")
	binding := UploadBinding{Endpoint: "http://127.0.0.1:1/upload", Auth: &UploadAuth{Type: "bearer", TokenEnv: "AHP_CANONICAL_MALFORMED"}}
	if _, status, err := UploadContent(context.Background(), binding, "", "", nil); err == nil || status != 0 || err.Error() != "invalid upload credential" {
		t.Fatalf("credential not rejected before request: %d %v", status, err)
	}
}

func TestCanonicalUploadAliasPreservesDescriptorValidation(t *testing.T) {
	body := []byte("abc")
	descriptor := Object{"ref": "local", "size": float64(3), "sha256": fmt.Sprintf("%x", sha256.Sum256(body))}
	event := Object{"items": []any{Object{"body": descriptor}}}
	resolveUploadAliases(event, "scope", map[string]string{contentKey("scope", "local"): "allocated"})
	confirmed := map[string]string{contentKey("scope", "allocated"): string(body)}
	if err := checkContent(event, "scope", confirmed); err != nil {
		t.Fatal(err)
	}
	descriptor["size"] = float64(2)
	if err := checkContent(event, "scope", confirmed); err == nil {
		t.Fatal("alias resolution hid corrupt metadata")
	}
	encoded, err := json.Marshal(event)
	if err != nil || bytes.Contains(encoded, []byte("subscriptionId")) || bytes.Contains(encoded, []byte(`"local"`)) {
		t.Fatal("local alias or subscription identity escaped into event")
	}
}

func TestCanonicalUploadInvalidConfirmationBlocksDependentEvent(t *testing.T) {
	for _, status := range []int{201, 202, 204} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var events atomic.Int32
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/upload" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(status)
					if status != 204 {
						_, _ = io.WriteString(w, `{"ref":"allocated","size":999,"sha256":"bad"}`)
					}
					return
				}
				events.Add(1)
				w.WriteHeader(500)
			}))
			defer receiver.Close()
			dir := t.TempDir()
			fixture := filepath.Join(dir, "scenario.json")
			req := request("dependent-event")
			scenario := lifecycleScenario{ID: "dependent-event", Requests: map[string]Object{"a": req}, Steps: []Object{
				{"op": "upload", "subscription": "body", "ref": "local", "bodyBase64": base64.StdEncoding.EncodeToString([]byte("abc"))},
				{"op": "send", "key": "a", "slot": "a", "subscription": "body"},
				{"op": "receive", "slot": "a"},
			}}
			c := LifecycleConfig{Config: Config{Transport: "http", Endpoint: receiver.URL, SchemaDir: schemaPath(t), ScenarioFile: fixture, ReportFile: filepath.Join(dir, "report.json")}, ControlEndpoint: receiver.URL, Uploads: map[string]UploadBinding{"body": {Endpoint: receiver.URL + "/upload"}}}
			// A body dependent on this upload must fail before dispatch, even when the
			// receiver returns a non-confirming 2xx status rather than malformed 201.
			event := obj(obj(req["params"])["event"])
			event["items"] = []any{Object{"id": "item", "kind": "text", "mediaType": "text/plain", "body": Object{"ref": "local", "size": float64(3), "sha256": fmt.Sprintf("%x", sha256.Sum256([]byte("abc")))}}}
			if err := writeAtomic(fixture, Object{"scenarios": []lifecycleScenario{scenario}}); err != nil {
				t.Fatal(err)
			}
			err := LifecycleClient(context.Background(), c)
			want := "unavailable scoped content reference"
			if status == 201 {
				want = "invalid upload confirmation"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("expected upload availability failure %q, got %v", want, err)
			}
			if events.Load() != 0 {
				t.Fatal("dependent event dispatched after failed confirmation")
			}
		})
	}
}

func TestCanonicalUploadConfirmationRejectsExtensions(t *testing.T) {
	body := []byte("abc")
	response := fmt.Sprintf(`{"ref":"allocated","size":3,"sha256":"%x","future":{"accepted":true}}`, sha256.Sum256(body))
	res := &http.Response{StatusCode: 201, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(response))}
	descriptor, status, err := confirmUpload(res, body)
	if err == nil || status != 201 || descriptor != nil {
		t.Fatalf("descriptor extension accepted: %v %d %v", descriptor, status, err)
	}
}

func TestCanonicalUploadConfigurationAllowsExtensions(t *testing.T) {
	var binding UploadBinding
	if err := json.Unmarshal([]byte(`{"endpoint":"http://127.0.0.1/upload","timeoutMs":1000,"maxBytes":null,"future":{"accepted":true}}`), &binding); err != nil || binding.Endpoint != "http://127.0.0.1/upload" {
		t.Fatalf("configuration extension rejected: %v", err)
	}
}

func TestCanonicalUploadScopesIndependentOfCorrelation(t *testing.T) {
	validator, err := newLifecycleValidator(schemaPath(t))
	if err != nil {
		t.Fatal(err)
	}
	req := request("jsonrpc-correlation")
	if err := validator.validate("intercept-request", req); err != nil {
		t.Fatalf("canonical request/event identity rejected: %v", err)
	}
	if _, err := Apply(req, lifecycleReply("event-identity")); err == nil {
		t.Fatal("response with mismatched request ID accepted")
	}
	if _, err := Apply(req, lifecycleReply("jsonrpc-correlation")); err != nil {
		t.Fatalf("request-correlated response rejected: %v", err)
	}
	receiver := &lifecycleReceiver{eventScopes: []string{"credential-scope"}, uploads: map[string]string{contentKey("credential-scope", "ref"): "granted", contentKey("jsonrpc-correlation", "hidden"): "private"}}
	content := receiver.eventContent()
	if content[contentKey("", "ref")] != "granted" {
		t.Fatal("credential-derived scope lost")
	}
	if _, ok := content[contentKey("", "hidden")]; ok {
		t.Fatal("JSON-RPC identity granted content access")
	}
}
