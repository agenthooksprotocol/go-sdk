package interop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func uploadTestReceiver() *lifecycleReceiver {
	return &lifecycleReceiver{changed: make(chan struct{}), uploads: map[string]string{}}
}

func TestUploadCanonicalOctetsAndImmutableReferences(t *testing.T) {
	t.Setenv("AHP_UPLOAD_TEST", "upload-only")
	s := uploadTestReceiver()
	bindings := map[string]UploadBinding{"scope": {Auth: &UploadAuth{Type: "bearer", TokenEnv: "AHP_UPLOAD_TEST"}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("AHP-Subscription") != "" || r.Header.Get("AHP-Content-Ref") != "" {
			t.Error("sender asserted wire identity")
		}
		if r.URL.RequestURI() != "/raw?exact=yes" {
			t.Error("changed route")
		}
		s.upload(w, r, bindings)
	}))
	defer server.Close()
	binding := bindings["scope"]
	binding.Endpoint = server.URL + "/raw?exact=yes"
	bindings["scope"] = binding
	previous := ""
	for _, body := range [][]byte{{0, 255, 128, 13, 10}, {}, {1, 2, 3}} {
		descriptor, status, err := UploadContent(context.Background(), binding, "untrusted-scope", "sender-ref", body)
		if err != nil || status != 201 {
			t.Fatalf("upload: %d %v", status, err)
		}
		ref := str(descriptor["ref"])
		if ref == "sender-ref" || ref == previous {
			t.Fatal("reference not freshly allocated")
		}
		previous = ref
		event := Object{"items": []any{Object{"content": descriptor}}}
		if err := checkContent(event, "scope", s.uploads); err != nil {
			t.Fatal(err)
		}
		if err := checkContent(event, "other", s.uploads); err == nil {
			t.Fatal("cross-scope access")
		}
		if !bytes.Equal([]byte(s.uploads[contentKey("scope", ref)]), body) {
			t.Fatal("octets changed")
		}
	}
}

func TestUploadRejectsInvalidConfirmations(t *testing.T) {
	body := []byte("abc")
	hash := fmt.Sprintf("%x", sha256.Sum256(body))
	valid := fmt.Sprintf(`{"ref":"allocated","size":3,"sha256":%q}`, hash)
	for _, tc := range []struct {
		name        string
		status      int
		media, body string
	}{
		{"valid", 201, "application/json", valid},
		{"204", 204, "application/json", ""},
		{"202", 202, "application/json", valid},
		{"missing", 201, "application/json", ""},
		{"wrong-media", 201, "text/plain", valid},
		{"empty-ref", 201, "application/json", strings.Replace(valid, "allocated", "", 1)},
		{"wrong-size", 201, "application/json", strings.Replace(valid, `"size":3`, `"size":4`, 1)},
		{"wrong-hash", 201, "application/json", strings.Replace(valid, hash, strings.Repeat("0", 64), 1)},
		{"extra-property", 201, "application/json", strings.Replace(valid, `"size":3`, `"size":3,"token":"secret"`, 1)},
		{"trailing-json", 201, "application/json", valid + `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {tc.media}}, Body: io.NopCloser(strings.NewReader(tc.body))}
			descriptor, _, err := confirmUpload(res, body)
			if (err == nil) != (tc.name == "valid") {
				t.Fatalf("descriptor=%v error=%v", descriptor, err)
			}
		})
	}
}

func TestUploadCredentialScopeAndFramingNegatives(t *testing.T) {
	t.Setenv("AHP_UPLOAD_A", "a")
	t.Setenv("AHP_UPLOAD_B", "b")
	limit := int64(3)
	bindings := map[string]UploadBinding{
		"a": {Endpoint: "http://127.0.0.1/a", Auth: &UploadAuth{Type: "bearer", TokenEnv: "AHP_UPLOAD_A"}, MaxBytes: &limit},
		"b": {Endpoint: "http://127.0.0.1/b", Auth: &UploadAuth{Type: "bearer", TokenEnv: "AHP_UPLOAD_B"}},
	}
	for _, tc := range []struct {
		name, path, token, hash string
		length                  int64
		want                    int
	}{
		{"ok", "/a", "a", "", 3, 201},
		{"missing-credential", "/a", "", "", 3, 401},
		{"event-token-not-upload-token", "/a", "event-token", "", 3, 401},
		{"wrong-grant", "/a", "b", "", 3, 403},
		{"unknown-route", "/absent", "a", "", 3, 404},
		{"hash-mismatch", "/a", "a", strings.Repeat("0", 64), 3, 400},
		{"length-mismatch", "/a", "a", "", 2, 400},
		{"oversize", "/a", "a", "", 4, 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := uploadTestReceiver()
			r := httptest.NewRequest("POST", tc.path, strings.NewReader("abc"))
			r.ContentLength = tc.length
			r.Header.Set("Content-Length", fmt.Sprint(tc.length))
			r.Header.Set("Content-Type", "application/octet-stream")
			hash := tc.hash
			if hash == "" {
				hash = fmt.Sprintf("%x", sha256.Sum256([]byte("abc")))
			}
			r.Header.Set("AHP-Content-SHA256", hash)
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			s.upload(w, r, bindings)
			if w.Code != tc.want {
				t.Fatalf("status %d want %d", w.Code, tc.want)
			}
			if tc.want != 201 && len(s.uploads) != 0 {
				t.Fatal("rejected bytes stored")
			}
		})
	}
}

func TestUploadFixtureMismatchReachesReceiver(t *testing.T) {
	s := uploadTestReceiver()
	bindings := map[string]UploadBinding{"anonymous": {}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.upload(w, r, bindings) }))
	defer server.Close()
	binding := UploadBinding{Endpoint: server.URL + "/upload"}
	for _, step := range []Object{{"size": float64(4)}, {"sha256": strings.Repeat("0", 64)}} {
		_, status, err := uploadFixture(context.Background(), binding, "ignored", "ignored", []byte("abc"), step)
		if status != 400 || err == nil {
			t.Fatalf("status=%d error=%v", status, err)
		}
	}
	if len(s.entries) != 2 || len(s.uploads) != 0 {
		t.Fatal("negative did not reach receiver")
	}
}

func TestUploadAliasesPreserveNegativeDescriptors(t *testing.T) {
	body := []byte("abc")
	descriptor := Object{"ref": "fixture", "size": float64(3), "sha256": fmt.Sprintf("%x", sha256.Sum256(body))}
	event := Object{"items": []any{Object{"content": descriptor}}}
	aliases := map[string]string{contentKey("scope", "fixture"): "allocated"}
	resolveUploadAliases(event, "scope", aliases)
	confirmed := map[string]string{contentKey("scope", "allocated"): string(body)}
	if err := checkContent(event, "scope", confirmed); err != nil {
		t.Fatal(err)
	}
	descriptor["size"] = float64(4)
	if err := checkContent(event, "scope", confirmed); err == nil {
		t.Fatal("mismatched descriptor accepted")
	}
	raw, _ := json.Marshal(event)
	if bytes.Contains(raw, []byte("subscriptionId")) {
		t.Fatal("wire subscription emitted")
	}
}

func TestUploadEventGrantsIndependentOfCorrelation(t *testing.T) {
	s := uploadTestReceiver()
	s.uploads[contentKey("granted", "ref")] = "abc"
	s.uploads[contentKey("forbidden", "other")] = "abc"
	s.eventScopes = []string{"granted"}
	available := s.eventContent()
	if available[contentKey("", "ref")] != "abc" {
		t.Fatal("missing explicit grant")
	}
	if _, ok := available[contentKey("", "other")]; ok {
		t.Fatal("ungranted scope leaked")
	}
}

func TestUploadSenderPolicyAndAnonymousIsolation(t *testing.T) {
	calls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; t.Error("redirect followed") }))
	defer destination.Close()
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("unexpected inherited credential")
		}
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer receiver.Close()
	binding := UploadBinding{Endpoint: receiver.URL}
	if _, status, err := UploadContent(context.Background(), binding, "", "", nil); err == nil || status != 307 {
		t.Fatalf("redirect status=%d err=%v", status, err)
	}
	if calls != 0 {
		t.Fatal("redirect destination reached")
	}
	limit := int64(0)
	binding.MaxBytes = &limit
	if _, status, err := UploadContent(context.Background(), binding, "", "", []byte("x")); err == nil || status != 0 {
		t.Fatal("maxBytes not enforced locally")
	}
	binding.MaxBytes = nil
	binding.Auth = &UploadAuth{Type: "bearer", TokenEnv: "AHP_TEST_ABSENT_UPLOAD_TOKEN"}
	t.Setenv(binding.Auth.TokenEnv, "")
	if _, status, err := UploadContent(context.Background(), binding, "", "", nil); err == nil || status != 0 {
		t.Fatal("missing credential accepted")
	}
}

func TestUploadReceiverFramingAndAnonymousPolicy(t *testing.T) {
	for _, name := range []string{"missing-length", "missing-hash", "repeated-hash", "encoded", "chunked", "wrong-method", "anonymous-not-granted"} {
		t.Run(name, func(t *testing.T) {
			s := uploadTestReceiver()
			r := httptest.NewRequest("POST", "/upload", strings.NewReader(""))
			r.Header.Set("Content-Length", "0")
			r.Header.Set("Content-Type", "application/octet-stream")
			r.Header.Set("AHP-Content-SHA256", fmt.Sprintf("%x", sha256.Sum256(nil)))
			bindings := map[string]UploadBinding{"anonymous": {}}
			switch name {
			case "missing-length":
				r.Header.Del("Content-Length")
			case "missing-hash":
				r.Header.Del("AHP-Content-SHA256")
			case "repeated-hash":
				r.Header.Add("AHP-Content-SHA256", r.Header.Get("AHP-Content-SHA256"))
			case "encoded":
				r.Header.Set("Content-Encoding", "gzip")
			case "chunked":
				r.TransferEncoding = []string{"chunked"}
			case "wrong-method":
				r.Method = "PUT"
			case "anonymous-not-granted":
				bindings = nil
			}
			w := httptest.NewRecorder()
			s.upload(w, r, bindings)
			if w.Code == 201 || len(s.uploads) != 0 {
				t.Fatal("malformed or unauthorized bytes accepted")
			}
		})
	}
}
