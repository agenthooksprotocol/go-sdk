package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// contentTestEvent completes the canonical tool.before envelope for private
// projection tests. Descriptor payloads are left untouched, including negatives.
func contentTestEvent(fields map[string]any) map[string]any {
	event := testInput()
	event["type"] = "tool.before"
	event["source"] = "urn:content-test"
	for key, value := range fields {
		event[key] = value
	}
	return event
}

func contentTestItem(body any) map[string]any {
	return map[string]any{"id": "item-1", "kind": "attachment", "mediaType": "application/octet-stream", "selection": "body", "body": body}
}
func contentTestSubscription(endpoint string) map[string]any {
	return map[string]any{"mode": "observe", "events": []any{"tool.before"}, "id": "subscription-1", "content": map[string]any{"default": "body"}, "upload": map[string]any{"endpoint": endpoint, "timeoutMs": 1000, "maxBytes": 128}}
}
func contentTestAllow(context.Context, ContentAuthorization) (bool, error) { return true, nil }

func TestContentAuthorizationTypedDescriptor(t *testing.T) {
	item := contentTestItem(map[string]any{"ref": "private"})
	item["category"] = "files"
	item["size"] = json.Number("9007199254740993")
	item["synthesized"] = false
	item["future"] = map[string]any{"kind": "attachment", "body": "opaque", "n": json.Number("9007199254740993")}
	sub := contentTestSubscription("https://uploads.example/raw")
	sub["future"] = map[string]any{"body": "subscription extension"}
	scope, err := contentAuthorization("read", "receiver", sub)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Subscription.ObserveSubscription.Present || scope.Subscription.ObserveSubscription.Value.Content == nil {
		t.Fatal("missing typed registered subscription")
	}
	if got := string(scope.Subscription.ObserveSubscription.Value.AdditionalProperties["future"]); got != `{"body":"subscription extension"}` {
		t.Fatal("subscription extension lost", got)
	}
	scope.Item, err = contentDescriptor(item, "body")
	if err != nil {
		t.Fatal(err)
	}
	if scope.Item.ID != "item-1" || scope.Item.Kind != "attachment" || scope.Item.Category.Value != "files" || scope.Item.Size.Value != "9007199254740993" || !scope.Item.Synthesized.Present || scope.Item.Synthesized.Value {
		t.Fatal("descriptor fields lost", scope.Item)
	}
	want := `{"body":"opaque","kind":"attachment","n":9007199254740993}`
	if got := string(scope.Item.AdditionalProperties["future"]); got != want {
		t.Fatal("opaque extension changed", got)
	}
	// The projection owns its raw bytes, including nested extension objects.
	item["future"].(map[string]any)["body"] = "changed"
	if got := string(scope.Item.AdditionalProperties["future"]); got != want {
		t.Fatal("projection aliases item", got)
	}
	scope.Item.AdditionalProperties["id"] = json.RawMessage(`"override"`)
	scope.Item.AdditionalProperties["category"] = json.RawMessage(`"override"`)
	scope.Item.AdditionalProperties["body"] = json.RawMessage(`"private"`)
	scope.Item.AdditionalProperties["text"] = json.RawMessage(`"private"`)
	scope.Item.AdditionalProperties["gap"] = json.RawMessage(`{}`)
	raw, err := json.Marshal(scope.Item)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["id"]) != `"item-1"` || string(fields["category"]) != `"files"` || string(fields["future"]) != want {
		t.Fatal("extension overrode known fields", string(raw))
	}
	for _, key := range []string{"body", "text", "gap"} {
		if _, ok := fields[key]; ok {
			t.Fatal("descriptor disclosed payload", string(raw))
		}
	}
}

func TestContentAuthorizationWriteDescriptorOmitsText(t *testing.T) {
	called := false
	c := &Hooks{opts: Options{Content: ContentOptions{AuthorizeContent: func(_ context.Context, scope ContentAuthorization) (bool, error) {
		called = true
		raw, err := json.Marshal(scope.Item)
		if err != nil {
			t.Fatal(err)
		}
		if scope.Operation != "write" || scope.Item.Kind != "text" || bytes.Contains(raw, []byte("private text")) {
			t.Fatal("invalid write descriptor", string(raw))
		}
		return true, nil
	}}}}
	part := map[string]any{"id": "text-1", "kind": "text", "mediaType": "text/plain", "selection": "body", "text": "private text"}
	if err := c.authorizeInlineWrite(context.Background(), part, contentTestSubscription("https://uploads.example/raw"), "receiver"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("write callback not called")
	}
}

func contentTestBody(t *testing.T, event map[string]any) map[string]any {
	t.Helper()
	items := event["items"].([]any)
	return items[0].(map[string]any)
}
func contentTestConfirm(w http.ResponseWriter, ref string, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(map[string]any{"ref": ref, "size": len(raw), "sha256": fmt.Sprintf("%x", sha256.Sum256(raw))})
}

func TestContentSelectionIsNotPermission(t *testing.T) {
	c := &Hooks{opts: Options{Content: ContentOptions{Resolver: func(context.Context, string) (io.ReadCloser, error) {
		t.Fatal("unauthorized resolver call")
		return nil, nil
	}}}}
	item := contentTestItem(map[string]any{"ref": "private"})
	item["authorized"] = true
	item["permissions"] = map[string]any{"content": true}
	item["future"] = map[string]any{"kind": "attachment", "body": map[string]any{"ref": "never-resolve"}, "input": map[string]any{"secret": "opaque-extra"}}
	event := contentTestEvent(map[string]any{"items": []any{item}, "native": map[string]any{"secret": "private"}, "tool": map[string]any{"input": map[string]any{"secret": "private"}, "output": "private", "name": "tool", "origin": "native"}})
	before := contentClone(event)
	for _, mode := range []string{"body", "metadata", "omit"} {
		sub := contentTestSubscription("https://uploads.example/raw")
		sub["includeNative"] = true
		sub["content"] = map[string]any{"default": mode}
		result, err := c.projectContent(context.Background(), event, sub, "backend-1")
		if err != nil {
			t.Fatal(err)
		}
		got := contentTestBody(t, result)
		if got["selection"] != mode || got["body"] != nil || got["authorized"] != true {
			t.Fatalf("unsafe view: %#v", got)
		}
		if !compositionEqual(got["future"], item["future"]) || !compositionEqual(got["permissions"], item["permissions"]) {
			t.Fatal("opaque descriptor metadata changed")
		}
		if mode == "body" && got["gap"].(map[string]any)["reason"] != "withheld" {
			t.Fatalf("missing withholding gap: %#v", got)
		}
		if result["native"] != nil || result["tool"].(map[string]any)["input"] != nil {
			t.Fatal("opaque content disclosed")
		}
	}
	if !reflect.DeepEqual(event, before) {
		t.Fatal("mutated host event")
	}
}

func TestContentCategoryPrecedence(t *testing.T) {
	c := &Hooks{}
	a := contentTestItem(map[string]any{"ref": "secret"})
	// Reasoning kind precedence is a classifier rule, not a declared attachment kind.
	if got := contentCategory(map[string]any{"kind": "reasoning", "category": "text"}); got != "reasoning" {
		t.Fatalf("reasoning precedence = %q", got)
	}
	a["category"] = "reasoning"
	b := contentTestItem(map[string]any{"ref": "secret"})
	b["category"] = "custom"
	b["mediaType"] = "image/png"
	d := contentTestItem(map[string]any{"ref": "secret"})
	d["mediaType"] = "image/png"
	e := contentTestItem(map[string]any{"ref": "secret"})
	e["category"] = "unknown"
	sub := map[string]any{"mode": "observe", "events": []any{"tool.before"}, "content": map[string]any{"default": "omit", "text": "body", "reasoning": "metadata", "custom": "omit", "images": "metadata"}}
	out, err := c.projectContent(context.Background(), contentTestEvent(map[string]any{"items": []any{a, b, d, e}}), sub, "backend")
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"metadata", "omit", "metadata", "omit"} {
		got := out["items"].([]any)[i].(map[string]any)
		if got["selection"] != want || got["body"] != nil {
			t.Fatalf("item %d: %#v", i, got)
		}
	}
	if _, err = c.projectContent(context.Background(), map[string]any{}, map[string]any{}, "backend"); err == nil {
		t.Fatal("missing default accepted")
	}
}

func TestContentRemoteHandlesUploadPerReceiver(t *testing.T) {
	raw := []byte{0, 255, 128, 13, 10}
	sum := fmt.Sprintf("%x", sha256.Sum256(raw))
	calls := 0
	reads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		data, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || r.URL.RequestURI() != "/custom/raw?tenant=one" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("AHP-Content-SHA256") != sum || r.ContentLength != int64(len(raw)) || len(r.TransferEncoding) != 0 || !bytes.Equal(data, raw) {
			t.Errorf("invalid upload request: %s %s %v %v", r.Method, r.URL, r.Header, data)
		}
		contentTestConfirm(w, fmt.Sprintf("receiver-handle-%d", calls), data)
	}))
	defer server.Close()
	c := &Hooks{opts: Options{MaxContentBytes: 128, Content: ContentOptions{AllowLoopbackHTTP: true, Resolver: func(_ context.Context, ref string) (io.ReadCloser, error) {
		reads++
		if ref != "https://never-fetch.example/private" {
			t.Errorf("unexpected resolver handle %q", ref)
		}
		return io.NopCloser(bytes.NewReader(raw)), nil
	}, AuthorizeContent: func(_ context.Context, scope ContentAuthorization) (bool, error) {
		if scope.BackendID != "backend-A" && scope.BackendID != "backend-B" {
			t.Error("missing backend scope")
		}
		if scope.SubscriptionID != "subscription-1" || scope.Item.ID != "item-1" {
			t.Error("missing subscription/item scope")
		}
		return true, nil
	}}}}
	sub := contentTestSubscription(server.URL + "/custom/raw?tenant=one")
	item := contentTestItem(map[string]any{"ref": "https://never-fetch.example/private"})
	event := contentTestEvent(map[string]any{"items": []any{item}})
	for i, backend := range []string{"backend-A", "backend-B"} {
		out, err := c.projectContent(context.Background(), event, sub, backend)
		if err != nil {
			t.Fatal(err)
		}
		body := contentTestBody(t, out)["body"].(map[string]any)
		if len(body) != 1 || body["ref"] != fmt.Sprintf("receiver-handle-%d", i+1) {
			t.Fatalf("reference not allocated per receiver: %#v", body)
		}
	}
	if calls != 2 || reads != 2 {
		t.Fatalf("uploads/resolutions: %d/%d", calls, reads)
	}
	if item["body"].(map[string]any)["ref"] != "https://never-fetch.example/private" {
		t.Fatal("host reference replaced")
	}
}

func TestContentRawUploadsAndIndependentAuthentication(t *testing.T) {
	t.Setenv("AHP_CONTENT_TEST_TOKEN", "upload-only")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		data, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer upload-only" || r.Header.Get("X-Event-Secret") != "" || r.ContentLength != int64(len(data)) || len(r.TransferEncoding) != 0 {
			t.Errorf("unsafe framing: %#v", r)
		}
		contentTestConfirm(w, "allocated", data)
	}))
	defer server.Close()
	eventTransport := contentTestRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("event client used for upload")
		return nil, fmt.Errorf("event client used")
	})
	c := &Hooks{opts: Options{EventClient: &http.Client{Transport: eventTransport}, Content: ContentOptions{AllowLoopbackHTTP: true, AuthorizeContent: contentTestAllow}}}
	sub := contentTestSubscription(server.URL)
	sub["upload"].(map[string]any)["auth"] = map[string]any{"type": "bearer", "tokenEnv": "AHP_CONTENT_TEST_TOKEN"}
	for _, raw := range [][]byte{{0, 128, 255}, {}} {
		c.opts.Content.Resolver = func(context.Context, string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
		event := contentTestEvent(map[string]any{"items": []any{contentTestItem(map[string]any{"ref": "host-bytes"})}})
		if _, err := c.projectContent(context.Background(), event, sub, "b"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}

type contentTestRoundTripper func(*http.Request) (*http.Response, error)

func (f contentTestRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestContentLimitsAndDeclaredIntegrity(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		raw, _ := io.ReadAll(r.Body)
		contentTestConfirm(w, "allocated", raw)
	}))
	defer server.Close()
	for _, test := range []struct {
		name   string
		mutate func(map[string]any, map[string]any, *Hooks)
	}{
		{"local limit", func(_ map[string]any, _ map[string]any, c *Hooks) { c.opts.MaxContentBytes = 2 }},
		{"upload limit", func(_ map[string]any, s map[string]any, _ *Hooks) { s["upload"].(map[string]any)["maxBytes"] = 2 }},
		{"size mismatch", func(i map[string]any, _ map[string]any, _ *Hooks) { i["size"] = 4 }},
		{"hash mismatch", func(i map[string]any, _ map[string]any, _ *Hooks) { i["sha256"] = strings.Repeat("0", 64) }},
		{"reference mismatch", func(i map[string]any, _ map[string]any, c *Hooks) {
			i["body"] = map[string]any{"ref": "handle", "size": 4}
			c.opts.Content.Resolver = func(context.Context, string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader("abc")), nil
			}
		}},
		{"loopback disabled", func(_ map[string]any, _ map[string]any, c *Hooks) { c.opts.Content.AllowLoopbackHTTP = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := &Hooks{opts: Options{Content: ContentOptions{AllowLoopbackHTTP: true, AuthorizeContent: contentTestAllow}}}
			c.opts.Content.Resolver = func(context.Context, string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader("abc")), nil
			}
			item := contentTestItem(map[string]any{"ref": "host-bytes"})
			sub := contentTestSubscription(server.URL)
			test.mutate(item, sub, c)
			if out, err := c.projectContent(context.Background(), contentTestEvent(map[string]any{"items": []any{item}}), sub, "backend"); err == nil || out != nil {
				t.Fatalf("failed preparation leaked event: %#v %v", out, err)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("integrity failures uploaded: %d", calls)
	}
}

func TestContentRejectsInvalidConfirmationsAndRedirects(t *testing.T) {
	goodHash := fmt.Sprintf("%x", sha256.Sum256([]byte("abc")))
	for _, test := range []struct {
		name        string
		status      int
		media, body string
	}{
		{"accepted", 202, "application/json", `{}`}, {"empty", 204, "application/json", ``},
		{"wrong media", 201, "text/plain", `{}`},
		{"wrong hash", 201, "application/json", `{"ref":"r","size":3,"sha256":"` + strings.Repeat("0", 64) + `"}`},
		{"wrong size", 201, "application/json", `{"ref":"r","size":4,"sha256":"` + goodHash + `"}`},
		{"extra field", 201, "application/json", `{"ref":"r","size":3,"sha256":"` + goodHash + `","secret":"x"}`},
		{"duplicate ref", 201, "application/json", `{"ref":"first","ref":"r","size":3,"sha256":"` + goodHash + `"}`},
		{"trailing value", 201, "application/json", `{"ref":"r","size":3,"sha256":"` + goodHash + `"} {}`},
		{"redirect", 307, "application/json", `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			redirected := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirect" {
					redirected = true
					contentTestConfirm(w, "r", []byte("abc"))
					return
				}
				w.Header().Set("Location", "/redirect")
				w.Header().Set("Content-Type", test.media)
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			c := &Hooks{opts: Options{Content: ContentOptions{AllowLoopbackHTTP: true, AuthorizeContent: contentTestAllow, Resolver: func(context.Context, string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader("abc")), nil
			}}}}
			out, err := c.projectContent(context.Background(), contentTestEvent(map[string]any{"items": []any{contentTestItem(map[string]any{"ref": "abc"})}}), contentTestSubscription(server.URL), "b")
			if err == nil || out != nil || redirected {
				t.Fatalf("invalid confirmation published: %v %v redirected=%v", out, err, redirected)
			}
		})
	}
}

func TestContentNativeRequiresExplicitProjection(t *testing.T) {
	calls := 0
	c := &Hooks{opts: Options{Content: ContentOptions{ProjectOpaque: func(_ context.Context, scope ContentAuthorization, path string, value any) (any, error) {
		calls++
		if scope.BackendID != "backend" || !scope.Subscription.ObserveSubscription.Present || scope.Subscription.ObserveSubscription.Value.Content == nil {
			t.Error("missing opaque scope")
		}
		return []any{"approved", path}, nil
	}}}}
	event := contentTestEvent(map[string]any{"native": []any{"secret"}, "input": map[string]any{"secret": "x"}})
	sub := map[string]any{"mode": "observe", "events": []any{"tool.before"}, "content": map[string]any{"default": "omit"}}
	out, err := c.projectContent(context.Background(), event, sub, "backend")
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := out["native"]; exists || calls != 1 {
		t.Fatal("native default disclosure")
	}
	sub["includeNative"] = true
	out, err = c.projectContent(context.Background(), event, sub, "backend")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out["native"], []any{"approved", "/native"}) || calls != 3 {
		t.Fatalf("native wrapper introduced: %#v", out)
	}
}

func TestContentOnlyProjectsDeclaredDescriptorPositions(t *testing.T) {
	c := &Hooks{}
	lookalike := contentTestItem("application-owned")
	event := contentTestEvent(map[string]any{"custom": lookalike, "items": []any{contentTestItem(map[string]any{"ref": "secret"})}})
	sub := map[string]any{"mode": "observe", "events": []any{"tool.before"}, "content": map[string]any{"default": "metadata"}}
	out, err := c.projectContent(context.Background(), event, sub, "backend")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out["custom"], lookalike) {
		t.Fatal("application data was normalized")
	}
	if contentTestBody(t, out)["body"] != nil {
		t.Fatal("normalized body disclosed")
	}
	bad := contentTestEvent(map[string]any{"items": []any{map[string]any{"body": "secret"}}})
	if _, err = c.projectContent(context.Background(), bad, sub, "backend"); err == nil {
		t.Fatal("malformed descriptor bypassed projection")
	}
	for _, media := range []string{"application/json", " Application/JSON; charset=utf-8"} {
		item := contentTestItem(map[string]any{"ref": "secret"})
		item["mediaType"] = media
		if contentCategory(item) != "text" {
			t.Fatalf("JSON misclassified: %q", media)
		}
	}
}

func TestContentFileReferencesAreReceiverAllocated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		contentTestConfirm(w, "receiver-file", raw)
	}))
	defer server.Close()
	c := &Hooks{opts: Options{Content: ContentOptions{AllowLoopbackHTTP: true, AuthorizeContent: contentTestAllow, Resolver: func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("abc")), nil
	}}}}
	sub := contentTestSubscription(server.URL)
	event := map[string]any{"type": "file.changed", "id": "file-event", "time": "2026-01-01T00:00:00Z", "source": "urn:content-test", "changes": []any{map[string]any{"path": "file.txt", "operation": "update", "agentCaused": true, "after": contentTestItem(map[string]any{"ref": "host-file"})}}}
	// FileChangedEvent.after is a ContentItem, not a bare ContentReference.
	invalid := contentClone(event).(map[string]any)
	invalid["changes"].([]any)[0].(map[string]any)["after"] = map[string]any{"ref": "host-file"}
	if out, err := c.projectContent(context.Background(), invalid, sub, "backend"); err == nil || out != nil {
		t.Fatal("bare reference accepted in declared content-item slot")
	}
	out, err := c.projectContent(context.Background(), event, sub, "backend")
	if err != nil {
		t.Fatal(err)
	}
	got := out["changes"].([]any)[0].(map[string]any)["after"].(map[string]any)
	if body := sdkObj(got["body"]); body["ref"] != "receiver-file" || len(body) != 1 {
		t.Fatalf("reference unallocated: %#v", got)
	}
	if got["id"] != "item-1" || got["kind"] != "attachment" {
		t.Fatalf("descriptor metadata changed: %#v", got)
	}
	sub["content"] = map[string]any{"default": "metadata"}
	out, err = c.projectContent(context.Background(), event, sub, "backend")
	if err != nil {
		t.Fatal(err)
	}
	got = out["changes"].([]any)[0].(map[string]any)["after"].(map[string]any)
	if got["body"] != nil || got["selection"] != "metadata" {
		t.Fatal("unselected reference leaked", got)
	}
}
