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

func contentTestItem(body any) map[string]any {
	return map[string]any{"id": "item-1", "kind": "attachment", "mediaType": "application/octet-stream", "selection": "body", "body": body}
}
func contentTestSubscription(endpoint string) map[string]any {
	return map[string]any{"id": "subscription-1", "content": map[string]any{"default": "body"}, "upload": map[string]any{"endpoint": endpoint, "timeoutMs": 1000, "maxBytes": 128}}
}
func contentTestAllow(context.Context, ContentAuthorization) (bool, error) { return true, nil }
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
	c := &Client{opts: Options{Content: ContentOptions{Resolver: func(context.Context, string) (io.ReadCloser, error) {
		t.Fatal("unauthorized resolver call")
		return nil, nil
	}}}}
	item := contentTestItem(map[string]any{"ref": "private"})
	item["authorized"] = true
	item["permissions"] = map[string]any{"content": true}
	event := map[string]any{"items": []any{item}, "native": map[string]any{"secret": "private"}, "tool": map[string]any{"input": "private", "output": "private", "name": "tool"}}
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
		if got["selection"] != mode || got["body"] != nil || got["authorized"] != nil {
			t.Fatalf("unsafe view: %#v", got)
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
	c := &Client{}
	a := contentTestItem("secret")
	a["kind"] = "reasoning"
	a["category"] = "text"
	b := contentTestItem("secret")
	b["category"] = "custom"
	b["mediaType"] = "image/png"
	d := contentTestItem("secret")
	d["mediaType"] = "image/png"
	e := contentTestItem("secret")
	e["category"] = "unknown"
	sub := map[string]any{"content": map[string]any{"default": "omit", "text": "body", "reasoning": "metadata", "custom": "omit", "images": "metadata"}}
	out, err := c.projectContent(context.Background(), map[string]any{"items": []any{a, b, d, e}}, sub, "backend")
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
	c := &Client{opts: Options{MaxContentBytes: 128, Content: ContentOptions{AllowLoopbackHTTP: true, Resolver: func(_ context.Context, ref string) (io.ReadCloser, error) {
		reads++
		if ref != "https://never-fetch.example/private" {
			t.Errorf("unexpected resolver handle %q", ref)
		}
		return io.NopCloser(bytes.NewReader(raw)), nil
	}, AuthorizeContent: func(_ context.Context, scope ContentAuthorization) (bool, error) {
		if scope.BackendID != "backend-A" && scope.BackendID != "backend-B" {
			t.Error("missing backend scope")
		}
		if scope.Subscription["id"] != "subscription-1" || scope.Item["id"] != "item-1" {
			t.Error("missing subscription/item scope")
		}
		return true, nil
	}}}}
	sub := contentTestSubscription(server.URL + "/custom/raw?tenant=one")
	item := contentTestItem(map[string]any{"ref": "https://never-fetch.example/private"})
	event := map[string]any{"items": []any{item}}
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
	c := &Client{opts: Options{EventClient: &http.Client{Transport: eventTransport}, Content: ContentOptions{AllowLoopbackHTTP: true, AuthorizeContent: contentTestAllow}}}
	sub := contentTestSubscription(server.URL)
	sub["upload"].(map[string]any)["auth"] = map[string]any{"type": "bearer", "tokenEnv": "AHP_CONTENT_TEST_TOKEN"}
	for _, raw := range [][]byte{{0, 128, 255}, {}} {
		event := map[string]any{"items": []any{contentTestItem(raw)}}
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
		mutate func(map[string]any, map[string]any, *Client)
	}{
		{"local limit", func(_ map[string]any, _ map[string]any, c *Client) { c.opts.MaxContentBytes = 2 }},
		{"upload limit", func(_ map[string]any, s map[string]any, _ *Client) { s["upload"].(map[string]any)["maxBytes"] = 2 }},
		{"size mismatch", func(i map[string]any, _ map[string]any, _ *Client) { i["size"] = 4 }},
		{"hash mismatch", func(i map[string]any, _ map[string]any, _ *Client) { i["sha256"] = strings.Repeat("0", 64) }},
		{"reference mismatch", func(i map[string]any, _ map[string]any, c *Client) {
			i["body"] = map[string]any{"ref": "handle", "size": 4}
			c.opts.Content.Resolver = func(context.Context, string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader("abc")), nil
			}
		}},
		{"loopback disabled", func(_ map[string]any, _ map[string]any, c *Client) { c.opts.Content.AllowLoopbackHTTP = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := &Client{opts: Options{Content: ContentOptions{AllowLoopbackHTTP: true, AuthorizeContent: contentTestAllow}}}
			item := contentTestItem([]byte("abc"))
			sub := contentTestSubscription(server.URL)
			test.mutate(item, sub, c)
			if out, err := c.projectContent(context.Background(), map[string]any{"items": []any{item}}, sub, "backend"); err == nil || out != nil {
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
			c := &Client{opts: Options{Content: ContentOptions{AllowLoopbackHTTP: true, AuthorizeContent: contentTestAllow}}}
			out, err := c.projectContent(context.Background(), map[string]any{"items": []any{contentTestItem("abc")}}, contentTestSubscription(server.URL), "b")
			if err == nil || out != nil || redirected {
				t.Fatalf("invalid confirmation published: %v %v redirected=%v", out, err, redirected)
			}
		})
	}
}

func TestContentNativeRequiresExplicitProjection(t *testing.T) {
	calls := 0
	c := &Client{opts: Options{Content: ContentOptions{ProjectOpaque: func(_ context.Context, scope ContentAuthorization, path string, value any) (any, error) {
		calls++
		if scope.BackendID != "backend" || scope.Subscription["content"] == nil {
			t.Error("missing opaque scope")
		}
		return []any{"approved", path}, nil
	}}}}
	event := map[string]any{"native": []any{"secret"}, "input": map[string]any{"secret": "x"}}
	sub := map[string]any{"content": map[string]any{"default": "omit"}}
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
	c := &Client{}
	lookalike := contentTestItem("application-owned")
	event := map[string]any{"custom": lookalike, "items": []any{contentTestItem("secret")}}
	sub := map[string]any{"content": map[string]any{"default": "metadata"}}
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
	bad := map[string]any{"items": []any{map[string]any{"body": "secret"}}}
	if _, err = c.projectContent(context.Background(), bad, sub, "backend"); err == nil {
		t.Fatal("malformed descriptor bypassed projection")
	}
	for _, media := range []string{"application/json", " Application/JSON; charset=utf-8"} {
		item := contentTestItem("secret")
		item["mediaType"] = media
		if contentCategory(item) != "text" {
			t.Fatalf("JSON misclassified: %q", media)
		}
	}
}

func TestContentBareFileReferencesAreReceiverAllocated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		contentTestConfirm(w, "receiver-file", raw)
	}))
	defer server.Close()
	c := &Client{opts: Options{Content: ContentOptions{AllowLoopbackHTTP: true, AuthorizeContent: contentTestAllow, Resolver: func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("abc")), nil
	}}}}
	sub := contentTestSubscription(server.URL)
	event := map[string]any{"type": "file.changed", "changes": []any{map[string]any{"path": "file.txt", "after": map[string]any{"ref": "host-file"}}}}
	out, err := c.projectContent(context.Background(), event, sub, "backend")
	if err != nil {
		t.Fatal(err)
	}
	got := out["changes"].([]any)[0].(map[string]any)["after"].(map[string]any)
	if got["ref"] != "receiver-file" || len(got) != 1 {
		t.Fatalf("bare reference normalized or unallocated: %#v", got)
	}
	sub["content"] = map[string]any{"default": "metadata"}
	out, err = c.projectContent(context.Background(), event, sub, "backend")
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := out["changes"].([]any)[0].(map[string]any)["after"]; exists {
		t.Fatal("unselected bare reference leaked")
	}
}
