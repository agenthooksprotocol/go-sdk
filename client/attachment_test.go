package client

import (
	"context"
	"github.com/agenthooksprotocol/go-sdk/internal/ownedcontent"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/event"
)

func TestOwnedAttachmentsTypedLifetime(t *testing.T) {
	for _, mode := range []string{"metadata", "no-match"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := testClient(t, "fail-open")
			c.backends[0].subscriptions[0]["content"] = map[string]any{"default": "metadata"}
			if mode == "no-match" {
				c.backends[0].subscriptions = nil
			}
			opens, closes := 0, 0
			a := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
				opens++
				return io.NopCloser(strings.NewReader("file bytes")), nil
			}, func() error { closes++; return nil })
			var item ahp.ContentItem
			if err := item.UnmarshalJSON([]byte(`{"id":"report","kind":"attachment","mediaType":"application/octet-stream","selection":"metadata"}`)); err != nil {
				t.Fatal(err)
			}
			result, err := c.ToolBefore(context.Background(), event.ToolBeforeInput[map[string]any]{
				CallID: "call-1", Path: "execute", Name: "read_file", Origin: ahp.ExecutionEventToolOriginNative,
				Input: map[string]any{}, Items: ahp.Optional[[]*ahp.ContentItem]{Present: true, Value: []*ahp.ContentItem{&item}},
				ItemsSources: []*content.Source{a},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer result.Close()
			if opens != 0 || closes != 0 {
				t.Fatalf("premature materialization/close: %d/%d", opens, closes)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				raw, err := result.ReadContent(context.Background(), "/items/0")
				if err != nil || string(raw) != "file bytes" {
					t.Fatalf("read %q: %v", raw, err)
				}
				raw[0] = 'X'
			}
			if opens != 1 || closes != 1 {
				t.Fatalf("open/cleanup: %d/%d", opens, closes)
			}
			if err := result.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := result.ReadContent(context.Background(), "/items/0"); err == nil {
				t.Fatal("read after close")
			}
		})
	}
}

func TestOwnedAttachmentUnopenedCleanupAndReuse(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	c.backends[0].subscriptions = nil
	opens, closes := 0, 0
	a := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
		opens++
		return io.NopCloser(strings.NewReader("abc")), nil
	}, func() error { closes++; return nil })
	input := testInput()
	item := contentTestItem(nil)
	delete(item, "body")
	item["selection"] = "metadata"
	input["items"] = []any{item}
	result, err := c.Dispatch(context.Background(), "tool.before", input, WithContentSource("/items/0", a))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Dispatch(context.Background(), "tool.before", input, WithContentSource("/items/0", a)); err == nil {
		t.Fatal("reuse accepted")
	}
	if closes != 0 {
		t.Fatal("reuse retired first result")
	}
	_ = result.Close()
	_ = result.Close()
	if opens != 0 || closes != 1 {
		t.Fatalf("open/cleanup %d/%d", opens, closes)
	}
}

func TestOwnedAttachmentCopiesAndLimits(t *testing.T) {
	for _, limit := range []int64{2, 3} {
		c, _ := testClient(t, "fail-open")
		c.opts.MaxContentBytes = limit
		c.backends[0].subscriptions = nil
		raw := []byte("abc")
		a := content.NewAttachment(raw)
		raw[0] = 'X'
		input := testInput()
		item := contentTestItem(nil)
		delete(item, "body")
		item["selection"] = "metadata"
		input["items"] = []any{item, item}
		result, err := c.Dispatch(context.Background(), "tool.before", input, WithContentSource("/items/0", a), WithContentSource("/items/1", a))
		if limit == 2 {
			if err == nil || result != nil {
				t.Fatal("oversized eager owner admitted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/items/0", "/items/1"} {
			b, err := result.ReadContent(context.Background(), path)
			if limit == 2 {
				if err == nil {
					t.Fatal("limit ignored")
				}
			} else {
				if err != nil || string(b) != "abc" {
					t.Fatalf("%q %v", b, err)
				}
				b[0] = 'Y'
			}
		}
		_ = result.Close()
	}
}

func TestOwnedAttachmentAdmissionFailure(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	opens, closes := 0, 0
	a := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) { opens++; return nil, nil }, func() error { closes++; return nil })
	if _, err := c.Dispatch(context.Background(), "tool.before", nil, WithContentSource("/items/0", a)); err == nil {
		t.Fatal("bad input admitted")
	}
	if opens != 0 || closes != 1 {
		t.Fatal(opens, closes)
	}
}

func TestOwnedAttachmentAggregateLimit(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	c.opts.MaxContentBytes = 5
	c.backends[0].subscriptions = nil
	a := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("abc")), nil }, nil)
	b := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("def")), nil }, nil)
	input := testInput()
	item := contentTestItem(nil)
	delete(item, "body")
	item["selection"] = "metadata"
	input["items"] = []any{item, item}
	result, err := c.Dispatch(context.Background(), "tool.before", input, WithContentSource("/items/0", a), WithContentSource("/items/1", b))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if _, err := result.ReadContent(context.Background(), "/items/0"); err != nil {
		t.Fatal(err)
	}
	if _, err := result.ReadContent(context.Background(), "/items/1"); err == nil {
		t.Fatal("aggregate budget ignored")
	}
}

func TestSelectedUploadAndResultShareAttachmentOwner(t *testing.T) {
	var uploads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if string(raw) != "one immutable owner" {
			t.Errorf("upload = %q", raw)
		}
		uploads.Add(1)
		contentTestConfirm(w, "receiver-ref", raw)
	}))
	defer server.Close()
	c, _ := testClient(t, "fail-open", "fail-open")
	c.opts.Content.AuthorizeContent = contentTestAllow
	c.opts.Content.AllowLoopbackHTTP = true
	for i := range c.backends {
		sub := c.backends[i].subscriptions[0]
		projection := contentTestSubscription(server.URL)
		sub["content"], sub["upload"] = projection["content"], projection["upload"]
	}
	var opens atomic.Int32
	a := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
		opens.Add(1)
		return io.NopCloser(strings.NewReader("one immutable owner")), nil
	}, nil)
	input := testInput()
	item := contentTestItem(nil)
	delete(item, "body")
	item["selection"] = "metadata"
	input["items"] = []any{item}
	result, err := c.Dispatch(context.Background(), "tool.before", input, WithContentSource("/items/0", a))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if len(result.Diagnostics) != 0 {
		t.Fatal(result.Diagnostics)
	}
	if uploads.Load() != 2 || opens.Load() != 1 {
		t.Fatalf("uploads=%d opens=%d", uploads.Load(), opens.Load())
	}
	if result.attachments["/items/0"] != a {
		t.Fatal("returned content uses a second backing owner")
	}
	original, ok := ownedcontent.Available(a)
	if !ok {
		t.Fatal("upload did not materialize attachment")
	}
	// Upload and result access use the same no-copy budget/borrow path, not a
	// reference-indexed byte cache or a detached result snapshot.
	borrowed, err := result.attachmentBudget.snapshot(context.Background(), a, 64, 64)
	if err != nil || &borrowed[0] != &original[0] {
		t.Fatal("internal read copied attachment backing bytes", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	returned, err := result.ReadContent(context.Background(), "/items/0")
	if err != nil || string(returned) != string(original) {
		t.Fatal(err, string(returned))
	}
	if &returned[0] == &original[0] {
		t.Fatal("caller received mutable backing buffer")
	}
	returned[0] = 'X'
	if string(original) != "one immutable owner" {
		t.Fatal("caller changed shared content")
	}
}

func TestBareFileReferencesUseSharedOwners(t *testing.T) {
	var opens atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		contentTestConfirm(w, "file-receipt", raw)
	}))
	defer server.Close()
	c := &Hooks{opts: Options{Content: ContentOptions{AllowLoopbackHTTP: true, AuthorizeContent: contentTestAllow, Resolver: func(context.Context, string) (io.ReadCloser, error) {
		opens.Add(1)
		return io.NopCloser(strings.NewReader("file")), nil
	}}}}
	event := map[string]any{"type": "file.changed", "changes": []any{map[string]any{"path": "report.pdf", "after": map[string]any{"ref": "external-file"}}}}
	cfg := contentSourceConfig(nil)
	p, err := c.prepareBoundary(context.Background(), event, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), preparedContextKey{}, p)
	for _, backend := range []string{"one", "two"} {
		if _, err := c.projectContent(ctx, event, contentTestSubscription(server.URL), backend); err != nil {
			t.Fatal(err)
		}
	}
	result := &Result{Event: sdkJSON(event)}
	result.retainAttachments(cfg, ctx, p, 64)
	defer result.Close()
	if opens.Load() != 1 {
		t.Fatalf("file reference opened %d times", opens.Load())
	}
	if result.attachments["/changes/0/after"] != p.sources["/changes/0/after"] {
		t.Fatal("bare ref result copied owner")
	}
	raw, err := result.ReadContent(context.Background(), "/changes/0/after")
	if err != nil || string(raw) != "file" {
		t.Fatal(err, string(raw))
	}
}

func TestEagerAdmissionEnforcesLimits(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	c.backends[0].subscriptions = nil
	c.opts.MaxContentBytes = 2
	a := content.NewAttachment([]byte("abc"))
	input := testInput()
	item := contentTestItem(nil)
	delete(item, "body")
	item["selection"] = "metadata"
	input["items"] = []any{item}
	result, err := c.Dispatch(context.Background(), "tool.before", input, WithContentSource("/items/0", a))
	if err == nil || result != nil {
		t.Fatal("oversized eager owner admitted")
	}
	if _, ok := a.Available(); ok {
		t.Fatal("rejected owner retained bytes")
	}
}

func TestMetadataEagerOwnerCountsAgainstSelectedLazyUpload(t *testing.T) {
	var uploads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploads.Add(1)
		raw, _ := io.ReadAll(r.Body)
		contentTestConfirm(w, "receipt", raw)
	}))
	defer server.Close()
	c, _ := testClient(t, "fail-open")
	c.opts.MaxContentBytes = 8
	c.opts.Content.AuthorizeContent = contentTestAllow
	c.opts.Content.AllowLoopbackHTTP = true
	sub := c.backends[0].subscriptions[0]
	projection := contentTestSubscription(server.URL)
	sub["content"] = map[string]any{"default": "metadata", "files": "body"}
	sub["upload"] = projection["upload"]
	a := content.NewAttachment([]byte("123456"))
	b := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("abcdef")), nil }, nil)
	first := contentTestItem(nil)
	delete(first, "body")
	first["selection"] = "metadata"
	first["category"] = "text"
	second := map[string]any{"id": "file", "kind": "attachment", "mediaType": "application/octet-stream", "category": "files", "selection": "metadata"}
	input := testInput()
	input["items"] = []any{first, second}
	result, err := c.Dispatch(context.Background(), "tool.before", input, WithContentSource("/items/0", a), WithContentSource("/items/1", b))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if len(result.Diagnostics) == 0 || uploads.Load() != 0 {
		t.Fatal("metadata owner was omitted from live upload accounting")
	}
	raw, err := result.ReadContent(context.Background(), "/items/0")
	if err != nil || string(raw) != "123456" {
		t.Fatal(err, string(raw))
	}
}
