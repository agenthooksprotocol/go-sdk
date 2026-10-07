package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type sourceTestReader struct {
	io.Reader
	reads, closes atomic.Int32
}

func (r *sourceTestReader) Read(p []byte) (int, error) { r.reads.Add(1); return r.Reader.Read(p) }
func (r *sourceTestReader) Close() error               { r.closes.Add(1); return nil }
func sourceTestBinding(t *testing.T, source *ContentSource) (context.Context, map[string]any, interceptConfig) {
	t.Helper()
	item := contentTestItem(nil)
	delete(item, "body")
	item["selection"] = "metadata"
	event := map[string]any{"items": []any{item}}
	cfg := contentSourceConfig([]InterceptOption{WithContentSource("/items/0", source)})
	ctx, err := cfg.bindSources(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, event, cfg
}

func TestContentSourceUnusedIsNeverReadAndClosed(t *testing.T) {
	for _, mode := range []string{"metadata", "omit", "body"} {
		t.Run(mode, func(t *testing.T) {
			reader := &sourceTestReader{Reader: strings.NewReader("private")}
			source := NewContentSource(reader)
			if reader.reads.Load() != 0 {
				t.Fatal("construction read")
			}
			ctx, event, cfg := sourceTestBinding(t, source)
			c := &Hooks{}
			sub := contentTestSubscription("https://example.test/upload")
			sub["content"] = map[string]any{"default": mode}
			if _, err := c.projectContent(ctx, event, sub, "backend"); err != nil {
				t.Fatal(err)
			}
			cfg.closeSources()
			cfg.closeSources()
			if reader.reads.Load() != 0 || reader.closes.Load() != 1 {
				t.Fatalf("reads=%d closes=%d", reader.reads.Load(), reader.closes.Load())
			}
		})
	}
}

func TestContentSourceConcurrentFanoutSnapshotsOnce(t *testing.T) {
	var uploads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if string(raw) != "actual" {
			t.Errorf("raw=%q", raw)
		}
		uploads.Add(1)
		contentTestConfirm(w, "receiver-ref", raw)
	}))
	defer server.Close()
	reader := &sourceTestReader{Reader: strings.NewReader("actual")}
	source := NewContentSource(reader)
	ctx, event, cfg := sourceTestBinding(t, source)
	defer cfg.closeSources()
	c := &Hooks{opts: Options{Content: ContentOptions{AuthorizeContent: contentTestAllow, AllowLoopbackHTTP: true}}}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := c.projectContent(ctx, event, contentTestSubscription(server.URL), "backend")
			if err != nil {
				t.Error(err)
				return
			}
			item := contentTestBody(t, out)
			if item["size"] != int64(6) || item["sha256"] == nil {
				t.Errorf("missing actual metadata: %#v", item)
			}
		}()
	}
	wg.Wait()
	if uploads.Load() != 4 || reader.closes.Load() != 1 || reader.reads.Load() != 2 {
		t.Fatalf("uploads=%d closes=%d reads=%d", uploads.Load(), reader.closes.Load(), reader.reads.Load())
	}
	if contentTestBody(t, event)["body"] != nil {
		t.Fatal("host descriptor mutated")
	}
}

func TestContentSourceLimitFailureIsCached(t *testing.T) {
	reader := &sourceTestReader{Reader: strings.NewReader("too long")}
	source := NewContentSource(reader)
	if _, err := source.Snapshot(context.Background(), 2); err == nil {
		t.Fatal("expected byte limit")
	}
	reads := reader.reads.Load()
	if _, err := source.Snapshot(context.Background(), 100); err == nil {
		t.Fatal("failure not cached")
	}
	if reader.reads.Load() != reads || reader.closes.Load() != 1 {
		t.Fatal("source retried or not closed")
	}
}

func TestContentSourceCancelledBeforeRead(t *testing.T) {
	reader := &sourceTestReader{Reader: strings.NewReader("private")}
	source := NewContentSource(reader)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Snapshot(ctx, 100); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if reader.reads.Load() != 0 || reader.closes.Load() != 1 {
		t.Fatal("cancelled source consumed or leaked")
	}
}

func TestContentSourceDeferredModificationBaseline(t *testing.T) {
	reader := &sourceTestReader{Reader: strings.NewReader("original")}
	source := NewContentSource(reader)
	ctx, event, cfg := sourceTestBinding(t, source)
	defer cfg.closeSources()
	event["type"] = "model.response.complete"
	p := &preparedBoundary{sources: cfg.sources, slots: map[string][]string{"content": {"/items/0"}}, bodies: map[string][]byte{}, absent: map[string]bool{}}
	values, err := p.values(event)
	if err != nil || len(values) != 0 || reader.reads.Load() != 0 {
		t.Fatalf("eager values: %#v %v", values, err)
	}
	if _, err := source.Snapshot(ctx, 128); err != nil {
		t.Fatal(err)
	}
	values, err = p.values(event)
	if err != nil || values["content"] != "original" {
		t.Fatalf("missing lazy baseline: %#v %v", values, err)
	}
}

func TestContentSourceSnapshotIsDetached(t *testing.T) {
	source := NewContentSource(io.NopCloser(strings.NewReader("original")))
	raw, err := source.Snapshot(context.Background(), 128)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 'X'
	available, ok := source.Available()
	if !ok || string(available) != "original" {
		t.Fatalf("snapshot aliased: %q", available)
	}
	available[0] = 'Y'
	again, _ := source.Available()
	if string(again) != "original" {
		t.Fatal("available snapshot aliased")
	}
}

func TestContentSourceProjectionTimeoutClosesRead(t *testing.T) {
	reader, _ := cancellationPipe(t)
	source := NewContentSource(reader)
	ctx, event, cfg := sourceTestBinding(t, source)
	defer cfg.closeSources()
	c := &Hooks{opts: Options{Content: ContentOptions{AuthorizeContent: contentTestAllow}}}
	sub := contentTestSubscription("https://example.test/upload")
	sdkObj(sub["upload"])["timeoutMs"] = 10
	_, err := c.projectContent(ctx, event, sub, "backend")
	if !errors.Is(err, context.DeadlineExceeded) || reader.closes.Load() != 1 {
		t.Fatalf("timeout=%v closes=%d", err, reader.closes.Load())
	}
}

func TestContentSourceFailureAndUnusedBoundaryClose(t *testing.T) {
	for _, mode := range []string{"unmatched", "metadata", "invalid", "closed"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := testClient(t, "fail-open")
			reader := &sourceTestReader{Reader: strings.NewReader("private")}
			source := NewContentSource(reader)
			input := testInput()
			item := contentTestItem(nil)
			delete(item, "body")
			item["selection"] = "metadata"
			input["items"] = []any{item}
			if mode == "unmatched" {
				c.backends[0].subscriptions[0]["events"] = []any{"tool.after"}
			}
			if mode == "invalid" {
				input["source"] = "forbidden"
			}
			if mode == "closed" {
				_ = c.Close()
			}
			_, err := c.dispatch(context.Background(), "tool.before", input, WithContentSource("/items/0", source))
			if (mode == "invalid" || mode == "closed") && err == nil {
				t.Fatal("invalid call accepted")
			}
			if reader.reads.Load() != 0 || reader.closes.Load() != 1 {
				t.Fatalf("reads=%d closes=%d err=%v", reader.reads.Load(), reader.closes.Load(), err)
			}
		})
	}
}

func TestContentSourceElicitationLazyPinnedContract(t *testing.T) {
	event, _ := elicitationFixture("request", "form", elicitationForm)
	item := preparedAt(event, "/elicitation/request")
	delete(item, "body")
	item["selection"] = "metadata"
	reader := &sourceTestReader{Reader: strings.NewReader(elicitationForm)}
	source := NewContentSource(reader)
	cfg := contentSourceConfig([]InterceptOption{WithContentSource("/elicitation/request", source)})
	defer cfg.closeSources()
	ctx, err := cfg.bindSources(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	c := &Hooks{}
	p, err := c.prepareBoundary(ctx, event, map[string]any{"effects": []any{"return"}}, cfg)
	if err != nil || reader.reads.Load() != 0 {
		t.Fatalf("eager preparation: %v", err)
	}
	if _, err = p.values(event); err != nil || p.snapshot.request != "" {
		t.Fatalf("metadata preparation: %v", err)
	}
	if _, err = source.Snapshot(ctx, 4096); err != nil {
		t.Fatal(err)
	}
	if _, err = p.values(event); err != nil {
		t.Fatal(err)
	}
	if err = validateElicitationAnswer(event, p.snapshot, map[string]any{"action": "accept", "content": map[string]any{"x": "a"}}); err != nil {
		t.Fatal(err)
	}
	if err = validateElicitationAnswer(event, p.snapshot, map[string]any{"action": "accept", "content": map[string]any{"x": "b"}}); err == nil {
		t.Fatal("invalid pinned form value accepted")
	}
}

func TestContentSourceElicitationInvalidBodyNeverUploads(t *testing.T) {
	var uploads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { uploads.Add(1) }))
	defer server.Close()
	event, _ := elicitationFixture("request", "form", elicitationForm)
	item := preparedAt(event, "/elicitation/request")
	delete(item, "body")
	item["selection"] = "metadata"
	source := NewContentSource(io.NopCloser(strings.NewReader(`{"message":"no schema"}`)))
	cfg := contentSourceConfig([]InterceptOption{WithContentSource("/elicitation/request", source)})
	defer cfg.closeSources()
	ctx, err := cfg.bindSources(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	c := &Hooks{opts: Options{Content: ContentOptions{AuthorizeContent: contentTestAllow, AllowLoopbackHTTP: true}}}
	p, err := c.prepareBoundary(ctx, event, map[string]any{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx = context.WithValue(ctx, preparedContextKey{}, p)
	if _, err = c.projectContent(ctx, event, contentTestSubscription(server.URL), "backend"); err == nil {
		t.Fatal("invalid elicitation accepted")
	}
	if uploads.Load() != 0 {
		t.Fatal("invalid pinned schema uploaded")
	}
}

func TestContentSourceOccurrenceBudget(t *testing.T) {
	first := NewContentSource(io.NopCloser(strings.NewReader("123")))
	second := NewContentSource(io.NopCloser(strings.NewReader("456")))
	b := &contentSourceBudget{seen: map[*ContentSource]bool{}}
	if _, err := b.snapshot(context.Background(), first, 4, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := b.snapshot(context.Background(), first, 4, 4); err != nil {
		t.Fatal("repeat charged twice", err)
	}
	if _, err := b.snapshot(context.Background(), second, 4, 4); err == nil {
		t.Fatal("aggregate source limit not enforced")
	}
}

func TestContentSourceUploadLimitsAreReceiverSpecific(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		contentTestConfirm(w, "ref", raw)
	}))
	defer server.Close()
	reader := &sourceTestReader{Reader: strings.NewReader("actual")}
	source := NewContentSource(reader)
	ctx, event, cfg := sourceTestBinding(t, source)
	defer cfg.closeSources()
	c := &Hooks{opts: Options{Content: ContentOptions{AuthorizeContent: contentTestAllow, AllowLoopbackHTTP: true}}}
	small := contentTestSubscription(server.URL)
	sdkObj(small["upload"])["maxBytes"] = 2
	if _, err := c.projectContent(ctx, event, small, "small"); err == nil {
		t.Fatal("small receiver limit ignored")
	}
	if _, err := c.projectContent(ctx, event, contentTestSubscription(server.URL), "larger"); err != nil {
		t.Fatal("small receiver poisoned shared snapshot", err)
	}
	if reader.reads.Load() != 2 || reader.closes.Load() != 1 {
		t.Fatal("fanout re-read source")
	}
}
