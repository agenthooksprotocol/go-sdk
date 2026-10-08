package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPublicDispatchRetainedResultsAndSources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		contentTestConfirm(w, "receiver-ref", raw)
	}))
	defer server.Close()
	c, transports := testClient(t, "fail-open")
	c.opts.Content.AuthorizeContent = contentTestAllow
	c.opts.Content.AllowLoopbackHTTP = true
	sub := c.backends[0].subscriptions[0]
	projection := contentTestSubscription(server.URL)
	sub["content"], sub["upload"] = projection["content"], projection["upload"]
	var sources []*ContentSource
	var results []*Result
	for i := 0; i < 4097; i++ {
		source := NewContentSource(io.NopCloser(strings.NewReader("original")))
		input := testInput()
		item := contentTestItem(nil)
		delete(item, "body")
		item["selection"] = "metadata"
		input["items"] = []any{item}
		result, err := c.Dispatch(context.Background(), "tool.before", input, WithContentSource("/items/0", source))
		if err != nil || len(result.Diagnostics) != 0 {
			t.Fatalf("call %d: %v %+v", i, err, result)
		}
		if _, ok := source.Available(); ok {
			t.Fatalf("call %d retained source snapshot", i)
		}
		if _, err := source.Snapshot(context.Background(), 64); err == nil {
			t.Fatal("completed source not retired")
		}
		sources = append(sources, source)
		results = append(results, result)
		// The recording test transport is not the SDK's content store.
		transports[0].calls = nil
	}
	for i, result := range results {
		raw, ok := result.Content("/items/0")
		if !ok || string(raw) != "original" {
			t.Fatalf("retained result %d: %q", i, raw)
		}
		raw[0] = 'X'
		again, _ := result.Content("/items/0")
		if string(again) != "original" {
			t.Fatal("result body aliased")
		}
		if sources[i].Claim() {
			t.Fatal("retained source reusable")
		}
	}
}

func TestPreparedResultOwnsReplacementBytes(t *testing.T) {
	raw := []byte("replacement")
	p := &preparedBoundary{bodies: map[string][]byte{"local": raw}}
	event := map[string]any{"items": []any{contentTestItem(map[string]any{"ref": "local"})}}
	result := &Result{content: preparedContent(event, p)}
	raw[0] = 'X'
	delete(p.bodies, "local")
	got, ok := result.Content("/items/0")
	if !ok || string(got) != "replacement" {
		t.Fatalf("replacement aliased preparation: %q", got)
	}
}

func TestPublicDispatchCancellationRetiresSource(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := testClient(t, "fail-open")
			c.opts.Content.AuthorizeContent = contentTestAllow
			c.opts.Content.AllowLoopbackHTTP = true
			sub := c.backends[0].subscriptions[0]
			projection := contentTestSubscription("http://127.0.0.1:1/upload")
			sub["content"], sub["upload"] = projection["content"], projection["upload"]
			r, w := io.Pipe()
			defer w.Close()
			source := NewContentSource(r)
			input := testInput()
			item := contentTestItem(nil)
			delete(item, "body")
			item["selection"] = "metadata"
			input["items"] = []any{item}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "timeout" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 500*time.Millisecond)
				defer stop()
			}
			done := make(chan error, 1)
			go func() {
				_, err := c.Dispatch(ctx, "tool.before", input, WithContentSource("/items/0", source))
				done <- err
			}()
			if _, err := w.Write([]byte("x")); err != nil && mode != "timeout" {
				t.Fatal(err)
			}
			if mode == "cancel" {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("boundary did not join cancellation")
			}
			if _, ok := source.Available(); ok {
				t.Fatal("cancelled source still available")
			}
			if _, err := source.Snapshot(context.Background(), 64); err == nil || err.Error() != "content source is retired" {
				t.Fatalf("not retired: %v", err)
			}
		})
	}
}
