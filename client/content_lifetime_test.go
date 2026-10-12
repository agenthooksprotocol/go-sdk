package client

import (
	"context"
	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/event"
	"github.com/agenthooksprotocol/go-sdk/internal/ownedcontent"
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
	var sources []*content.Source
	var results []*Result
	for i := 0; i < 4097; i++ {
		source := content.NewSource(io.NopCloser(strings.NewReader("original")))
		input := testInput()
		item := contentTestItem(nil)
		delete(item, "body")
		item["selection"] = "metadata"
		input["items"] = []any{item}
		result, err := c.Dispatch(context.Background(), event.ToolBefore, input, WithContentSource("/items/0", source))
		if err != nil || len(result.Diagnostics) != 0 {
			t.Fatalf("call %d: %v %+v", i, err, result)
		}
		if result.attachments["/items/0"] != source {
			t.Fatal("result replaced the attachment owner")
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
		if ownedcontent.Claim(sources[i]) {
			t.Fatal("retained source reusable")
		}
		_ = result.Close()
		if _, ok := sources[i].Available(); ok {
			t.Fatal("closed result retained source bytes")
		}
	}
}

func TestPreparedResultRetainsReplacementOwner(t *testing.T) {
	// Canonical text is inline; existing binary bytes remain owned by the same attachment.
	source := content.NewAttachment([]byte("replacement"))
	path := "/items/0/parts/1"
	attachment := map[string]any{"id": "binary", "kind": "attachment", "mediaType": "application/octet-stream", "selection": "metadata"}
	event := targetTestCanonicalEvent(t, "model.request.before", []any{targetInlineMessage("message", targetInlineText("text", "inline replacement"), attachment)})
	p := &preparedBoundary{sources: map[string]*content.Source{path: source}, slots: map[string][]string{"request": {"/items"}}}
	result := &Result{Event: parsedFixtureEvent(t, event)}
	result.retainAttachments(contentSourceConfig(nil), context.Background(), p, 64)
	delete(p.sources, path)
	if result.attachments[path] != source || len(result.attachments) != 1 {
		t.Fatal("result created a second owner or text snapshot")
	}
	items := result.Event.ModelRequestBeforeEvent.Value.Items
	if string(sdkJSON(items)) != string(sdkJSON(event["items"])) {
		t.Fatal("typed canonical items changed during owner transfer")
	}
	got, ok := result.Content(path)
	if !ok || string(got) != "replacement" {
		t.Fatal(string(got))
	}
	got[0] = 'X'
	again, _ := result.Content(path)
	if string(again) != "replacement" {
		t.Fatal("caller mutated binary owner")
	}
	if _, ok := result.Content("/items/0/parts/0"); ok {
		t.Fatal("inline text acquired attachment bytes")
	}
	if err := result.Close(); err != nil {
		t.Fatal(err)
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
			source := content.NewSource(r)
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
				_, err := c.Dispatch(ctx, event.ToolBefore, input, WithContentSource("/items/0", source))
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
