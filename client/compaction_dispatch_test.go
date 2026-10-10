package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPreparedCompactionSerialAndObservedInlineText(t *testing.T) {
	for _, stage := range []string{"before", "after"} {
		t.Run(stage, func(t *testing.T) {
			target := "instructions"
			if stage == "after" {
				target = "summary"
			}
			name := "context.compact." + stage
			c, trs := testClient(t, "fail-open", "fail-open", "fail-open")
			setDispatchBoundary(c, name, targetTestCaps(target))
			original := " original " + target + "\n"
			part := func(text string) map[string]any {
				return map[string]any{"id": "stable-item", "kind": "text", "mediaType": "text/plain", "selection": "body", "text": text}
			}
			input := map[string]any{"id": "compact", "time": "2026-01-01T00:00:00Z", target: []any{part(original)}}
			if stage == "before" {
				input["trigger"] = "manual"
				input["items"] = []any{}
			} else {
				input["removed"] = []any{}
				input["execution"] = map[string]any{"status": "executed"}
			}
			var uploads atomic.Int32
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				uploads.Add(1)
				raw, _ := io.ReadAll(r.Body)
				contentTestConfirm(w, "unexpected", raw)
			}))
			defer endpoint.Close()
			c.opts.Content.AllowLoopbackHTTP = true
			c.opts.Content.AuthorizeContent = contentTestAllow
			c.opts.Content.Resolver = func(context.Context, string) (io.ReadCloser, error) {
				t.Error("inline text reached resolver")
				return nil, io.ErrUnexpectedEOF
			}
			for i := range c.backends {
				for _, sub := range c.backends[i].subscriptions {
					sub["content"] = map[string]any{"default": "body"}
					sub["upload"] = map[string]any{"endpoint": endpoint.URL, "timeoutMs": 1000, "maxBytes": 4096}
				}
			}
			c.backends[2].subscriptions[0]["mode"] = "observe"
			trs[0].reply = func(map[string]any) []any {
				return []any{map[string]any{"type": "modify", "target": target, "operation": "replace", "value": []any{part("effective " + target)}}}
			}
			trs[1].reply = func(map[string]any) []any { return []any{} }
			result, err := c.intercept(context.Background(), name, input)
			if err != nil || result == nil || len(result.Errors) != 0 {
				t.Fatalf("result: %+v %v", result, err)
			}
			defer result.Close()
			waitObservations(t, result)
			if uploads.Load() != 0 {
				t.Fatalf("inline text uploaded %d times", uploads.Load())
			}
			for i, tr := range trs {
				tr.mu.Lock()
				calls := tr.calls
				tr.mu.Unlock()
				event := sdkObj(sdkObj(calls[len(calls)-1]["params"])["event"])
				parts := sdkArray(event[target])
				if len(parts) != 1 {
					t.Fatalf("receiver %d parts: %#v", i, parts)
				}
				projected := sdkObj(parts[0])
				want := "effective " + target
				if i == 0 {
					want = original
				}
				if projected["id"] != "stable-item" || projected["text"] != want || projected["body"] != nil {
					t.Fatal("inline text changed", projected)
				}
			}
			if sdkObj(sdkArray(input[target])[0])["text"] != original {
				t.Fatal("host input mutated")
			}
			if stage == "after" {
				event := compositionObject(result.Event)
				if sdkObj(event["execution"])["status"] != "executed" || len(sdkArray(event["removed"])) != 0 {
					t.Fatal("compaction fabricated execution or installation")
				}
			}
		})
	}
}
