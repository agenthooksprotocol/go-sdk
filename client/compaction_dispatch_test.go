package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestPreparedCompactionSerialAndObservedUploads(t *testing.T) {
	for _, stage := range []string{"before", "after"} {
		t.Run(stage, func(t *testing.T) {
			target := "instructions"
			if stage == "after" {
				target = "summary"
			}
			name := "context.compact." + stage
			c, trs := testClient(t, "fail-open", "fail-open", "fail-open")
			setDispatchBoundary(c, name, targetTestCaps(target))
			original := []byte(" original " + target + "\n")
			item, bodies := targetTestItem("stable-item", "text/plain", string(original))
			item["category"] = "text"
			item["parentItemId"] = "parent-item"
			input := map[string]any{"id": "compact", "time": "2026-01-01T00:00:00Z", target: item}
			if stage == "before" {
				input["trigger"] = "manual"
				input["items"] = []any{}
			} else {
				input["removed"] = []any{}
				input["execution"] = map[string]any{"status": "executed"}
			}
			var mu sync.Mutex
			uploaded := map[string][]byte{}
			order := []string{}
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				_ = r.Body.Close()
				mu.Lock()
				ref := fmt.Sprintf("uploaded-%d", len(order))
				order = append(order, ref)
				uploaded[ref] = bytes.Clone(raw)
				mu.Unlock()
				contentTestConfirm(w, ref, raw)
			}))
			defer endpoint.Close()
			c.opts.Content.AllowLoopbackHTTP = true
			c.opts.Content.AuthorizeContent = contentTestAllow
			c.opts.Content.Resolver = func(_ context.Context, ref string) (io.ReadCloser, error) {
				raw, ok := bodies[ref]
				if !ok {
					return nil, fmt.Errorf("internal reference reached host")
				}
				return io.NopCloser(bytes.NewReader(raw)), nil
			}
			for i := range c.backends {
				for _, sub := range c.backends[i].subscriptions {
					sub["content"] = map[string]any{"default": "body"}
					sub["upload"] = map[string]any{"endpoint": endpoint.URL, "timeoutMs": 1000, "maxBytes": 4096}
				}
			}
			c.backends[2].subscriptions[0]["mode"] = "observe"
			trs[0].reply = func(map[string]any) []any {
				return []any{map[string]any{"type": "modify", "target": target, "operation": "replace", "value": "effective " + target}}
			}
			trs[1].reply = func(map[string]any) []any { return []any{} }
			result, err := c.intercept(context.Background(), name, input)
			if err != nil || result == nil || len(result.Errors) != 0 {
				t.Fatalf("result: %+v %v", result, err)
			}
			waitObservations(t, result)
			mu.Lock()
			defer mu.Unlock()
			if len(order) != 3 {
				t.Fatalf("uploads=%d", len(order))
			}
			for i, ref := range order {
				want := "effective " + target
				if i == 0 {
					want = string(original)
				}
				if string(uploaded[ref]) != want {
					t.Fatalf("receiver %d bytes %q", i, uploaded[ref])
				}
			}
			for _, tr := range trs {
				tr.mu.Lock()
				calls := tr.calls
				tr.mu.Unlock()
				event := sdkObj(sdkObj(calls[len(calls)-1]["params"])["event"])
				projected := sdkObj(event[target])
				if projected["id"] != "stable-item" || projected["role"] != "assistant" || projected["parentItemId"] != "parent-item" || projected["category"] != "text" {
					t.Fatal("descriptor identity changed", projected)
				}
			}
			if !bytes.Equal(bodies["urn:test:stable-item"], original) {
				t.Fatal("host backing bytes mutated")
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
