package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func elicitationDispatchInput(stage, mode, raw string) map[string]any {
	e, _ := elicitationFixture(stage, mode, raw)
	e["time"] = "2026-01-01T00:00:00Z"
	delete(e, "source")
	delete(e, "type")
	return e
}
func elicitationDispatchCaps(stage, mode string) map[string]any {
	c := map[string]any{"effects": []any{"return", "message", "deny"}, "elicitation": map[string]any{mode: map[string]any{}}}
	if stage == "result" {
		c["effects"] = []any{"modify", "message"}
		c["modify"] = map[string]any{"content": map[string]any{"replace": true, "merge": true}}
	}
	return c
}
func setDispatchBoundary(c *Client, name string, caps map[string]any) {
	c.manifest["events"] = []any{map[string]any{"event": name, "modes": []any{"intercept", "observe"}, "capabilities": caps}}
	for i := range c.backends {
		for _, sub := range c.backends[i].subscriptions {
			sub["events"] = []any{name}
		}
	}
}
func TestElicitationDispatchSnapshotAndAtomicAnswers(t *testing.T) {
	original := []byte(" {\"message\":\"choose\",\"requestedSchema\":{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"string\",\"enum\":[\"a\",\"b\"]}},\"required\":[\"x\"]}} \n")
	c, transports := testClient(t, "fail-open", "fail-open")
	setDispatchBoundary(c, "user.elicitation.request", elicitationDispatchCaps("request", "form"))
	c.opts.Content.Resolver = func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(original)), nil
	}
	transports[0].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "return", "value": map[string]any{"action": "accept", "content": map[string]any{"x": "a"}}}}
	}
	transports[1].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "message", "text": "atomic"}, map[string]any{"type": "return", "value": map[string]any{"action": "accept", "content": map[string]any{"x": "outside"}}}}
	}
	result, err := c.intercept(context.Background(), "user.elicitation.request", elicitationDispatchInput("request", "form", string(original)))
	if err != nil || result == nil {
		t.Fatal(err)
	}
	if result.Snapshot == nil || !result.Snapshot.requestValid || !compositionEqual(result.Snapshot.requestedSchema, compositionObject(original)["requestedSchema"]) {
		t.Fatal("original form contract not snapshotted")
	}
	if len(result.Errors) != 1 || len(result.Response.Effects) != 1 {
		t.Fatalf("non-atomic acceptance: %+v", result)
	}
	var state map[string]any
	_ = json.Unmarshal(sdkJSON(result.State), &state)
	if sdkObj(sdkObj(state["candidate"])["value"])["action"] != "accept" {
		t.Fatal(state)
	}
	schema := sdkJSON(result.Snapshot.requestedSchema)
	original[1] = 'x'
	if !bytes.Equal(schema, sdkJSON(result.Snapshot.requestedSchema)) {
		t.Fatal("snapshot aliases caller bytes")
	}
	waitObservations(t, result)
}

func TestElicitationResultSerialReceiverUploads(t *testing.T) {
	request := `{"message":"choose","requestedSchema":{"type":"object","properties":{"x":{"type":"string","enum":["a","b"]}},"required":["x"]}}`
	c, transports := testClient(t, "fail-open", "fail-open")
	setDispatchBoundary(c, "user.elicitation.request", elicitationDispatchCaps("request", "form"))
	c.opts.Content.Resolver = func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewBufferString(request)), nil
	}
	before, err := c.intercept(context.Background(), "user.elicitation.request", elicitationDispatchInput("request", "form", request))
	if err != nil {
		t.Fatal(err)
	}
	waitObservations(t, before)
	initial := ` {"action":"accept","content":{"x":"a"},"_meta":{"preserved":true}} `
	setDispatchBoundary(c, "user.elicitation.result", elicitationDispatchCaps("result", "form"))
	var mu sync.Mutex
	uploaded := map[string][]byte{}
	count := 0
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		mu.Lock()
		count++
		ref := fmt.Sprintf("receiver-%d", count)
		uploaded[ref] = bytes.Clone(raw)
		mu.Unlock()
		contentTestConfirm(w, ref, raw)
	}))
	defer endpoint.Close()
	c.opts.Content.AllowLoopbackHTTP = true
	c.opts.Content.AuthorizeContent = contentTestAllow
	c.opts.Content.Resolver = func(_ context.Context, ref string) (io.ReadCloser, error) {
		if ref != "result-ref" {
			return nil, errors.New("internal reference escaped resolver")
		}
		return io.NopCloser(bytes.NewBufferString(initial)), nil
	}
	for i := range c.backends {
		for _, sub := range c.backends[i].subscriptions {
			sub["content"] = map[string]any{"default": "body"}
			sub["upload"] = map[string]any{"endpoint": endpoint.URL, "timeoutMs": 1000, "maxBytes": 4096}
		}
	}
	seen := []string{}
	for i, tr := range transports {
		index := i
		tr.reply = func(req map[string]any) []any {
			event := sdkObj(sdkObj(req["params"])["event"])
			item := sdkObj(sdkObj(event["elicitation"])["result"])
			ref := compositionString(sdkObj(item["body"])["ref"])
			mu.Lock()
			raw := uploaded[ref]
			mu.Unlock()
			seen = append(seen, string(raw))
			if index == 0 {
				return []any{map[string]any{"type": "modify", "target": "content", "operation": "merge", "value": map[string]any{"x": "b"}}}
			}
			return []any{}
		}
	}
	input := elicitationDispatchInput("result", "form", initial)
	item := sdkObj(sdkObj(input["elicitation"])["result"])
	item["body"] = map[string]any{"ref": "result-ref"}
	result, err := c.intercept(context.Background(), "user.elicitation.result", input, WithElicitationRequest(before.Snapshot))
	if err != nil || result == nil || len(result.Errors) != 0 {
		t.Fatalf("result: %+v %v", result, err)
	}
	if len(seen) != 2 || seen[0] != initial {
		t.Fatalf("original bytes changed: %q", seen)
	}
	var second map[string]any
	_ = json.Unmarshal([]byte(seen[1]), &second)
	if sdkObj(second["content"])["x"] != "b" || sdkObj(second["_meta"])["preserved"] != true {
		t.Fatal(second)
	}
	raw, ok := result.Content("/elicitation/result")
	if !ok || string(raw) != seen[1] {
		t.Fatal("effective bytes inaccessible")
	}
	raw[0] = 'x'
	again, _ := result.Content("/elicitation/result")
	if again[0] == 'x' {
		t.Fatal("effective bytes alias result backing store")
	}
	waitObservations(t, result)
}

func TestElicitationCorrelationAdmissionBeforeResolver(t *testing.T) {
	req, bodies := elicitationFixture("request", "form", elicitationForm)
	req["source"] = "urn:test:host"
	snapshot, err := prepareElicitation(req, nil, elicitationOwners(req, bodies))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"parentEventId", "server", "mode", "session"} {
		t.Run(field, func(t *testing.T) {
			c, _ := testClient(t, "fail-open")
			setDispatchBoundary(c, "user.elicitation.result", elicitationDispatchCaps("result", "form"))
			c.opts.Content.Resolver = func(context.Context, string) (io.ReadCloser, error) {
				t.Fatal("resolver called before correlation validation")
				return nil, nil
			}
			input := elicitationDispatchInput("result", "form", `{"action":"accept","content":{"x":"a"}}`)
			switch field {
			case "parentEventId":
				input[field] = "wrong"
			case "session":
				input[field] = map[string]any{"id": "wrong"}
			default:
				sdkObj(input["elicitation"])[field] = "wrong"
			}
			result, err := c.intercept(context.Background(), "user.elicitation.result", input, WithElicitationRequest(snapshot))
			if err == nil || result != nil {
				t.Fatal("uncorrelated occurrence admitted")
			}
		})
	}
}
