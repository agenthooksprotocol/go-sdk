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

func TestElicitationResultSerialInlineReceivers(t *testing.T) {
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
			seen = append(seen, compositionString(item["text"]))
			if index == 0 {
				return []any{map[string]any{"type": "modify", "target": "content", "operation": "merge", "value": map[string]any{"x": "b"}}}
			}
			return []any{}
		}
	}
	input := elicitationDispatchInput("result", "form", initial)

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
	raw := []byte(compositionString(sdkObj(sdkObj(compositionObject(result.Event)["elicitation"])["result"])["text"]))
	if string(raw) != seen[1] {
		t.Fatal("effective inline bytes inaccessible")
	}
	raw[0] = 'x'
	again := compositionString(sdkObj(sdkObj(compositionObject(result.Event)["elicitation"])["result"])["text"])
	if again != seen[1] {
		t.Fatal("effective bytes alias caller buffer")
	}
	if count != 0 {
		t.Fatalf("inline JSON uploaded %d times", count)
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

func TestElicitationStructuredEditPrivacy(t *testing.T) {
	for _, operation := range []string{"replace", "merge"} {
		for _, tc := range []struct {
			name, defaultSelection, categorySelection                                    string
			read, write, writeError, noAuthorizer, hostMetadata, invalidAnswer, accepted bool
		}{
			{name: "body-authorized", defaultSelection: "body", read: true, write: true, accepted: true},
			{name: "metadata", defaultSelection: "metadata", read: true, write: true},
			{name: "omit", defaultSelection: "omit", read: true, write: true},
			{name: "category-metadata", defaultSelection: "body", categorySelection: "metadata", read: true, write: true},
			{name: "category-body", defaultSelection: "metadata", categorySelection: "body", read: true, write: true, accepted: true},
			{name: "read-denied", defaultSelection: "body", write: true},
			{name: "write-denied", defaultSelection: "body", read: true},
			{name: "write-error", defaultSelection: "body", read: true, writeError: true},
			{name: "no-authorizer", defaultSelection: "body", noAuthorizer: true},
			{name: "host-metadata", defaultSelection: "body", read: true, write: true, hostMetadata: true},
			{name: "pinned-invalid-answer", defaultSelection: "body", read: true, write: true, invalidAnswer: true},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				c, transports := testClient(t, "fail-open")
				request, _ := elicitationFixture("request", "form", `{"message":"choose","requestedSchema":{"type":"object","properties":{"x":{"type":"string","enum":["old","new"]},"keep":{"type":"string"}},"required":["x"]}}`)
				request["source"] = c.opts.Source
				snapshot, err := prepareElicitation(request, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				setDispatchBoundary(c, "user.elicitation.result", elicitationDispatchCaps("result", "form"))
				sub := c.backends[0].subscriptions[0]
				selection := map[string]any{"default": tc.defaultSelection}
				if tc.categorySelection != "" {
					selection["answers"] = tc.categorySelection
				}
				sub["content"] = selection
				reads, writes := 0, 0
				if !tc.noAuthorizer {
					c.opts.Content.AuthorizeContent = func(_ context.Context, scope ContentAuthorization) (bool, error) {
						if scope.Item["kind"] != "text" || scope.Item["mediaType"] != "text/plain" || scope.Item["category"] != "answers" {
							t.Error("wrong answer authorization item", scope.Item)
						}
						switch scope.Operation {
						case "read":
							reads++
							return tc.read, nil
						case "write":
							writes++
							if scope.BackendID != c.backends[0].id || scope.SubscriptionID != compositionString(sub["id"]) || scope.Item["body"] != nil {
								t.Error("write authority lost backend scope or became an upload", scope)
							}
							if tc.writeError {
								return false, errors.New("write denied by host")
							}
							return tc.write, nil
						default:
							t.Error("unspecified content operation", scope.Operation)
							return false, nil
						}
					}
				}
				initial := ` {"action":"accept","content":{"x":"old","keep":"retained"},"_meta":{"preserved":true},"extension":{"untouched":true}} `
				input := elicitationDispatchInput("result", "form", initial)
				item := sdkObj(sdkObj(input["elicitation"])["result"])
				item["category"] = "answers"
				if tc.hostMetadata {
					item["selection"] = "metadata"
					delete(item, "text")
				}
				before := string(sdkJSON(input))
				value := "new"
				if tc.invalidAnswer {
					value = "outside"
				}
				visibleBody := false
				transports[0].reply = func(req map[string]any) []any {
					visible := preparedAt(sdkObj(sdkObj(req["params"])["event"]), "/elicitation/result")
					visibleBody = visible["selection"] == "body" && visible["text"] != nil && visible["gap"] == nil
					return []any{map[string]any{"type": "message", "text": "atomic prefix"}, map[string]any{"type": "modify", "target": "content", "operation": operation, "value": map[string]any{"x": value}}}
				}
				result, err := c.intercept(context.Background(), "user.elicitation.result", input, WithElicitationRequest(snapshot))
				if err != nil || result == nil {
					t.Fatal("result admission failed before privacy test", err)
				}
				defer result.Close()
				waitObservations(t, result)
				if string(sdkJSON(input)) != before {
					t.Fatal("caller result mutated")
				}
				effectiveItem := preparedAt(compositionObject(result.Event), "/elicitation/result")
				if tc.accepted {
					if len(result.Errors) != 0 || len(result.Response.Effects) != 2 || !visibleBody || writes != 1 {
						t.Fatalf("authorized answer rejected: errors=%v visible=%v writes=%d reads=%d", result.Errors, visibleBody, writes, reads)
					}
					answer := compositionObject([]byte(compositionString(effectiveItem["text"])))
					content := sdkObj(answer["content"])
					_, keep := content["keep"]
					if answer["action"] != "accept" || sdkObj(answer["_meta"])["preserved"] != true || sdkObj(answer["extension"])["untouched"] != true || content["x"] != "new" || keep != (operation == "merge") {
						t.Fatal("structured edit changed wrapper or used wrong object operation", answer)
					}
				} else {
					if len(result.Errors) == 0 || len(result.Response.Effects) != 0 {
						t.Fatal("unauthorized/invalid edit published atomic prefix", result.Errors, result.Response.Effects)
					}
					if effectiveItem["text"] != item["text"] || effectiveItem["selection"] != item["selection"] {
						t.Fatal("rejected structured edit changed host answer", effectiveItem)
					}
					if !visibleBody && writes != 0 {
						t.Fatal("write callback received undisclosed answer", writes)
					}
					if visibleBody && !tc.noAuthorizer && writes != 1 {
						t.Fatal("visible edit bypassed host write decision", writes)
					}
				}
				if len(result.attachments) != 0 {
					t.Fatal("structured inline edit acquired attachment owner")
				}
			})
		}
	}
}
