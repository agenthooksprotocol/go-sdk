package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

func inlineTestText(id, text string) map[string]any {
	return map[string]any{"id": id, "kind": "text", "mediaType": "text/plain", "selection": "body", "text": text}
}
func inlineTestMessage(id, role string, parts ...any) map[string]any {
	return map[string]any{"id": id, "role": role, "parts": parts}
}
func inlineTestInput(t *testing.T, messages []any) map[string]any {
	t.Helper()
	input := targetTestCanonicalEvent(t, "model.request.before", messages)
	delete(input, "source")
	delete(input, "type")
	return input
}

func TestInlineCanonicalMessagesSelectionPrivacy(t *testing.T) {
	for _, mode := range []string{"body", "metadata", "omit"} {
		t.Run(mode, func(t *testing.T) {
			c, transports := testClient(t, "fail-closed")
			setDispatchBoundary(c, "model.request.before", map[string]any{"effects": []any{}})
			c.opts.Content.AuthorizeContent = contentTestAllow
			c.opts.Content.Resolver = func(context.Context, string) (io.ReadCloser, error) {
				t.Fatal("inline text invoked resolver")
				return nil, nil
			}
			sub := c.backends[0].subscriptions[0]
			sub["content"] = map[string]any{"default": mode}
			// Inline text has no upload dependency. Both message and part order matter.
			messages := []any{
				inlineTestMessage("m1", "user", inlineTestText("p1", "private one"), inlineTestText("p2", "private two")),
				inlineTestMessage("m2", "assistant", inlineTestText("p3", "private three")),
			}
			input := inlineTestInput(t, messages)
			before := contentClone(input)
			result, err := c.Dispatch(context.Background(), "model.request.before", input)
			if result != nil {
				defer result.Close()
			}
			if err != nil || result == nil || len(result.Errors) != 0 {
				t.Fatalf("dispatch: %v %+v", err, result)
			}
			if len(transports[0].calls) != 1 {
				t.Fatalf("deliveries: %d", len(transports[0].calls))
			}
			event := sdkObj(sdkObj(transports[0].calls[0]["params"])["event"])
			got := sdkArray(event["items"])
			if len(got) != 2 || sdkObj(got[0])["role"] != "user" || sdkObj(got[1])["role"] != "assistant" {
				t.Fatalf("message order/roles: %#v", got)
			}
			for i, message := range got {
				parts := sdkArray(sdkObj(message)["parts"])
				original := sdkArray(sdkObj(messages[i])["parts"])
				if len(parts) != len(original) {
					t.Fatalf("part count: %#v", parts)
				}
				for j, raw := range parts {
					part := sdkObj(raw)
					if part["id"] != sdkObj(original[j])["id"] || part["selection"] != mode {
						t.Fatalf("identity/selection: %#v", part)
					}
					if mode == "body" {
						if part["text"] != sdkObj(original[j])["text"] {
							t.Fatalf("inline body: %#v", part)
						}
					} else if _, present := part["text"]; present {
						t.Fatalf("private text disclosed: %#v", part)
					}
					if _, present := part["body"]; present {
						t.Fatalf("text acquired a descriptor: %#v", part)
					}
				}
			}
			if !reflect.DeepEqual(input, before) {
				t.Fatal("selection mutated host input")
			}
		})
	}
}

func TestInlineCanonicalMessagesMergeAppendAndReplaceSubstitute(t *testing.T) {
	original := inlineTestMessage("m1", "user", inlineTestText("p1", "original"))
	added := inlineTestMessage("m2", "assistant", inlineTestText("p2", "accepted"))
	for _, operation := range []string{"merge", "replace"} {
		t.Run(operation, func(t *testing.T) {
			c, transports := testClient(t, "fail-closed", "fail-closed")
			setDispatchBoundary(c, "model.request.before", map[string]any{"effects": []any{"modify"}, "modify": map[string]any{"request": map[string]any{"merge": true, "replace": true}}})
			c.opts.Content.AuthorizeContent = contentTestAllow
			for _, backend := range c.backends {
				backend.subscriptions[0]["content"] = map[string]any{"default": "body"}
			}
			// Repeating an identical message verifies merge preserves duplicates.
			value := []any{added, added}
			transports[0].reply = func(map[string]any) []any {
				return []any{map[string]any{"type": "modify", "target": "request", "operation": operation, "value": value}}
			}
			input := inlineTestInput(t, []any{original})
			before := contentClone(input)
			result, err := c.Dispatch(context.Background(), "model.request.before", input)
			if result != nil {
				defer result.Close()
			}
			if err != nil || result == nil || len(result.Errors) != 0 {
				t.Fatalf("composition: %v %+v", err, result)
			}
			want := value
			if operation == "merge" {
				want = append([]any{original}, value...)
			}
			if len(transports[1].calls) != 1 {
				t.Fatalf("next receiver missing: %+v", result)
			}
			next := sdkObj(sdkObj(transports[1].calls[0]["params"])["event"])["items"]
			if !compositionEqual(next, want) {
				t.Fatalf("next receiver list: %s want %s", sdkJSON(next), sdkJSON(want))
			}
			var effective map[string]any
			if err := json.Unmarshal(result.Event, &effective); err != nil {
				t.Fatal(err)
			}
			if !compositionEqual(effective["items"], want) {
				t.Fatalf("effective list: %s", result.Event)
			}
			if !reflect.DeepEqual(input, before) {
				t.Fatal("composition mutated host input")
			}
		})
	}
}

func TestInlineCanonicalMessagesBodySelectionRequiresAuthorization(t *testing.T) {
	c, transports := testClient(t, "fail-closed")
	setDispatchBoundary(c, "model.request.before", map[string]any{"effects": []any{}})
	c.backends[0].subscriptions[0]["content"] = map[string]any{"default": "body"}
	result, err := c.Dispatch(context.Background(), "model.request.before", inlineTestInput(t, []any{inlineTestMessage("m1", "user", inlineTestText("p1", "secret"))}))
	if result != nil {
		defer result.Close()
	}
	if err != nil || result == nil || len(result.Errors) != 0 {
		t.Fatalf("dispatch: %v %+v", err, result)
	}
	if len(transports[0].calls) != 1 {
		t.Fatal("missing delivery")
	}
	event := sdkObj(sdkObj(transports[0].calls[0]["params"])["event"])
	message := sdkObj(sdkArray(event["items"])[0])
	part := sdkObj(sdkArray(message["parts"])[0])
	if _, present := part["text"]; present {
		t.Fatalf("unauthorized disclosure: %#v", part)
	}
	if part["selection"] != "body" || sdkObj(part["gap"])["reason"] != "withheld" {
		t.Fatalf("withholding gap missing: %#v", part)
	}
}

func inlineTestRejectEdit(t *testing.T, selection map[string]any, original, incoming []any, operation string, authorize func(context.Context, ContentAuthorization) (bool, error)) (*Result, []*testTransport) {
	t.Helper()
	c, transports := testClient(t, "fail-open", "fail-open")
	setDispatchBoundary(c, "model.request.before", map[string]any{"effects": []any{"modify"}, "modify": map[string]any{"request": map[string]any{"merge": true, "replace": true}}})
	c.opts.Content.AuthorizeContent = authorize
	c.backends[0].subscriptions[0]["content"] = selection
	c.backends[1].subscriptions[0]["content"] = map[string]any{"default": "body"}
	transports[0].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "modify", "target": "request", "operation": operation, "value": incoming}}
	}
	result, err := c.Dispatch(context.Background(), "model.request.before", inlineTestInput(t, original))
	if result != nil {
		t.Cleanup(func() { _ = result.Close() })
	}
	if err != nil || result == nil {
		t.Fatalf("dispatch: %v %+v", err, result)
	}
	if len(result.Errors) != 1 || result.Errors[0].Code != DeliveryCode("protocol_rejection") {
		t.Fatalf("edit was not rejected: %+v", result.Errors)
	}
	var effective map[string]any
	if err := json.Unmarshal(result.Event, &effective); err != nil {
		t.Fatal(err)
	}
	if !compositionEqual(effective["items"], original) {
		t.Fatalf("rejected edit changed host list: %s", result.Event)
	}
	if len(transports[1].calls) != 1 {
		t.Fatal("fail-open did not deliver original to next receiver")
	}
	next := sdkObj(sdkObj(transports[1].calls[0]["params"])["event"])["items"]
	if !compositionEqual(next, original) {
		t.Fatalf("rejected edit reached next receiver: %s", sdkJSON(next))
	}
	return result, transports
}

func TestInlineCanonicalMessagesHiddenListReplacementRejected(t *testing.T) {
	for _, mode := range []string{"metadata", "omit", "gap"} {
		for _, changedID := range []bool{false, true} {
			name := mode + "/same-id"
			if changedID {
				name = mode + "/changed-id"
			}
			t.Run(name, func(t *testing.T) {
				original := []any{inlineTestMessage("m1", "user", inlineTestText("p1", "hidden original"))}
				messageID, partID := "m1", "p1"
				if changedID {
					messageID, partID = "different-message", "different-part"
				}
				replacement := []any{inlineTestMessage(messageID, "user", inlineTestText(partID, "replacement"))}
				selection := map[string]any{"default": mode}
				if mode == "gap" {
					selection["default"] = "body"
				}
				authorize := func(_ context.Context, scope ContentAuthorization) (bool, error) {
					// Withhold the first receiver's read, but permit writes and later reads.
					return mode != "gap" || scope.Operation == "write" || scope.BackendID != "com.example.backenda", nil
				}
				_, transports := inlineTestRejectEdit(t, selection, original, replacement, "replace", authorize)
				delivered := sdkObj(sdkObj(transports[0].calls[0]["params"])["event"])
				part := sdkObj(sdkArray(sdkObj(sdkArray(delivered["items"])[0])["parts"])[0])
				if _, present := part["text"]; present {
					t.Fatalf("test did not withhold original: %#v", part)
				}
				if mode == "gap" && sdkObj(part["gap"])["reason"] != "withheld" {
					t.Fatalf("gap missing: %#v", part)
				}
			})
		}
	}
}

func TestInlineCanonicalMessagesAppendReasoningMetadataRejected(t *testing.T) {
	reasoning := inlineTestText("reasoning-1", "private reasoning")
	reasoning["category"] = "reasoning"
	inlineTestRejectEdit(t, map[string]any{"default": "body", "reasoning": "metadata"},
		[]any{inlineTestMessage("m1", "user", inlineTestText("p1", "visible"))},
		[]any{inlineTestMessage("m2", "assistant", reasoning)}, "merge", contentTestAllow)
}

func TestInlineCanonicalMessagesWriteAuthorizationDenied(t *testing.T) {
	for _, operation := range []string{"merge", "replace"} {
		t.Run(operation, func(t *testing.T) {
			reads, writes := 0, 0
			authorize := func(_ context.Context, scope ContentAuthorization) (bool, error) {
				switch scope.Operation {
				case "read":
					reads++
					return true, nil
				case "write":
					writes++
					if scope.BackendID != "com.example.backenda" || scope.Item["id"] != "p2" {
						t.Errorf("write scope: %+v", scope)
					}
					return false, nil
				default:
					t.Errorf("missing authorization operation: %+v", scope)
					return false, nil
				}
			}
			inlineTestRejectEdit(t, map[string]any{"default": "body"},
				[]any{inlineTestMessage("m1", "user", inlineTestText("p1", "visible"))},
				[]any{inlineTestMessage("m2", "assistant", inlineTestText("p2", "not accepted"))}, operation, authorize)
			if reads == 0 || writes != 1 {
				t.Fatalf("authorization calls: read=%d write=%d", reads, writes)
			}
		})
	}
}

func TestInlineCanonicalReceiverStatePrivacy(t *testing.T) {
	for _, family := range []string{"candidate", "injection"} {
		for _, mode := range []string{"metadata", "omit", "denied"} {
			t.Run(family+"/"+mode, func(t *testing.T) {
				c, transports := testClient(t, "fail-closed", "fail-closed")
				setDispatchBoundary(c, "model.request.before", map[string]any{
					"effects": []any{"return", "inject"},
					"inject":  map[string]any{"context": map[string]any{"append": true, "deliverAt": []any{"now"}}},
				})
				c.opts.Content.AuthorizeContent = func(_ context.Context, scope ContentAuthorization) (bool, error) {
					if mode == "denied" && scope.Operation == "read" && scope.BackendID == "com.example.backendb" && scope.Item["category"] == "reasoning" {
						return false, nil
					}
					return true, nil
				}
				c.backends[0].subscriptions[0]["content"] = map[string]any{"default": "body"}
				secondSelection := map[string]any{"default": "body"}
				if mode != "denied" {
					secondSelection["reasoning"] = mode
				}
				c.backends[1].subscriptions[0]["content"] = secondSelection
				hidden := inlineTestText("state-reasoning", "private cumulative reasoning")
				hidden["category"] = "reasoning"
				visible := inlineTestText("state-visible", "public cumulative text")
				value := []any{inlineTestMessage("state-message", "assistant", hidden, visible)}
				transports[0].reply = func(map[string]any) []any {
					if family == "candidate" {
						return []any{map[string]any{"type": "return", "value": value}}
					}
					return []any{map[string]any{"type": "inject", "target": "context", "operation": "append", "deliverAt": "now", "value": value}}
				}
				result, err := c.Dispatch(context.Background(), "model.request.before", inlineTestInput(t, []any{inlineTestMessage("input-message", "user", inlineTestText("input-text", "ordinary input"))}))
				if result != nil {
					defer result.Close()
				}
				if err != nil || result == nil || len(result.Errors) != 0 {
					t.Fatalf("state composition: %v %+v", err, result)
				}
				if len(transports[1].calls) != 1 {
					t.Fatalf("second delivery missing: %+v", result)
				}
				stateValue := func(state map[string]any) any {
					if family == "candidate" {
						return sdkObj(state["candidate"])["value"]
					}
					injections := sdkArray(state["injections"])
					if len(injections) != 1 {
						t.Fatalf("injection state missing: %#v", state)
					}
					return sdkObj(injections[0])["value"]
				}
				second := transports[1].calls[0]
				deliveredState := sdkObj(sdkObj(second["params"])["state"])
				delivered := sdkArray(stateValue(deliveredState))
				if len(delivered) != 1 {
					t.Fatalf("projected state list missing: %#v", deliveredState)
				}
				message := sdkObj(delivered[0])
				parts := sdkArray(message["parts"])
				if message["id"] != "state-message" || message["role"] != "assistant" || len(parts) != 2 {
					t.Fatalf("projected state identity/order: %#v", message)
				}
				privatePart := sdkObj(parts[0])
				if privatePart["id"] != "state-reasoning" || privatePart["category"] != "reasoning" {
					t.Fatalf("reasoning classification lost: %#v", privatePart)
				}
				wantSelection := mode
				if mode == "denied" {
					wantSelection = "body"
				}
				if privatePart["selection"] != wantSelection {
					t.Fatalf("state selection: %#v", privatePart)
				}
				if _, present := privatePart["text"]; present {
					t.Fatalf("state disclosed private text: %#v", privatePart)
				}
				if mode == "denied" && sdkObj(privatePart["gap"])["reason"] != "withheld" {
					t.Fatalf("state withholding gap missing: %#v", privatePart)
				}
				if sdkObj(parts[1])["text"] != "public cumulative text" {
					t.Fatalf("public state part was over-redacted: %#v", parts)
				}
				if bytes.Contains(sdkJSON(second), []byte("private cumulative reasoning")) {
					t.Fatalf("private text escaped through another delivery field: %s", sdkJSON(second))
				}
				hostState, err := sdkMap(result.State)
				if err != nil {
					t.Fatal(err)
				}
				if !compositionEqual(stateValue(hostState), value) {
					t.Fatalf("receiver projection redacted cumulative host state: %s", sdkJSON(hostState))
				}
			})
		}
	}
}

func TestInlineCanonicalInitialModelCandidateRejectedBeforeDelivery(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"scalar", "provider output"},
		{"native-object", map[string]any{"content": "provider output"}},
		{"text-part-list", []any{inlineTestText("part", "not a message list")}},
		{"null", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, transports := testClient(t, "fail-closed")
			setDispatchBoundary(c, "model.request.before", map[string]any{"effects": []any{}})
			var initial ahp.InterceptRequestParamsState
			if err := json.Unmarshal(sdkJSON(map[string]any{"permission": "none", "candidate": map[string]any{"value": tc.value}}), &initial); err != nil {
				t.Fatal(err)
			}
			result, err := c.Dispatch(context.Background(), "model.request.before", inlineTestInput(t, []any{}), WithInitialState(initial))
			if result != nil {
				defer result.Close()
			}
			if err == nil {
				t.Fatal("invalid initial model candidate accepted")
			}
			if len(transports[0].calls) != 0 {
				t.Fatalf("invalid candidate reached backend: %#v", transports[0].calls)
			}
		})
	}
}
