package client

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/event"
)

func TestPublicCompactionInlineTextEdits(t *testing.T) {
	for _, target := range []string{"instructions", "summary"} {
		for _, operation := range []string{"replace", "merge"} {
			t.Run(target+"/"+operation, func(t *testing.T) {
				kind := "context.compact.before"
				if target == "summary" {
					kind = "context.compact.after"
				}
				c, transports := testClient(t, "fail-closed")
				setDispatchBoundary(c, kind, targetTestCaps(target))
				c.opts.Content.AuthorizeContent = contentTestAllow
				c.backends[0].subscriptions[0]["content"] = map[string]any{"default": "body"}
				original := inlineTestText("original", "old")
				replacement := inlineTestText("replacement", "new")
				transports[0].reply = func(map[string]any) []any {
					effects := []any{map[string]any{"type": "modify", "target": target, "operation": operation, "value": []any{replacement}}}
					return effects
				}
				var texts ahp.TextParts
				if err := json.Unmarshal(sdkJSON([]any{original}), &texts); err != nil {
					t.Fatal(err)
				}
				before, _ := json.Marshal(texts)
				var result *Result
				var err error
				if target == "instructions" {
					result, err = c.ContextCompactBefore(context.Background(), event.ContextCompactBeforeInput{Trigger: "manual", Items: []*ahp.ModelVisibleItem{}, Instructions: ahp.Some(&texts)})
				} else {
					var execution ahp.ExecutionEventExecution
					if err := json.Unmarshal([]byte(`{"status":"executed"}`), &execution); err != nil {
						t.Fatal(err)
					}
					result, err = c.ContextCompactAfter(context.Background(), event.ContextCompactAfterInput{Execution: &execution, Removed: []ahp.ContextCompactAfterEventRemovedItem{}, Summary: &texts})
				}
				if err != nil || result == nil {
					t.Fatalf("dispatch: %v", err)
				}
				defer result.Close()
				if len(result.Errors) != 0 {
					t.Fatalf("composition: %+v", result.Errors)
				}
				effective := inlineAt(compositionObject(result.Event), "/"+target)
				expected := []any{replacement}
				if operation == "merge" {
					expected = []any{original, replacement}
				}
				if !compositionEqual(effective, expected) {
					t.Fatalf("effective %s", sdkJSON(effective))
				}
				for _, raw := range sdkArray(effective) {
					if _, exists := sdkObj(raw)["parts"]; exists {
						t.Fatal("flat text part acquired parts member")
					}
				}
				after, _ := json.Marshal(texts)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("caller text parts mutated")
				}
			})
		}
	}
}

func TestTypedInlineTraversalKeepsUnknownMetadataOpaque(t *testing.T) {
	text := inlineTestText("text", "literal")
	text["parts"] = []any{map[string]any{"kind": "attachment", "ref": "secret"}, inlineTestText("unknown", "not a canonical child")}
	text["future"] = map[string]any{"kind": "attachment", "ref": "secret"}
	before := sdkJSON(text)
	for _, path := range []string{"/instructions", "/summary", "/items"} {
		value := []any{text}
		if path == "/items" {
			value = []any{inlineTestMessage("message", "assistant", text)}
		}
		parts, err := knownInlineTextParts(path, value)
		if err != nil || len(parts) != 1 {
			t.Fatalf("known parts: %d %v", len(parts), err)
		}
		if !compositionEqual(parts[0], text) {
			t.Fatal("opaque fields were reshaped")
		}
		if len(inlineAttachments(value, path)) != 0 {
			t.Fatal("unknown metadata traversed as attachments")
		}
	}
	if !reflect.DeepEqual(before, sdkJSON(text)) {
		t.Fatal("parsed traversal changed source")
	}
}

func TestPublicCompactionResponseRollbackRetainsEarlierAcceptedEdits(t *testing.T) {
	c, transports := testClient(t, "fail-open", "fail-open")
	setDispatchBoundary(c, "context.compact.before", targetTestCaps("instructions"))
	c.opts.Content.AuthorizeContent = contentTestAllow
	for _, backend := range c.backends {
		backend.subscriptions[0]["content"] = map[string]any{"default": "body"}
	}
	accepted := inlineTestText("accepted", "accepted")
	transports[0].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "modify", "target": "instructions", "operation": "replace", "value": []any{accepted}}}
	}
	transports[1].reply = func(req map[string]any) []any {
		incoming := sdkObj(sdkObj(req["params"])["event"])["instructions"]
		if !compositionEqual(incoming, []any{accepted}) {
			t.Fatal("later interceptor did not receive accepted state")
		}
		return []any{map[string]any{"type": "message", "text": "must not publish"}, map[string]any{"type": "modify", "target": "instructions", "operation": "replace", "value": []any{inlineTestText("rejected", "rejected")}}, map[string]any{"type": "deny", "reason": "ungranted"}}
	}
	var texts ahp.TextParts
	if err := json.Unmarshal(sdkJSON([]any{inlineTestText("original", "old")}), &texts); err != nil {
		t.Fatal(err)
	}
	result, err := c.ContextCompactBefore(context.Background(), event.ContextCompactBeforeInput{Trigger: "manual", Items: []*ahp.ModelVisibleItem{}, Instructions: ahp.Some(&texts)})
	if err != nil || result == nil {
		t.Fatalf("dispatch: %v", err)
	}
	defer result.Close()
	if len(result.Errors) != 1 || len(result.Response.Effects.Value) != 1 || !compositionEqual(compositionObject(result.Event)["instructions"], []any{accepted}) {
		t.Fatalf("response not atomic: errors=%d effects=%d", len(result.Errors), len(result.Response.Effects.Value))
	}
}

func TestPublicWorkspaceModifyPreservesOpaquePrior(t *testing.T) {
	c, transports := testClient(t, "fail-closed")
	setDispatchBoundary(c, "workspace.change.before", targetTestCaps("workspace"))
	prior := map[string]any{"cwd": "/prior"}
	input := map[string]any{"workspace": map[string]any{"kind": "cwd", "change": map[string]any{"cwd": "/old"}, "prior": prior}, "future": map[string]any{"kind": "attachment", "parts": nil}}
	before := contentClone(input)
	transports[0].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "modify", "target": "workspace", "operation": "merge", "value": map[string]any{"cwd": "/new"}}}
	}
	result, err := c.Dispatch(context.Background(), "workspace.change.before", input)
	if err != nil || result == nil {
		t.Fatalf("dispatch: %v", err)
	}
	defer result.Close()
	if len(result.Errors) != 0 {
		t.Fatalf("composition: %+v", result.Errors)
	}
	effective := compositionObject(result.Event)
	workspace := sdkObj(effective["workspace"])
	if !compositionEqual(effective["future"], input["future"]) {
		t.Fatal("unknown event metadata changed")
	}
	if sdkObj(workspace["change"])["cwd"] != "/new" || !compositionEqual(workspace["prior"], prior) || !reflect.DeepEqual(input, before) {
		t.Fatal("workspace scope or opaque prior mutated")
	}
}

func TestPublicModelReturnCanonicalMessages(t *testing.T) {
	c, transports := testClient(t, "fail-closed")
	setDispatchBoundary(c, "model.request.before", map[string]any{"effects": []any{"return"}})
	c.opts.Content.AuthorizeContent = contentTestAllow
	c.backends[0].subscriptions[0]["content"] = map[string]any{"default": "body"}
	messages := []any{inlineTestMessage("candidate", "assistant", inlineTestText("candidate-part", "answer"))}
	transports[0].reply = func(map[string]any) []any { return []any{map[string]any{"type": "return", "value": messages}} }
	result, err := c.Dispatch(context.Background(), "model.request.before", inlineTestInput(t, []any{inlineTestMessage("input", "user", inlineTestText("input-part", "question"))}))
	if err != nil || result == nil {
		t.Fatalf("dispatch: %v", err)
	}
	defer result.Close()
	if len(result.Errors) != 0 {
		t.Fatalf("composition: %+v", result.Errors)
	}
	state := compositionObject(sdkJSON(result.State))
	candidate := sdkObj(state["candidate"])["value"]
	var typed ahp.CanonicalMessages
	if err := json.Unmarshal(sdkJSON(candidate), &typed); err != nil || len(typed) != 1 || typed[0].Parts[0].TextBodyPart.Value.Text != "answer" {
		t.Fatalf("candidate: %s %v", sdkJSON(candidate), err)
	}
}

func TestTypedElicitResultUnknownMetadataRoundTrip(t *testing.T) {
	raw := []byte(`{"action":"accept","content":{"answer":"yes"},"_meta":{"future":{"kind":"attachment","parts":null}},"future":{"kind":"text","parts":null}}`)
	var result ahp.McpElicitationElicitResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Action != "accept" || !result.Content.Present {
		t.Fatal("known result fields missing")
	}
	encoded, err := json.Marshal(result)
	if err != nil || !compositionEqual(compositionObject(raw), compositionObject(encoded)) {
		t.Fatalf("opaque fields changed: %s %v", encoded, err)
	}
}
