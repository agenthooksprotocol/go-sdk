package client

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/event"
)

type hookFormAnswer struct {
	Name   string `json:"name"`
	Count  int8   `json:"count"`
	Choice string `json:"choice"`
	Flag   bool   `json:"flag,omitempty"`
}

func hookForm(t *testing.T) *FormContract[hookFormAnswer] {
	t.Helper()
	form, err := NewFormContract[hookFormAnswer](WithFormField("name", FormFieldOptions{MinLength: "2", MaxLength: "8"}), WithFormField("count", FormFieldOptions{Minimum: "1"}), WithFormField("choice", FormFieldOptions{Enum: []string{"a", "b"}}))
	if err != nil {
		t.Fatal(err)
	}
	return form
}
func hookFormPart(t *testing.T, id, text string) *ahp.TextPart {
	t.Helper()
	var part ahp.TextPart
	if err := json.Unmarshal(sdkJSON(inlineTestText(id, text)), &part); err != nil {
		t.Fatal(err)
	}
	return &part
}
func hookFormInput(t *testing.T) event.UserElicitationRequestInput {
	return event.UserElicitationRequestInput{ID: ahp.Some("form-request"), Elicitation: ahp.UserElicitationRequestEventElicitation{Mode: "form", Server: "requester", Request: ahp.Some(hookFormPart(t, "request-body", "caller template"))}}
}

func TestFormHooksSingleDeclarationAndStagedReturnValidation(t *testing.T) {
	for _, invalid := range []string{"constraint", "overflow", "unknown-field", "repaired-constraint"} {
		t.Run(invalid, func(t *testing.T) {
			form := hookForm(t)
			c, transports := testClient(t, "fail-open", "fail-open", "fail-open")
			setDispatchBoundary(c, "user.elicitation.request", map[string]any{"effects": []any{"return"}, "elicitation": map[string]any{"form": map[string]any{}}})
			for _, backend := range c.backends {
				backend.subscriptions[0]["content"] = map[string]any{"default": "body"}
			}
			c.opts.Content.AuthorizeContent = contentTestAllow
			valid := map[string]any{"name": "name", "count": 2, "choice": "a", "flag": false}
			transports[0].reply = func(req map[string]any) []any {
				part := sdkObj(sdkObj(sdkObj(req["params"])["event"])["elicitation"])["request"]
				body := compositionObject([]byte(compositionString(sdkObj(part)["text"])))
				if !compositionEqual(body["requestedSchema"], compositionObject(sdkJSON(form.RequestedSchema()))) {
					t.Fatal("request not derived from answer T")
				}
				return []any{map[string]any{"type": "return", "value": map[string]any{"action": "accept", "content": valid, "_meta": map[string]any{"future": map[string]any{"kind": "attachment", "parts": nil}}}}}
			}
			transports[1].reply = func(req map[string]any) []any {
				candidate := sdkObj(sdkObj(sdkObj(req["params"])["state"])["candidate"])
				if sdkObj(sdkObj(candidate["value"])["content"])["count"] != float64(2) {
					t.Fatal("accepted answer missing from next interceptor")
				}
				bad := map[string]any{"name": "name", "count": 3, "choice": "a"}
				switch invalid {
				case "constraint", "repaired-constraint":
					bad["choice"] = "other"
				case "overflow":
					bad["count"] = 128
				case "unknown-field":
					bad["extra"] = "must not silently drop"
				}
				effects := []any{map[string]any{"type": "return", "value": map[string]any{"action": "accept", "content": bad}}}
				if invalid == "repaired-constraint" {
					effects = append(effects, map[string]any{"type": "return", "value": map[string]any{"action": "accept", "content": map[string]any{"name": "name", "count": 3, "choice": "a"}}})
				}
				return effects
			}
			transports[2].reply = func(req map[string]any) []any {
				content := sdkObj(sdkObj(sdkObj(sdkObj(req["params"])["state"])["candidate"])["value"])["content"]
				if sdkObj(content)["count"] != float64(2) {
					t.Fatal("later interceptor saw invalid typed answer")
				}
				return nil
			}
			input := hookFormInput(t)
			before := sdkJSON(input)
			result, err := ElicitForm(context.Background(), c, input, form, "choose")
			if err != nil || result == nil {
				t.Fatalf("elicitation: %v", err)
			}
			defer result.Close()
			if len(result.Errors) != 1 || len(result.Response.Effects.Value) != 1 || !result.Candidate.Present || !result.Candidate.Value.Available || result.Candidate.Value.Answer.Count != 2 {
				t.Fatalf("candidate validation failed: errors=%d", len(result.Errors))
			}
			encoded := sdkJSON(result.Candidate.Value.Result)
			if !strings.Contains(string(encoded), `"parts":null`) || !strings.Contains(string(encoded), `"flag":false`) {
				t.Fatal("opaque metadata or literal optional false dropped")
			}
			if string(before) != string(sdkJSON(input)) {
				t.Fatal("request template mutated")
			}
		})
	}
}

func TestFormHooksDeclineCancelAndURL(t *testing.T) {
	for _, action := range []string{"decline", "cancel"} {
		c, transports := testClient(t, "fail-closed")
		setDispatchBoundary(c, "user.elicitation.request", map[string]any{"effects": []any{"return"}, "elicitation": map[string]any{"form": map[string]any{}}})
		transports[0].reply = func(map[string]any) []any {
			return []any{map[string]any{"type": "return", "value": map[string]any{"action": action}}}
		}
		result, err := ElicitForm(context.Background(), c, hookFormInput(t), hookForm(t), "choose")
		if err != nil || result == nil {
			t.Fatalf("%s: %v", action, err)
		}
		if len(result.Errors) != 0 || !result.Candidate.Present || result.Candidate.Value.Available {
			t.Fatal("nonaccept result acquired typed content")
		}
		result.Close()
	}
	c, transports := testClient(t, "fail-closed")
	input := hookFormInput(t)
	input.Elicitation.Mode = "url"
	if result, err := ElicitForm(context.Background(), c, input, hookForm(t), "choose"); err == nil || result != nil || len(transports[0].calls) != 0 {
		t.Fatal("form helper admitted URL mode")
	}
}

func TestFormHooksCorrelatedResultTypedMerge(t *testing.T) {
	c, transports := testClient(t, "fail-open", "fail-open", "fail-open")
	form := hookForm(t)
	setDispatchBoundary(c, "user.elicitation.request", map[string]any{"effects": []any{}, "elicitation": map[string]any{"form": map[string]any{}}})
	request, err := ElicitForm(context.Background(), c, hookFormInput(t), form, "choose")
	if err != nil || request == nil {
		t.Fatalf("request: %v", err)
	}
	defer request.Close()
	if request.Snapshot == nil {
		t.Fatal("original form snapshot missing")
	}
	setDispatchBoundary(c, "user.elicitation.result", map[string]any{"effects": []any{"modify"}, "modify": map[string]any{"content": map[string]any{"merge": true, "replace": true}}, "elicitation": map[string]any{"form": map[string]any{}}})
	for _, backend := range c.backends {
		backend.subscriptions[0]["content"] = map[string]any{"default": "body"}
	}
	c.opts.Content.AuthorizeContent = contentTestAllow
	transports[0].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "modify", "target": "content", "operation": "merge", "value": map[string]any{"count": 2}}}
	}
	transports[1].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "modify", "target": "content", "operation": "merge", "value": map[string]any{"count": 128}}, map[string]any{"type": "modify", "target": "content", "operation": "merge", "value": map[string]any{"count": 3}}}
	}
	transports[2].reply = func(req map[string]any) []any {
		descriptor := sdkObj(sdkObj(sdkObj(req["params"])["event"])["elicitation"])["result"]
		wrapper := compositionObject([]byte(compositionString(sdkObj(descriptor)["text"])))
		if !compositionEqual(sdkObj(wrapper["content"])["count"], json.Number("2")) {
			t.Fatal("invalid typed answer became visible")
		}
		return nil
	}
	input := event.UserElicitationResultInput{ID: ahp.Some("form-result"), ParentEventID: ahp.Some("form-request"), Elicitation: ahp.UserElicitationResultEventElicitation{Mode: "form", Server: "requester", Action: "accept", Result: ahp.Some(hookFormPart(t, "result-body", `{"action":"accept","content":{"name":"name","count":1,"choice":"a","flag":false},"_meta":{"future":{"parts":null}}}`))}}
	result, err := ElicitFormResult(context.Background(), c, input, form, request.Snapshot)
	if err != nil || result == nil {
		t.Fatalf("result: %v", err)
	}
	defer result.Close()
	if len(result.Errors) != 1 || !result.Answer.Present || !result.Answer.Value.Available || result.Answer.Value.Answer.Count != 2 || result.Answer.Value.Answer.Name != "name" {
		t.Fatal("typed partial answer merge not atomic")
	}
	if !strings.Contains(string(sdkJSON(result.Answer.Value.Result)), `"flag":false`) {
		t.Fatal("literal optional false dropped")
	}
}

func TestFormContractExactFloatAndOptionalZero(t *testing.T) {
	type answer struct {
		Number float64 `json:"number"`
		Flag   bool    `json:"flag,omitempty"`
	}
	form, err := NewFormContract[answer]()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := form.DecodeResult([]byte(`{"action":"accept","content":{"number":9007199254740993}}`)); err == nil {
		t.Fatal("float rounded exact JSON integer")
	}
	got, err := form.DecodeResult([]byte(`{"action":"accept","content":{"number":1.5,"flag":false}}`))
	if err != nil || !got.Available || got.Answer.Flag {
		t.Fatalf("optional false: %v", err)
	}
}

func TestFormHooksCorrelatedNonacceptResults(t *testing.T) {
	for _, action := range []string{"decline", "cancel"} {
		c, _ := testClient(t, "fail-closed")
		form := hookForm(t)
		setDispatchBoundary(c, "user.elicitation.request", map[string]any{"effects": []any{}, "elicitation": map[string]any{"form": map[string]any{}}})
		request, err := ElicitForm(context.Background(), c, hookFormInput(t), form, "choose")
		if err != nil || request == nil {
			t.Fatalf("request: %v", err)
		}
		setDispatchBoundary(c, "user.elicitation.result", map[string]any{"effects": []any{"modify"}, "modify": map[string]any{"content": map[string]any{"merge": true, "replace": true}}, "elicitation": map[string]any{"form": map[string]any{}}})
		input := event.UserElicitationResultInput{ID: ahp.Some("form-result"), ParentEventID: ahp.Some("form-request"), Elicitation: ahp.UserElicitationResultEventElicitation{Mode: "form", Server: "requester", Action: ahp.UserElicitationResultEventElicitationAction(action), Result: ahp.Some(hookFormPart(t, "result-body", `{"action":"`+action+`"}`))}}
		result, err := ElicitFormResult(context.Background(), c, input, form, request.Snapshot)
		if err != nil || result == nil {
			t.Fatalf("%s result: %v", action, err)
		}
		if len(result.Errors) != 0 || !result.Answer.Present || result.Answer.Value.Available || result.Answer.Value.Result.Content.Present {
			t.Fatal("nonaccept result acquired content")
		}
		result.Close()
		request.Close()
	}
}

func checkFormOmittedAcceptContent[T any](t *testing.T, wantValid bool) {
	t.Helper()
	form, err := NewFormContract[T]()
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"action":"accept","future":{"opaque":true}}`)
	answer, err := form.DecodeResult(raw)
	if wantValid {
		if err != nil || !answer.Available || answer.Result.Content.Present {
			t.Fatalf("omitted form content: answer=%+v err=%v", answer, err)
		}
		if strings.Contains(string(sdkJSON(answer.Result)), `"content"`) {
			t.Fatal("omitted content was published")
		}
	} else if err == nil {
		t.Fatal("required answer field accepted without content")
	}
	c, transports := testClient(t, "fail-open")
	setDispatchBoundary(c, "user.elicitation.request", map[string]any{"effects": []any{"return"}, "elicitation": map[string]any{"form": map[string]any{}}})
	transports[0].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "return", "value": map[string]any{"action": "accept", "future": map[string]any{"opaque": true}}}}
	}
	result, err := ElicitForm(context.Background(), c, hookFormInput(t), form, "choose")
	if err != nil || result == nil {
		t.Fatalf("public form hook: %v", err)
	}
	defer result.Close()
	if wantValid {
		if len(result.Errors) != 0 || !result.Candidate.Present || !result.Candidate.Value.Available || result.Candidate.Value.Result.Content.Present {
			t.Fatalf("public candidate: %+v errors=%v", result.Candidate, result.Errors)
		}
		if strings.Contains(string(sdkJSON(result.Candidate.Value.Result)), `"content"`) {
			t.Fatal("candidate acquired content")
		}
	} else if len(result.Errors) != 1 || result.Candidate.Present || len(result.Response.Effects.Value) != 0 {
		t.Fatal("invalid required answer was published")
	}
}

func TestFormHooksOmittedAcceptContent(t *testing.T) {
	t.Run("empty", func(t *testing.T) { checkFormOmittedAcceptContent[struct{}](t, true) })
	t.Run("optional", func(t *testing.T) {
		checkFormOmittedAcceptContent[struct {
			Name  string `json:"name,omitempty"`
			Count int    `json:"count,omitempty"`
		}](t, true)
	})
	t.Run("required", func(t *testing.T) {
		checkFormOmittedAcceptContent[struct {
			Name string `json:"name"`
		}](t, false)
	})
}

func TestPublicNeutralElicitationMetadataResult(t *testing.T) {
	c, transports := testClient(t, "fail-open")
	setDispatchBoundary(c, "user.elicitation.request", map[string]any{"effects": []any{}, "elicitation": map[string]any{"form": map[string]any{}}})
	request, err := ElicitForm(context.Background(), c, hookFormInput(t), hookForm(t), "choose")
	if err != nil || request == nil {
		t.Fatal(err)
	}
	defer request.Close()
	setDispatchBoundary(c, "user.elicitation.result", map[string]any{"effects": []any{}})
	var descriptor ahp.TextPart
	if err := json.Unmarshal([]byte(`{"id":"metadata-result","kind":"text","selection":"metadata","mediaType":"text/plain"}`), &descriptor); err != nil {
		t.Fatal(err)
	}
	input := event.UserElicitationResultInput{ID: ahp.Some("form-result"), ParentEventID: ahp.Some("form-request"), Elicitation: ahp.UserElicitationResultEventElicitation{Mode: "form", Server: "requester", Action: "accept", Result: ahp.Some(&descriptor)}}
	before := len(transports[0].calls)
	result, err := c.UserElicitationResult(context.Background(), input, WithElicitationRequest(request.Snapshot))
	if err != nil || result == nil {
		t.Fatalf("metadata result: %v", err)
	}
	defer result.Close()
	if len(result.Errors) != 0 || len(transports[0].calls) != before+1 {
		t.Fatalf("neutral metadata delivery: %v", result.Errors)
	}
}
