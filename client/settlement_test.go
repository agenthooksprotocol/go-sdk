package client

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/event"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

// These assignments are compiler regressions: callers need no schema-owned JSON
// decode to reach effective messages, candidates, or contextual effect envelopes.
func typedConsumerSurface(r *Result) {
	var event *ahp.Event = r.SettledEvent
	var response ahp.ContextualResponse = r.AcceptedResponse
	var candidate *ahp.MessagesCandidate = r.SettledCandidate.Value.Messages
	var messages *ahp.CanonicalMessages = candidate.Value
	_, _, _, _ = event, response, candidate, messages
}

func TestTypedSettlementPublicBoundary(t *testing.T) {
	c, transports := testClient(t, "fail-closed")
	c.opts.Content.AuthorizeContent = contentTestAllow
	c.backends[0].subscriptions[0]["content"] = map[string]any{"default": "body"}
	setDispatchBoundary(c, "model.request.before", map[string]any{"effects": []any{"return", "message", "inject"}, "inject": map[string]any{"context": map[string]any{"append": true, "deliverAt": []any{"now"}}}})
	messages := []any{inlineTestMessage("m1", "user", inlineTestText("p1", "hello"))}
	input := inlineTestInput(t, messages)
	input["future"] = json.RawMessage(`{"integer":9007199254740993,"null":null}`)
	input["params"] = map[string]any{"future": json.RawMessage(`{"integer":9007199254740993,"null":null}`)}
	transports[0].reply = func(req map[string]any) []any {
		effects := []any{
			map[string]any{"type": "return", "value": messages},
			map[string]any{"type": "message", "text": "accepted"},
			map[string]any{"type": "inject", "target": "context", "operation": "append", "deliverAt": "now", "value": messages},
		}
		parsed := ahp.ResponseForRequest("model.request.before", sdkJSON(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"protocolVersion": "draft", "effects": effects}}))
		if err := canonical.Validate("intercept-response", sdkJSON(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"protocolVersion": "draft", "effects": effects}})); err != nil {
			t.Fatal(err)
		}
		if !parsed.OK {
			t.Fatal(parsed.Diagnostics)
		}
		return effects
	}
	result, err := c.Dispatch(context.Background(), "model.request.before", input)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if !result.SettledEvent.ModelRequestBeforeEvent.Present {
		t.Fatal("missing typed event")
	}
	if len(result.Errors) != 0 {
		t.Fatalf("delivery rejected: %+v", result.Errors)
	}
	candidate := result.SettledCandidate.Value.Messages
	if !result.SettledCandidate.Valid || candidate == nil || len(*candidate.Value) != 1 {
		t.Fatal("missing typed candidate")
	}
	typedConsumerSurface(result)
	response, ok := result.AcceptedResponse.(*ahp.ModelRequestBeforeInterceptResponse)
	if !ok || len(response.Result.Effects.Value) != 3 {
		t.Fatal("missing contextual effects")
	}
	message := response.Result.Effects.Value[1].MessageEffect.Value
	injection := response.Result.Effects.Value[2].InjectEffect.Value
	if message.Text != "accepted" || injection.DeliverAt != "now" || len(*injection.Value) != 1 {
		t.Fatal("erased effect envelopes")
	}
	encoded, err := json.Marshal(result.SettledEvent)
	if err != nil {
		t.Fatal(err)
	}
	if !contractPreserves(compositionObject(result.Event), compositionObject(encoded)) {
		t.Fatal("settled event lost extras")
	}
	future := result.SettledEvent.ModelRequestBeforeEvent.Value.AdditionalProperties["future"]
	if string(future) != `{"integer":9007199254740993,"null":null}` {
		t.Fatalf("opaque extras changed: %s", future)
	}
}

func settlementFixture(t *testing.T) *Result {
	t.Helper()
	request := compositionTestRequest(t)
	return &Result{Event: sdkJSON(request.Params.Event), State: request.Params.State.Value, Response: compositionTestResponse(t, `[]`).Result}
}

func TestTypedSettlementCandidateNullAndExtras(t *testing.T) {
	r := settlementFixture(t)
	raw := `{"value":null,"provenance":{"future":{"n":9007199254740993}},"future":null}`
	var candidate ahp.InterceptRequestParamsStateCandidateValue
	if err := json.Unmarshal([]byte(raw), &candidate); err != nil {
		t.Fatal(err)
	}
	r.State.Candidate = ahp.NonNull(candidate)
	if err := r.decodeSettlement("tool.before", true); err != nil {
		t.Fatal(err)
	}
	if !r.SettledCandidate.Valid || string(r.SettledCandidate.Value.Opaque.Value) != "null" {
		t.Fatal("null candidate became absent")
	}
	encoded, _ := json.Marshal(r.SettledCandidate.Value.Opaque)
	if !contractPreserves(compositionObject([]byte(raw)), compositionObject(encoded)) {
		t.Fatal("candidate extras/provenance lost")
	}
	r.State.Candidate = ahp.Null[ahp.InterceptRequestParamsStateCandidateValue]()
	if err := r.decodeSettlement("tool.before", true); err != nil || r.SettledCandidate.Valid {
		t.Fatal("absent candidate became present", err)
	}
}

func TestTypedSettlementInvalidFailsAtomically(t *testing.T) {
	for _, kind := range []string{"event", "identity", "response", "candidate"} {
		t.Run(kind, func(t *testing.T) {
			r := settlementFixture(t)
			name := "tool.before"
			switch kind {
			case "event":
				r.Event = json.RawMessage(`{"type":"unknown.future"}`)
			case "identity":
				name = "tool.after"
			case "response":
				r.Response.Effects.Value = []*ahp.Effect{{}}
			case "candidate":
				name = "model.request.before"
				r.Event = sdkJSON(targetTestCanonicalEvent(t, name, []any{}))
				r.State.Candidate = ahp.NonNull(ahp.InterceptRequestParamsStateCandidateValue{Value: json.RawMessage(`42`)})
			}
			r.Permission = "allow"
			err := r.decodeSettlement(name, true)
			var decode *SettlementDecodeError
			if !errors.As(err, &decode) {
				t.Fatalf("expected decode error: %v", err)
			}
			if !r.Interrupted || r.Permission != "none" || r.State.Permission != "allow" {
				t.Fatal("decode failure did not gate execution or lost accepted state")
			}
			if r.SettledEvent != nil || r.AcceptedResponse != nil || r.SettledCandidate.Valid {
				t.Fatal("partial typed publication")
			}
		})
	}
}

func TestTypedSettlementOtherCandidateOrigins(t *testing.T) {
	for _, kind := range []string{"context.compact.before", "user.elicitation.request"} {
		t.Run(kind, func(t *testing.T) {
			r := settlementFixture(t)
			var event map[string]any
			var value any
			if kind == "context.compact.before" {
				value = []any{inlineTestText("p", "summary")}
				event = map[string]any{"id": "test", "source": "urn:test", "time": "2026-01-01T00:00:00Z", "type": kind, "trigger": "manual", "items": []any{}, "instructions": value}
			} else {
				event, _ = elicitationFixture("request", "form", `{"message":"question","requestedSchema":{"type":"object","properties":{}}}`)
				event["id"], event["source"], event["time"] = "test", "urn:test", "2026-01-01T00:00:00Z"
				value = map[string]any{"action": "decline", "future": map[string]any{"n": json.Number("9007199254740993")}}
			}
			r.Event = sdkJSON(event)
			var raw ahp.InterceptRequestParamsStateCandidateValue
			candidate := map[string]any{"value": value, "provenance": map[string]any{"future": true}, "future": nil}
			if err := json.Unmarshal(sdkJSON(candidate), &raw); err != nil {
				t.Fatal(err)
			}
			r.State.Candidate = ahp.NonNull(raw)
			if err := r.decodeSettlement(kind, true); err != nil {
				t.Fatal(err)
			}
			var envelope any
			if kind == "context.compact.before" {
				text := r.SettledCandidate.Value.Text
				if text == nil || len(*text.Value) != 1 {
					t.Fatal("missing TextParts candidate")
				}
				envelope = text
			} else {
				elicit := r.SettledCandidate.Value.Elicitation
				if elicit == nil {
					t.Fatal("missing complete elicitation candidate")
				}
				envelope = elicit
			}
			if !contractPreserves(candidate, compositionObject(sdkJSON(envelope))) {
				t.Fatal("candidate envelope extras lost")
			}
		})
	}
}

func TestTypedSettlementNamedModelRequest(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	setDispatchBoundary(c, "model.request.before", map[string]any{"effects": []any{}})
	canonical := targetTestCanonicalEvent(t, "model.request.before", []any{})
	parsed := ahp.ParseEvent(sdkJSON(canonical))
	if !parsed.OK {
		t.Fatal(parsed.Diagnostics)
	}
	original := parsed.Value.ModelRequestBeforeEvent.Value
	result, err := c.ModelRequestBefore(context.Background(), event.ModelRequestBeforeInput{Attempt: original.Attempt, Model: original.Model, Params: original.Params, Items: original.Items})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if result.SettledEvent == nil || !result.SettledEvent.ModelRequestBeforeEvent.Present {
		t.Fatal("named consumer requires event decode")
	}
	if _, ok := result.AcceptedResponse.(*ahp.ModelRequestBeforeInterceptResponse); !ok {
		t.Fatal("named consumer response lost context")
	}
}
