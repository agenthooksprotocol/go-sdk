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

type losslessToolArguments struct {
	Count int `json:"count"`
}

func losslessToolInput() event.ToolBeforeInput[losslessToolArguments] {
	return event.ToolBeforeInput[losslessToolArguments]{CallID: "call-lossless", Name: "task", Path: "execute", Origin: "native", Input: losslessToolArguments{Count: 1}}
}

func TestToolBeforeDefaultCodecRejectsLossyEditsAtomically(t *testing.T) {
	for _, raw := range []string{`{"count":null}`, `{"count":1,"future":"lost"}`, `{"count":null,"future":"lost"}`} {
		for _, policy := range []string{"fail-open", "fail-closed"} {
			t.Run(policy+raw, func(t *testing.T) {
				hooks, transports := testClient(t, "fail-open", policy)
				transports[0].reply = func(map[string]any) []any {
					return []any{
						map[string]any{"type": "modify", "target": "input", "operation": "replace", "value": json.RawMessage(`{"count":2}`)},
						map[string]any{"type": "allow"},
					}
				}
				transports[1].reply = func(map[string]any) []any {
					return []any{
						map[string]any{"type": "modify", "target": "input", "operation": "replace", "value": json.RawMessage(raw)},
						// A later repair cannot rescue the invalid intermediate edit.
						map[string]any{"type": "modify", "target": "input", "operation": "replace", "value": json.RawMessage(`{"count":3}`)},
						map[string]any{"type": "allow"},
					}
				}
				result, err := interceptToolBefore(context.Background(), hooks, losslessToolInput())
				if result != nil {
					defer result.Close()
				}
				if err != nil || result == nil || !result.InputAvailable || result.Input.Count != 2 {
					t.Fatalf("lost accepted prefix: result=%+v err=%v", result, err)
				}
				if len(result.AcceptedResponses) != 1 || len(result.Diagnostics) != 1 {
					t.Fatalf("invalid response published: %+v", result)
				}
				if policy == "fail-closed" && result.Permission != "deny" {
					t.Fatal("invalid edit granted execution")
				}
			})
		}
	}
}

func TestToolBeforePublicProjectionCannotGrantLossyInput(t *testing.T) {
	hooks, transports := testClient(t, "fail-closed")
	transports[0].reply = func(map[string]any) []any {
		return []any{
			map[string]any{"type": "modify", "target": "input", "operation": "replace", "value": json.RawMessage(`{"count":null,"future":"lost"}`)},
			map[string]any{"type": "allow"},
		}
	}
	result, err := hooks.ToolBefore(context.Background(), losslessToolInput())
	if result == nil {
		t.Fatalf("missing acceptance evidence: %v", err)
	}
	defer result.Close()
	if result.Permission == "allow" || (!result.Interrupted && result.Permission != "deny") {
		t.Fatalf("lossy projection authorized execution: %+v", result)
	}
	if result.InputAvailable && result.Input.Count != 1 {
		t.Fatal("invalid input became available")
	}
}

func TestToolBeforeDefaultCodecPreservesLargeApplicationNumbers(t *testing.T) {
	hooks, transports := testClient(t, "fail-closed")
	transports[0].reply = func(map[string]any) []any {
		return []any{
			map[string]any{"type": "modify", "target": "input", "operation": "replace", "value": json.RawMessage(`{"count":9007199254740993}`)},
			map[string]any{"type": "allow"},
		}
	}
	input := event.ToolBeforeInput[map[string]any]{CallID: "large", Name: "task", Path: "execute", Origin: "native", Input: map[string]any{"count": json.Number("1")}}
	result, err := interceptToolBefore(context.Background(), hooks, input)
	if result != nil {
		defer result.Close()
	}
	if err != nil || result == nil || !result.InputAvailable || result.Permission != "allow" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	number, ok := result.Input["count"].(json.Number)
	if !ok || number.String() != "9007199254740993" {
		t.Fatalf("application number changed: %#v", result.Input)
	}
}

func TestToolBeforeDefaultCodecRetainsSuppliedValidator(t *testing.T) {
	hooks, transports := testClient(t, "fail-closed")
	transports[0].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "modify", "target": "input", "operation": "replace", "value": json.RawMessage(`{"count":3}`)}}
	}
	validator := JSONCodec(func(value losslessToolArguments) error {
		if value.Count > 2 {
			return errors.New("too large")
		}
		return nil
	})
	result, err := interceptToolBefore(context.Background(), hooks, losslessToolInput(), WithTargetCodec("input", validator))
	if result != nil {
		defer result.Close()
	}
	if err != nil || result == nil || result.Permission != "deny" || len(result.AcceptedResponses) != 0 || result.Input.Count != 1 {
		t.Fatalf("supplied validator bypassed: result=%+v err=%v", result, err)
	}
}

func interruptedProjectionFixture(t *testing.T) (*Result, error) {
	t.Helper()
	result := settlementFixture(t)
	accepted := event.ResponseForRequest(event.ToolBefore, []byte(`{"jsonrpc":"2.0","id":"accepted","result":{"protocolVersion":"draft","effects":[]}}`))
	if !accepted.OK {
		t.Fatal(accepted.Diagnostics)
	}
	result.AcceptedResponses = []ahp.ContextualResponse{accepted.Value}
	result.eventWire = json.RawMessage(`{"type":"future.invalid"}`)
	err := result.decodeSettlement("tool.before")
	if err == nil || result.Event != nil {
		t.Fatal("fixture did not produce interrupted settlement")
	}
	return result, err
}

func TestApplicationProjectionsHandleMissingSettledEvent(t *testing.T) {
	type answer struct {
		Name string `json:"name"`
	}
	form, err := NewFormContract[answer]()
	if err != nil {
		t.Fatal(err)
	}
	for _, projection := range []string{"tool", "declared-tool", "form-request", "form-result"} {
		t.Run(projection, func(t *testing.T) {
			result, original := interruptedProjectionFixture(t)
			var returned *Result
			var got error
			switch projection {
			case "tool":
				out, e := decodeToolBefore[losslessToolArguments](result, original)
				returned, got = out.Result, e
				if out.InputAvailable {
					t.Fatal("input became available")
				}
			case "declared-tool":
				contract := ToolContract[losslessToolArguments, answer]{Arguments: JSONCodec[losslessToolArguments](nil), Result: JSONCodec[answer](nil)}
				out, e := decodeToolDecision(result, original, contract, JSONCodec[json.RawMessage](nil))
				returned, got = out.Result, e
				if out.InputAvailable || out.Candidate.Present {
					t.Fatal("partial application projection")
				}
			case "form-request":
				out, e := decodeFormRequest(result, original, form)
				returned, got = out.Result, e
				if out.Candidate.Present {
					t.Fatal("candidate became available")
				}
			case "form-result":
				out, e := decodeFormResult(result, original, form)
				returned, got = out.Result, e
				if out.Answer.Present {
					t.Fatal("answer became available")
				}
			}
			if !errors.Is(got, original) || returned != result || !returned.Interrupted || returned.Permission != "none" || len(returned.AcceptedResponses) != 1 {
				t.Fatalf("acceptance/error evidence lost: result=%+v err=%v", returned, got)
			}
		})
	}
}

func TestTypedSettlementExposesInitialInstructionsAndInjections(t *testing.T) {
	for _, presence := range []string{"omitted", "empty", "populated"} {
		t.Run(presence, func(t *testing.T) {
			hooks, _ := testClient(t, "fail-closed")
			setDispatchBoundary(hooks, "model.request.before", map[string]any{"effects": []any{}})
			hooks.backends[0].subscriptions[0]["events"] = []any{"tool.before"}
			initial := ahp.InterceptRequestParamsState{Permission: "none", Candidate: ahp.Null[ahp.InterceptRequestParamsStateCandidateValue]()}
			if presence != "omitted" {
				initial.Instructions = ahp.Some([]string{})
				initial.Injections = ahp.Some([]*ahp.InjectEffect{})
			}
			if presence == "populated" {
				initial.Instructions = ahp.Some([]string{"native first", "native second"})
				messages := []any{inlineTestMessage("native-message", "user", inlineTestText("native-part", "native context"))}
				var injection ahp.InjectEffect
				if err := json.Unmarshal(sdkJSON(map[string]any{"type": "inject", "target": "context", "operation": "append", "deliverAt": "next_turn", "value": messages}), &injection); err != nil {
					t.Fatal(err)
				}
				initial.Injections = ahp.Some([]*ahp.InjectEffect{&injection})
			}
			probeEvent := targetTestCanonicalEvent(t, "model.request.before", []any{})
			probeEvent["id"] = "probe"
			probe := map[string]any{"jsonrpc": "2.0", "id": "probe", "method": "hooks/intercept", "params": map[string]any{"protocolVersion": "draft", "event": probeEvent, "capabilities": map[string]any{"effects": []any{}}, "state": initial}}
			if e := canonical.Validate("intercept-request", sdkJSON(probe)); e != nil {
				t.Fatalf("invalid native state fixture: %v", e)
			}
			result, err := hooks.Dispatch(context.Background(), event.ModelRequestBefore, inlineTestInput(t, []any{}), WithInitialState(initial))
			if result != nil {
				defer result.Close()
			}
			if err != nil || result == nil || len(result.AcceptedResponses) != 0 {
				t.Fatalf("result=%+v err=%v state=%s", result, err, sdkJSON(initial))
			}
			if result.Instructions.Present != initial.Instructions.Present || result.Injections.Present != initial.Injections.Present {
				t.Fatal("initial settlement presence changed")
			}
			if string(sdkJSON(result.Instructions)) != string(sdkJSON(initial.Instructions)) || string(sdkJSON(result.Injections)) != string(sdkJSON(initial.Injections)) {
				t.Fatal("initial settlement envelopes changed")
			}
			if presence == "populated" {
				injection := result.Injections.Value[0]
				if injection.DeliverAt != "next_turn" || len(*injection.Value) != 1 {
					t.Fatal("initial typed injection lost payload or extras")
				}
			}
		})
	}
}

func TestTypedSettlementAccumulatesInitialAndReceiverState(t *testing.T) {
	hooks, transports := testClient(t, "fail-closed")
	hooks.opts.Content.AuthorizeContent = contentTestAllow
	hooks.backends[0].subscriptions[0]["content"] = map[string]any{"default": "body"}
	setDispatchBoundary(hooks, "model.request.before", map[string]any{"effects": []any{"inject"}, "inject": map[string]any{"context": map[string]any{"append": true, "deliverAt": []any{"now", "next_turn"}}}})
	messages := []any{inlineTestMessage("receiver-message", "user", inlineTestText("receiver-part", "context"))}
	var injection ahp.InjectEffect
	if err := json.Unmarshal(sdkJSON(map[string]any{"type": "inject", "target": "context", "operation": "append", "deliverAt": "next_turn", "value": messages}), &injection); err != nil {
		t.Fatal(err)
	}
	initial := ahp.InterceptRequestParamsState{Permission: "none", Candidate: ahp.Null[ahp.InterceptRequestParamsStateCandidateValue](), Instructions: ahp.Some([]string{"native"}), Injections: ahp.Some([]*ahp.InjectEffect{&injection})}
	transports[0].reply = func(map[string]any) []any {
		return []any{
			map[string]any{"type": "inject", "target": "context", "operation": "append", "deliverAt": "now", "value": messages},
			map[string]any{"type": "inject", "target": "context", "operation": "append", "deliverAt": "next_turn", "value": messages},
		}
	}
	result, err := hooks.Dispatch(context.Background(), event.ModelRequestBefore, inlineTestInput(t, []any{}), WithInitialState(initial))
	if result != nil {
		defer result.Close()
	}
	if err != nil || result == nil || len(result.Diagnostics) != 0 || len(result.AcceptedResponses) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !result.Instructions.Present || string(sdkJSON(result.Instructions.Value)) != `["native"]` {
		t.Fatal("initial instructions lost")
	}
	if !result.Injections.Present || len(result.Injections.Value) != 3 || result.Injections.Value[0].DeliverAt != "next_turn" || result.Injections.Value[1].DeliverAt != "now" || result.Injections.Value[2].DeliverAt != "next_turn" {
		t.Fatal("injection accumulation/order changed")
	}
	for _, effect := range result.Injections.Value {
		if effect.Type != "inject" || effect.Target != "context" || effect.Operation != "append" || string(sdkJSON(effect.Value)) != string(sdkJSON(messages)) {
			t.Fatal("injection envelope changed")
		}
	}
}

func TestTypedSettlementAccumulatesInstructions(t *testing.T) {
	hooks, transports := testClient(t, "fail-closed")
	setDispatchBoundary(hooks, "turn.finish.before", map[string]any{"effects": []any{"flow"}, "flow": map[string]any{"operations": []any{"continue"}, "remainingContinuations": json.Number("2"), "continuationCount": json.Number("0")}})
	hooks.manifest["limits"].(map[string]any)["maxContinuations"] = json.Number("2")
	initial := ahp.InterceptRequestParamsState{Permission: "none", Candidate: ahp.Null[ahp.InterceptRequestParamsStateCandidateValue](), Instructions: ahp.Some([]string{"native"})}
	transports[0].reply = func(map[string]any) []any {
		return []any{
			map[string]any{"type": "flow", "operation": "continue", "instruction": "receiver first"},
			map[string]any{"type": "flow", "operation": "continue", "instruction": "receiver second"},
		}
	}
	input := map[string]any{"turn": map[string]any{"id": "turn-state"}, "outcome": "completed", "continuationCount": json.Number("0"), "items": []any{}}
	result, err := hooks.Dispatch(context.Background(), event.TurnFinishBefore, input, WithInitialState(initial))
	if result != nil {
		defer result.Close()
	}
	if err != nil || result == nil || len(result.Diagnostics) != 0 || len(result.AcceptedResponses) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !result.Instructions.Present || string(sdkJSON(result.Instructions.Value)) != `["native","receiver first","receiver second"]` {
		t.Fatal("instruction accumulation changed")
	}
}

func TestToolBeforeScalarAndNullInputsFailAdmission(t *testing.T) {
	for _, raw := range []string{"null", "0"} {
		t.Run(raw, func(t *testing.T) {
			hooks, transports := testClient(t, "fail-closed")
			input := event.ToolBeforeInput[json.RawMessage]{CallID: "invalid-input", Name: "task", Path: "execute", Origin: "native", Input: json.RawMessage(raw)}
			result, err := interceptToolBefore(context.Background(), hooks, input)
			var admission *AdmissionError
			if result != nil || !errors.As(err, &admission) || len(transports[0].calls) != 0 {
				t.Fatalf("invalid scalar input admitted: result=%+v err=%v", result, err)
			}
		})
	}
}
