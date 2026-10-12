package client

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/event"
)

type contractArguments struct {
	Name     string         `json:"name"`
	Count    int            `json:"count"`
	Nullable *string        `json:"nullable"`
	Nested   map[string]int `json:"nested"`
	Exact    json.Number    `json:"exact"`
}
type contractAnswer struct {
	Answer string `json:"answer"`
}
type contractProvenance struct {
	Origin string `json:"origin"`
}

func testToolContract() ToolContract[contractArguments, contractAnswer] {
	return ToolContract[contractArguments, contractAnswer]{Arguments: JSONCodec(func(a contractArguments) error {
		if a.Name == "" || a.Count < 1 || a.Exact != "9007199254740993" {
			return errors.New("invalid arguments contain private values")
		}
		return nil
	}), Result: JSONCodec(func(r contractAnswer) error {
		if r.Answer == "" {
			return errors.New("answer required")
		}
		return nil
	})}
}
func testContractInput() event.ToolBeforeInput[contractArguments] {
	literal := "old"
	return event.ToolBeforeInput[contractArguments]{CallID: "call-contract", Path: "execute", Name: "task", Origin: "native", ToolKind: ahp.Some("task"), Input: contractArguments{Name: "required", Count: 1, Nullable: &literal, Nested: map[string]int{"old": 1, "keep": 2}, Exact: "9007199254740993"}}
}

func TestContractToolBeforeWholeStagedMerge(t *testing.T) {
	c, transports := testClient(t, "fail-closed", "fail-closed")
	input := testContractInput()
	before := sdkJSON(input)
	transports[0].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "modify", "target": "input", "operation": "merge", "value": map[string]any{"count": 2, "nullable": nil, "nested": map[string]any{"new": 3}}}, map[string]any{"type": "return", "value": map[string]any{"answer": "yes"}}}
	}
	transports[1].reply = func(req map[string]any) []any {
		args := sdkObj(sdkObj(sdkObj(sdkObj(req["params"])["event"])["tool"])["input"])
		if args["name"] != "required" || args["nullable"] != nil || len(sdkObj(args["nested"])) != 1 || args["count"] != float64(2) {
			t.Fatal("patch was decoded as whole T or merge was deep")
		}
		return nil
	}
	result, err := ToolBefore(context.Background(), c, input, testToolContract())
	if err != nil || result == nil {
		t.Fatalf("tool: %v", err)
	}
	defer result.Close()
	if len(result.Diagnostics) != 0 || !result.InputAvailable || result.Input.Count != 2 || result.Input.Name != "required" || result.Input.Nullable != nil || result.Input.Exact != "9007199254740993" || !reflect.DeepEqual(result.Input.Nested, map[string]int{"new": 3}) {
		t.Fatalf("whole staged input: %+v errors=%+v", result.Input, result.Diagnostics)
	}
	if !result.Candidate.Present || result.Candidate.Value.Value.Answer != "yes" {
		t.Fatal("result type was not independent of argument type")
	}
	if !reflect.DeepEqual(before, sdkJSON(input)) {
		t.Fatal("caller-owned input mutated")
	}
}

func TestContractInvalidResponseRollbackBeforeLaterInterceptor(t *testing.T) {
	for _, invalid := range []string{"argument-type", "invariant", "return-type", "unknown-field", "null-loss", "nonobject-merge", "repaired-invariant", "repaired-return"} {
		t.Run(invalid, func(t *testing.T) {
			c, transports := testClient(t, "fail-open", "fail-open", "fail-open")
			transports[0].reply = func(map[string]any) []any {
				return []any{map[string]any{"type": "modify", "target": "input", "operation": "merge", "value": map[string]any{"count": 2}}}
			}
			transports[1].reply = func(map[string]any) []any {
				patch := any(map[string]any{"count": 3})
				switch invalid {
				case "argument-type":
					patch = map[string]any{"count": "bad"}
				case "invariant", "repaired-invariant":
					patch = map[string]any{"count": 0}
				case "unknown-field":
					patch = map[string]any{"extra": "must not drop"}
				case "null-loss":
					patch = map[string]any{"count": nil}
				case "nonobject-merge":
					patch = "not an object"
				}
				effects := []any{map[string]any{"type": "modify", "target": "input", "operation": "merge", "value": patch}}
				if invalid == "return-type" || invalid == "repaired-return" {
					effects = append(effects, map[string]any{"type": "return", "value": map[string]any{"count": 9}})
				}
				if invalid == "repaired-invariant" {
					effects = append(effects, map[string]any{"type": "modify", "target": "input", "operation": "merge", "value": map[string]any{"count": 3}})
				}
				if invalid == "repaired-return" {
					effects = append(effects, map[string]any{"type": "return", "value": map[string]any{"answer": "repaired"}})
				}
				return effects
			}
			transports[2].reply = func(req map[string]any) []any {
				params := sdkObj(req["params"])
				args := sdkObj(sdkObj(sdkObj(params["event"])["tool"])["input"])
				if args["count"] != float64(2) || sdkObj(params["state"])["candidate"] != nil {
					t.Fatal("later interceptor saw invalid response changes")
				}
				return []any{map[string]any{"type": "return", "value": map[string]any{"answer": "valid"}}}
			}
			result, err := ToolBefore(context.Background(), c, testContractInput(), testToolContract())
			if err != nil || result == nil {
				t.Fatalf("tool: %v", err)
			}
			defer result.Close()
			if len(result.Diagnostics) != 1 || result.Input.Count != 2 || len(result.response.Effects.Value) != 2 || !result.Candidate.Present || result.Candidate.Value.Value.Answer != "valid" {
				t.Fatalf("rollback: count=%d errors=%d effects=%d", result.Input.Count, len(result.Diagnostics), len(result.response.Effects.Value))
			}
			if strings.Contains(result.Diagnostics[0].Error(), "private values") {
				t.Fatal("validator payload leaked")
			}
		})
	}
}

func TestContractInvalidInitialInputRejectedBeforeDelivery(t *testing.T) {
	c, transports := testClient(t, "fail-closed")
	input := testContractInput()
	input.Input.Count = 0
	result, err := ToolBefore(context.Background(), c, input, testToolContract())
	if result != nil || err == nil || len(transports[0].calls) != 0 {
		t.Fatal("invalid input reached backend")
	}
}

func TestContractCandidateNullAndProvenanceReplacement(t *testing.T) {
	for _, mode := range []string{"absent", "retained", "null-value", "replacement", "input-change"} {
		t.Run(mode, func(t *testing.T) {
			c, transports := testClient(t, "fail-open")
			raw := `{"permission":"none","candidate":{"value":{"answer":"old"},"provenance":{"origin":"host"}}}`
			if mode == "absent" {
				raw = `{"permission":"none","candidate":null}`
			}
			var initial ahp.InterceptRequestParamsState
			if err := json.Unmarshal([]byte(raw), &initial); err != nil {
				t.Fatal(err)
			}
			transports[0].reply = func(map[string]any) []any {
				switch mode {
				case "null-value":
					return []any{map[string]any{"type": "return", "value": nil}}
				case "replacement":
					return []any{map[string]any{"type": "return", "value": map[string]any{"answer": "new"}}}
				case "input-change":
					return []any{map[string]any{"type": "modify", "target": "input", "operation": "merge", "value": map[string]any{"count": 2}}}
				default:
					return nil
				}
			}
			contract := ToolContract[contractArguments, *contractAnswer]{Arguments: testToolContract().Arguments, Result: JSONCodec[*contractAnswer](nil)}
			result, err := ToolBeforeWithProvenance(context.Background(), c, testContractInput(), contract, JSONCodec[contractProvenance](nil), WithInitialState(initial))
			if err != nil || result == nil {
				t.Fatalf("tool: %v", err)
			}
			defer result.Close()
			if len(result.Diagnostics) != 0 {
				t.Fatalf("errors: %+v", result.Diagnostics)
			}
			if mode == "absent" || mode == "input-change" {
				if result.Candidate.Present {
					t.Fatal("candidate survived clearing")
				}
				return
			}
			if mode == "retained" {
				if !result.Candidate.Present || !result.Candidate.Value.Provenance.Present || result.Candidate.Value.Provenance.Value.Origin != "host" {
					t.Fatal("declared provenance not associated with retained candidate")
				}
				return
			}
			if !result.Candidate.Present || result.Candidate.Value.Provenance.Present {
				t.Fatal("replacement inherited provenance")
			}
			if mode == "null-value" && result.Candidate.Value.Value != nil {
				t.Fatal("null candidate confused with absent candidate")
			}
			if mode == "replacement" && (result.Candidate.Value.Value == nil || result.Candidate.Value.Value.Answer != "new") {
				t.Fatal("replacement candidate missing")
			}
		})
	}
}

func TestCodecRejectsDataLossAndKeepsExactOpaqueValues(t *testing.T) {
	raw := json.RawMessage(`{"known":1,"future":{"kind":"attachment","ref":"private"},"integer":9007199254740993}`)
	type narrow struct {
		Known int `json:"known"`
	}
	if _, err := JSONCodec[narrow](nil).DecodeJSON(raw); err == nil {
		t.Fatal("unknown fields silently dropped")
	}
	decoded, err := JSONCodec[map[string]any](nil).DecodeJSON(raw)
	if err != nil || decoded["integer"] != json.Number("9007199254740993") {
		t.Fatalf("exact opaque decode: %v", err)
	}
	if _, err := JSONCodec[map[string]float64](nil).DecodeJSON(json.RawMessage(`{"integer":9007199254740993}`)); err == nil {
		t.Fatal("integer fidelity lost silently")
	}
	if _, err := JSONCodec[any](nil).DecodeJSON(json.RawMessage(`1 2`)); err == nil {
		t.Fatal("multiple values accepted")
	}
	if _, err := JSONCodec[int](nil).DecodeJSON(json.RawMessage(`null`)); err == nil {
		t.Fatal("literal null was coerced to zero")
	}
}

func TestContractPublicHostCodecsOptInOnly(t *testing.T) {
	for _, mode := range []string{"opaque", "declared", "invalid", "missing"} {
		t.Run(mode, func(t *testing.T) {
			c, transports := testClient(t, "fail-closed")
			input := testInput()
			input["native"] = map[string]any{"count": 1, "future": map[string]any{"kind": "attachment", "ref": "must not resolve"}}
			var options []InterceptOption
			if mode == "declared" {
				options = append(options, WithHostValueCodec("/native", JSONCodec[map[string]json.RawMessage](nil)))
			}
			if mode == "invalid" {
				type native struct {
					Count string `json:"count"`
				}
				options = append(options, WithHostValueCodec("/native", JSONCodec[native](nil)))
			}
			if mode == "missing" {
				options = append(options, WithHostValueCodec("/absent", JSONCodec[int](nil)))
			}
			result, err := c.Dispatch(context.Background(), event.ToolBefore, input, options...)
			if mode == "invalid" {
				if err == nil || result != nil || len(transports[0].calls) != 0 {
					t.Fatal("invalid host contract reached backend")
				}
				return
			}
			if err != nil || result == nil {
				t.Fatalf("dispatch: %v", err)
			}
			defer result.Close()
			if len(result.Diagnostics) != 0 || !compositionEqual(compositionObject(sdkJSON(result.Event))["native"], compositionObject(sdkJSON(input))["native"]) {
				t.Fatal("opaque host value reshaped")
			}
		})
	}
}

func TestContractRejectsInvalidDeclarationsAndInitialCandidate(t *testing.T) {
	for _, mode := range []string{"target", "pointer", "candidate", "provenance"} {
		t.Run(mode, func(t *testing.T) {
			c, transports := testClient(t, "fail-closed")
			var options []InterceptOption
			switch mode {
			case "target":
				options = append(options, WithTargetCodec("not-a-target", JSONCodec[any](nil)))
			case "pointer":
				options = append(options, WithHostValueCodec("/native/~broken", JSONCodec[any](nil)))
			case "candidate", "provenance":
				value := `{"answer":"old"}`
				provenance := `{"origin":"host"}`
				if mode == "candidate" {
					value = `{"count":1}`
				}
				if mode == "provenance" {
					provenance = `{"origin":42}`
				}
				var state ahp.InterceptRequestParamsState
				if err := json.Unmarshal([]byte(`{"permission":"none","candidate":{"value":`+value+`,"provenance":`+provenance+`}}`), &state); err != nil {
					t.Fatal(err)
				}
				options = append(options, WithInitialState(state))
			}
			input := testContractInput()
			if mode == "pointer" {
				native := ahp.NativeEvent(json.RawMessage(`{}`))
				input.Native = ahp.Some(&native)
			}
			result, err := ToolBeforeWithProvenance(context.Background(), c, input, testToolContract(), JSONCodec[contractProvenance](nil), options...)
			if err == nil || result != nil || len(transports[0].calls) != 0 {
				t.Fatal("invalid declaration or initial candidate reached backend")
			}
		})
	}
}
