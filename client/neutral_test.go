package client

import (
	"context"
	"encoding/json"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"reflect"
	"testing"
)

func TestDispatchNeutralEffects(t *testing.T) {
	for _, field := range []string{"absent", "empty", "null", "invalid"} {
		t.Run(field, func(t *testing.T) {
			c, _ := testClient(t, "fail-closed")
			c.backends[0].transport = diagnosticTransport{response: func(req map[string]any) []byte {
				result := map[string]any{"protocolVersion": "draft", "future": map[string]any{"parts": nil}}
				switch field {
				case "empty":
					result["effects"] = []any{}
				case "null":
					result["effects"] = nil
				case "invalid":
					result["effects"] = "invalid"
				}
				return sdkJSON(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": result})
			}}
			input := testInput()
			before := contentClone(input)
			result, err := c.Dispatch(context.Background(), "tool.before", input)
			if err != nil || result == nil {
				t.Fatalf("dispatch: %v", err)
			}
			defer result.Close()
			if field == "null" || field == "invalid" {
				if len(result.Errors) == 0 {
					t.Fatal("invalid effects accepted")
				}
				return
			}
			if len(result.Errors) != 0 || result.Response.Effects.Value == nil || len(result.Response.Effects.Value) != 0 {
				t.Fatalf("not typed neutral: %+v", result)
			}
			if !reflect.DeepEqual(input, before) {
				t.Fatal("input mutated")
			}
		})
	}
}

func TestGeneratedAbsentEffectsRemainNeutralWithoutMutation(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":"test","result":{"protocolVersion":"draft","future":{"kind":"attachment","parts":null}}}`)
	before := string(raw)
	parsed := ahp.ResponseForRequest("tool.before", raw)
	if !parsed.OK {
		t.Fatal(parsed.Diagnostics)
	}
	value := parsed.Value.(*ahp.ToolBeforeInterceptResponse)
	if len(value.Result.Effects.Value) != 0 || string(raw) != before {
		t.Fatal("absence changed wire or is nonneutral")
	}
	encoded, err := json.Marshal(value)
	if err != nil || !compositionEqual(compositionObject(raw), compositionObject(encoded)) {
		t.Fatal("opaque response metadata changed")
	}
}
