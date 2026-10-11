package client

import (
	"context"
	"encoding/json"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"testing"
)

func TestSessionCountersLosslessFullPublicDecode(t *testing.T) {
	raw := []byte(`{"turns":1e100,"modelRequests":2.0,"toolCalls":9007199254740993,"inputTokens":184467440737095516160,"outputTokens":0,"future":1234567890123456789012345678901234567890}`)
	var counters ahp.SessionCounters
	if err := json.Unmarshal(raw, &counters); err != nil {
		t.Fatal(err)
	}
	if counters.Turns.Value != "1e100" || counters.ModelRequests.Value != "2.0" || counters.AdditionalProperties["future"] != "1234567890123456789012345678901234567890" {
		t.Fatal("counter values rounded or bounded")
	}
	c, _ := testClient(t, "fail-closed")
	input := testContractInput()
	input.Session = ahp.Some(&ahp.Session{ID: "session", Counters: ahp.Some(&counters)})
	result, err := ToolBefore(context.Background(), c, input, testToolContract())
	if err != nil || result == nil {
		t.Fatalf("public decode: %v", err)
	}
	defer result.Close()
	if len(result.Diagnostics) != 0 {
		t.Fatalf("counter admission: %+v", result.Diagnostics)
	}
	var event ahp.Event
	if err := json.Unmarshal(sdkJSON(result.Event), &event); err != nil {
		t.Fatal(err)
	}
	decoded := event.ToolBeforeEvent.Value.Session.Value.Counters.Value
	if decoded == nil || !wireEqual(decoded, &counters) || decoded.ToolCalls.Value != "9007199254740993" {
		t.Fatal("full protocol decoding changed host counters")
	}
}

func TestSessionCountersRejectNonIntegerAndNegative(t *testing.T) {
	for _, raw := range []string{`{"turns":-1}`, `{"future":-1}`, `{"future":1.5}`, `{"toolCalls":null}`, `{"inputTokens":"1"}`} {
		var counters ahp.SessionCounters
		if err := json.Unmarshal([]byte(raw), &counters); err == nil {
			t.Fatalf("accepted invalid counters %s", raw)
		}
	}
	c, transports := testClient(t, "fail-closed")
	input := testInput()
	input["session"] = map[string]any{"id": "session", "counters": map[string]any{"future": json.Number("-1")}}
	if result, err := c.Dispatch(context.Background(), "tool.before", input); err == nil || result != nil || len(transports[0].calls) != 0 {
		t.Fatal("invalid full counter input reached backend")
	}
}
