package client

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

func compositionTestRequest(t *testing.T) ahp.InterceptRequest {
	t.Helper()
	p := ahp.ParseInterceptRequest([]byte(`{"jsonrpc":"2.0","id":"test","method":"hooks/intercept","params":{"protocolVersion":"draft","event":{"id":"test","source":"urn:test","type":"tool.before","time":"2026-01-01T00:00:00Z","call":{"id":"call"},"path":"execute","tool":{"name":"task","kind":"task","origin":"native","input":{"task":1,"nested":{"a":1},"large":9007199254740993}}},"capabilities":{"effects":["allow","ask","deny","modify","return","message","inject","flow"],"modify":{"input":{"replace":true,"merge":true}},"inject":{"context":{"append":true,"deliverAt":["now","next_turn"]}},"flow":{"operations":["stop"]}},"state":{"permission":"allow","candidate":{"value":"cached"},"injections":[]}}}`))
	if !p.OK {
		t.Fatal(p.Diagnostics)
	}
	return p.Value
}
func compositionTestResponse(t *testing.T, effects string) ahp.InterceptResponse {
	t.Helper()
	p := ahp.ParseInterceptResponse([]byte(`{"jsonrpc":"2.0","id":"test","result":{"protocolVersion":"draft","effects":` + effects + `}}`))
	if !p.OK {
		t.Fatal(p.Diagnostics)
	}
	return p.Value
}
func compositionTestState(t *testing.T, c *Composition) map[string]any {
	t.Helper()
	b, err := json.Marshal(c.State)
	if err != nil {
		t.Fatal(err)
	}
	return compositionObject(b)
}

func TestCompositionHostDecodeDoesNotRejectProtocol(t *testing.T) {
	req := compositionTestRequest(t)
	res := compositionTestResponse(t, `[{"type":"modify","target":"input","operation":"merge","value":{"task":"host-incompatible","nested":{"b":2},"literal":null}},{"type":"message","text":"accepted"}]`)
	before, _ := ahp.EncodeInterceptRequest(req)
	c, err := compose(req, res)
	if err != nil {
		t.Fatal(err)
	}
	var host struct{ Task int }
	if json.Unmarshal(c.EffectiveInput, &host) == nil {
		t.Fatal("expected host decode failure")
	}
	if len(c.Response.Effects) != 2 {
		t.Fatal("accepted effects lost")
	}
	v := compositionObject(c.EffectiveInput)
	if v["large"] != json.Number("9007199254740993") || !reflect.DeepEqual(v["nested"], map[string]any{"b": json.Number("2")}) {
		t.Fatal(v)
	}
	if _, ok := v["literal"]; !ok {
		t.Fatal("literal null deleted")
	}
	state := compositionTestState(t, c)
	if state["permission"] != "none" || state["candidate"] != nil {
		t.Fatal("stale approval/candidate", state)
	}
	after, _ := ahp.EncodeInterceptRequest(req)
	if string(before) != string(after) {
		t.Fatal("mutated caller request")
	}
	event := compositionObject(c.Event)
	if !compositionEqual(compositionMap(event["tool"])["input"], v) {
		t.Fatal("effective event stale")
	}
}

func TestCompositionAtomicRejection(t *testing.T) {
	req := compositionTestRequest(t)
	original, _ := ahp.EncodeInterceptRequest(req)
	for _, effects := range []string{
		`[{"type":"deny","reason":"no"},{"type":"modify","target":"input","operation":"replace","value":null}]`,
		`[{"type":"message","text":"never published"},{"type":"modify","target":"output","operation":"replace","value":{}}]`,
		`[{"type":"inject","target":"context","operation":"append","deliverAt":"now","value":"never queued"},{"type":"flow","operation":"continue"}]`,
	} {
		c, err := compose(req, compositionTestResponse(t, effects))
		if err == nil || c != nil {
			t.Fatal("accepted invalid response", effects)
		}
	}
	current, _ := ahp.EncodeInterceptRequest(req)
	if string(original) != string(current) {
		t.Fatal("rejection mutated accepted prefix")
	}
}

func TestCompositionPermissionAndBinding(t *testing.T) {
	for _, tc := range []struct {
		effects, permission string
		candidate           bool
	}{
		{`[{"type":"return","value":false},{"type":"modify","target":"input","operation":"replace","value":{"task":0}}]`, "none", true},
		{`[{"type":"ask"},{"type":"allow"}]`, "ask", true},
		{`[{"type":"deny","reason":"blocked"},{"type":"ask"},{"type":"allow"},{"type":"return","value":null}]`, "deny", false},
		{`[{"type":"flow","operation":"stop","reason":"stop"},{"type":"return","value":false}]`, "allow", false},
		{`[]`, "allow", true},
	} {
		c, err := compose(compositionTestRequest(t), compositionTestResponse(t, tc.effects))
		if err != nil {
			t.Fatal(err)
		}
		state := compositionTestState(t, c)
		if state["permission"] != tc.permission || (state["candidate"] != nil) != tc.candidate {
			t.Fatal(state, tc)
		}
	}
}

func TestCompositionUnknownEffectFieldAndCorrelation(t *testing.T) {
	req := compositionTestRequest(t)
	res := compositionTestResponse(t, `[{"type":"message","text":"ok"}]`)
	raw, _ := ahp.EncodeInterceptResponse(res)
	m := compositionObject(raw)
	compositionMap(compositionArray(compositionMap(m["result"])["effects"])[0])["future"] = true
	b, _ := json.Marshal(m)
	// Unmarshal permits constructing malformed canonical models; acceptance must not.
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if c, err := compose(req, res); err == nil || c != nil {
		t.Fatal("unknown effect field accepted")
	}
	res = compositionTestResponse(t, `[]`)
	if err := json.Unmarshal([]byte(`"wrong"`), res.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := compose(req, res); err == nil {
		t.Fatal("correlation mismatch accepted")
	}
}

func TestCompositionFlowAndInjectionQueues(t *testing.T) {
	req := compositionTestRequest(t)
	raw, _ := ahp.EncodeInterceptRequest(req)
	r := compositionObject(raw)
	p := compositionMap(r["params"])
	p["event"] = map[string]any{"id": "test", "source": "urn:test", "type": "turn.finish.before", "time": "2026-01-01T00:00:00Z", "turn": map[string]any{"id": "turn"}, "outcome": "completed", "continuationCount": json.Number("0"), "items": []any{}}
	p["capabilities"] = map[string]any{"effects": []any{"flow", "message"}, "flow": map[string]any{"operations": []any{"stop", "continue"}, "remainingContinuations": json.Number("1"), "continuationCount": json.Number("0")}}
	b, _ := json.Marshal(r)
	parsed := ahp.ParseInterceptRequest(b)
	if !parsed.OK {
		t.Fatal(parsed.Diagnostics)
	}
	req = parsed.Value
	c, err := compose(req, compositionTestResponse(t, `[{"type":"flow","operation":"continue","instruction":"first"},{"type":"flow","operation":"continue","instruction":"second"}]`))
	if err != nil {
		t.Fatal(err)
	}
	state := compositionTestState(t, c)
	if state["flow"] != "continue" || !reflect.DeepEqual(state["instructions"], []any{"first", "second"}) {
		t.Fatal(state)
	}
	compositionMap(compositionMap(p["capabilities"])["flow"])["remainingContinuations"] = json.Number("0")
	b, _ = json.Marshal(r)
	parsed = ahp.ParseInterceptRequest(b)
	if _, err := compose(parsed.Value, compositionTestResponse(t, `[{"type":"flow","operation":"continue"}]`)); err == nil {
		t.Fatal("exhausted continuation accepted")
	}
	req = compositionTestRequest(t)
	c, err = compose(req, compositionTestResponse(t, `[{"type":"inject","target":"context","operation":"append","deliverAt":"now","value":"one"},{"type":"inject","target":"context","operation":"append","deliverAt":"next_turn","value":"two"}]`))
	if err != nil {
		t.Fatal(err)
	}
	state = compositionTestState(t, c)
	if len(compositionArray(state["injections"])) != 2 {
		t.Fatal(state)
	}
	req.Params.State = ahp.Optional[ahp.InterceptRequestParamsState]{Present: true, Value: c.State}
	c, err = compose(req, compositionTestResponse(t, `[]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(compositionArray(compositionTestState(t, c)["injections"])) != 2 {
		t.Fatal("lost accepted queue")
	}
}

func TestCompositionEquivalentNumbersPreserveApproval(t *testing.T) {
	req := compositionTestRequest(t)
	c, err := compose(req, compositionTestResponse(t, `[{"type":"modify","target":"input","operation":"merge","value":{"task":1.0}}]`))
	if err != nil {
		t.Fatal(err)
	}
	state := compositionTestState(t, c)
	if state["permission"] != "allow" || state["candidate"] == nil {
		t.Fatal("unchanged input invalidated approval")
	}
}

func compositionBoundaryRequest(t *testing.T, event, capabilities map[string]any) ahp.InterceptRequest {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "test", "method": "hooks/intercept", "params": map[string]any{"protocolVersion": "draft", "event": event, "capabilities": capabilities, "state": map[string]any{"permission": "none", "candidate": nil}}})
	if err != nil {
		t.Fatal(err)
	}
	parsed := ahp.ParseInterceptRequest(raw)
	if !parsed.OK {
		t.Fatal(parsed.Diagnostics)
	}
	return parsed.Value
}

func compositionDescriptor() map[string]any {
	return map[string]any{"id": "item-1", "kind": "text", "mediaType": "text/plain", "selection": "metadata"}
}

// Each descriptor-backed boundary survives two serial accepted responses without
// raw effect bytes replacing its descriptor. Mutation grants are rejected during
// admission, before a backend could be asked to supply an unpublishable result.
func TestCompositionDescriptorBoundariesSerial(t *testing.T) {
	for _, tc := range []struct{ event, target string }{
		{"context.compact.before", "instructions"},
		{"context.compact.after", "summary"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			event := map[string]any{"id": "test", "source": "urn:test", "type": tc.event, "time": "2026-01-01T00:00:00Z", tc.target: compositionDescriptor()}
			if tc.event == "context.compact.before" {
				event["trigger"] = "manual"
				event["items"] = []any{}
			} else {
				compositionMap(event[tc.target])["role"] = "assistant"
				event["removed"] = []any{}
				event["execution"] = map[string]any{"status": "executed"}
			}
			caps := map[string]any{"effects": []any{"message"}}
			req := compositionBoundaryRequest(t, event, caps)
			first, err := compose(req, compositionTestResponse(t, `[{"type":"message","text":"first"}]`))
			if err != nil {
				t.Fatal(err)
			}
			next := compositionBoundaryRequest(t, compositionObject(first.Event), caps)
			next.Params.State = ahp.Optional[ahp.InterceptRequestParamsState]{Present: true, Value: first.State}
			second, err := compose(next, compositionTestResponse(t, `[{"type":"message","text":"second"}]`))
			if err != nil {
				t.Fatal(err)
			}
			if !compositionEqual(compositionObject(second.Event)[tc.target], event[tc.target]) {
				t.Fatal("descriptor changed")
			}
			caps["effects"] = []any{"modify", "message"}
			caps["modify"] = map[string]any{tc.target: map[string]any{"replace": true, "merge": false}}
			unsupported := compositionBoundaryRequest(t, compositionObject(second.Event), caps)
			var admission *CapabilityAdmissionError
			if err := validateInitial(unsupported); !errors.As(err, &admission) || admission.Target != tc.target || admission.Effect != "modify" {
				t.Fatalf("expected typed admission rejection, got %v", err)
			}
			if c, err := compose(unsupported, compositionTestResponse(t, `[{"type":"modify","target":"`+tc.target+`","operation":"replace","value":"raw new body"}]`)); !errors.As(err, &admission) || c != nil {
				t.Fatal("unpublishable mutation accepted", c, err)
			}
		})
	}
}

func TestCompositionNonInputGrantsRejectedBeforeEffects(t *testing.T) {
	for _, target := range []string{"output", "prompt", "request", "response", "content", "instructions", "summary", "workspace"} {
		var event string
		for kind, supported := range compositionTargets {
			if supported == target {
				event = kind
				break
			}
		}
		for _, operation := range []string{"replace", "merge"} {
			caps := map[string]any{"modify": map[string]any{target: map[string]any{operation: true}}}
			err := compositionCapabilities(caps, map[string]any{"type": event, "elicitation": map[string]any{"mode": "form"}})
			// Eliminate elicitation-mode failure so this test isolates target admission.
			if event == "user.elicitation.result" {
				caps["elicitation"] = map[string]any{"form": map[string]any{}}
				err = compositionCapabilities(caps, map[string]any{"type": event, "elicitation": map[string]any{"mode": "form"}})
			}
			var admission *CapabilityAdmissionError
			if !errors.As(err, &admission) || admission.Target != target {
				t.Fatalf("%s/%s: %v", target, operation, err)
			}
		}
	}
}

func TestCompositionElicitationReturnRequiresRequestBodyCorrelation(t *testing.T) {
	for _, mode := range []string{"form", "url"} {
		t.Run(mode, func(t *testing.T) {
			descriptor := compositionDescriptor()
			descriptor["mediaType"] = "application/json"
			event := map[string]any{"id": "test", "source": "urn:test", "type": "user.elicitation.request", "time": "2026-01-01T00:00:00Z", "elicitation": map[string]any{"server": "requester", "mode": mode, "request": descriptor}}
			caps := map[string]any{"effects": []any{"return", "deny", "message"}, "elicitation": map[string]any{mode: map[string]any{}}}
			req := compositionBoundaryRequest(t, event, caps)
			var admission *CapabilityAdmissionError
			if err := validateInitial(req); !errors.As(err, &admission) || admission.Effect != "return" {
				t.Fatal("uncorrelated return grant reached dispatch", err)
			}
			for _, answer := range []string{`{"action":"accept","content":{"answer":"unvalidated"}}`, `{"action":"accept"}`, `{"action":"decline","content":{"answer":"forbidden"}}`, `{"action":"cancel"}`} {
				c, err := compose(req, compositionTestResponse(t, `[{"type":"return","value":`+answer+`}]`))
				if !errors.As(err, &admission) || c != nil {
					t.Fatal("answer accepted without original form schema/URL correlation", err)
				}
			}
			// Denial and user messages do not fabricate an MCP answer or URL completion.
			caps["effects"] = []any{"deny", "message"}
			req = compositionBoundaryRequest(t, event, caps)
			if err := validateInitial(req); err != nil {
				t.Fatal(err)
			}
			c, err := compose(req, compositionTestResponse(t, `[{"type":"deny","reason":"not permitted"}]`))
			if err != nil {
				t.Fatal(err)
			}
			if state := compositionTestState(t, c); state["permission"] != "deny" || state["candidate"] != nil {
				t.Fatal(state)
			}
		})
	}
}

func TestCompositionElicitationResultMutationRequiresExchange(t *testing.T) {
	for _, mode := range []string{"form", "url"} {
		descriptor := compositionDescriptor()
		descriptor["mediaType"] = "application/json"
		event := map[string]any{"id": "test", "source": "urn:test", "type": "user.elicitation.result", "time": "2026-01-01T00:00:00Z", "parentEventId": "original-request", "elicitation": map[string]any{"server": "requester", "mode": mode, "action": "accept", "result": descriptor}}
		caps := map[string]any{"effects": []any{"modify"}, "modify": map[string]any{"content": map[string]any{"replace": true, "merge": true}}, "elicitation": map[string]any{mode: map[string]any{}}}
		req := compositionBoundaryRequest(t, event, caps)
		var admission *CapabilityAdmissionError
		if err := validateInitial(req); !errors.As(err, &admission) || admission.Target != "content" {
			t.Fatal("result mutation accepted without original exchange", err)
		}
	}
}
