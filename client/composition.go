package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

// CapabilityAdmissionError reports missing prepared inputs for protocol-only
// composition. Public boundary calls prepare verified bodies and snapshots first;
// invalid or missing host inputs fail admission before transport dispatch.
type CapabilityAdmissionError struct {
	Event  string
	Effect string
	Target string
	Reason string
}

func (e *CapabilityAdmissionError) Error() string {
	return fmt.Sprintf("unsupported capability %s/%s at %s: %s", e.Effect, e.Target, e.Event, e.Reason)
}

// Composition is an atomically accepted protocol response. It does not authorize
// native execution or validate effective values against an application's schema.
// Response retains accepted effects even when a subsequent host decode fails.
type Composition struct {
	// Event is the accepted effective event; caller-owned input is never mutated.
	Event          json.RawMessage
	State          ahp.InterceptRequestParamsState
	EffectiveInput json.RawMessage
	Response       ahp.InterceptResponseResult
	prepared       *preparedBoundary
}

// EffectiveValue encodes an available accepted non-input target on demand.
// It never opens an unread attachment or retains another copy of its bytes.
// Protocol-only compositions without prepared owners have no effective values.
func (c *Composition) EffectiveValue(target string) (json.RawMessage, error) {
	if c == nil || c.prepared == nil || target == "input" {
		return nil, fmt.Errorf("effective value %q unavailable", target)
	}
	event := compositionObject(c.Event)
	if event == nil {
		return nil, fmt.Errorf("effective event unavailable")
	}
	// Decoding may materialize an elicitation snapshot; keep that assignment
	// local while sharing immutable attachment owners.
	view := c.prepared.clone()
	values, err := view.values(event)
	if err != nil {
		return nil, err
	}
	value, ok := values[target]
	if !ok {
		return nil, fmt.Errorf("effective value %q unavailable", target)
	}
	return sdkJSON(value), nil
}

func compose(request ahp.InterceptRequest, response ahp.InterceptResponse) (*Composition, error) {
	return composePrepared(request, response, nil)
}

func composePrepared(request ahp.InterceptRequest, response ahp.InterceptResponse, prepared *preparedBoundary) (*Composition, error) {
	reqBytes, err := ahp.EncodeInterceptRequest(request)
	if err != nil {
		return nil, fmt.Errorf("encode intercept request: %w", err)
	}
	if err := canonical.Validate("intercept-request", reqBytes); err != nil {
		return nil, err
	}
	req := ahp.ParseInterceptRequest(reqBytes)
	if !req.OK {
		return nil, fmt.Errorf("invalid intercept request")
	}
	resBytes, err := ahp.EncodeInterceptResponse(response)
	if err != nil {
		return nil, fmt.Errorf("encode intercept response: %w", err)
	}
	if err := canonical.Validate("intercept-response", resBytes); err != nil {
		return nil, err
	}
	res := ahp.ParseInterceptResponse(resBytes)
	if !res.OK {
		return nil, fmt.Errorf("invalid intercept response")
	}
	r, s := compositionObject(reqBytes), compositionObject(resBytes)
	p := compositionMap(r["params"])
	event, caps := compositionMap(p["event"]), compositionMap(p["capabilities"])
	if !compositionEqual(r["id"], s["id"]) || !compositionEqual(r["id"], event["id"]) {
		return nil, fmt.Errorf("intercept correlation mismatch")
	}
	state := compositionMap(p["state"])
	if state == nil {
		state = map[string]any{"permission": "none", "candidate": nil}
	}
	kind := compositionString(event["type"])
	if err := compositionEventConstraints(event); err != nil {
		return nil, err
	}
	if err := compositionCapabilitiesPrepared(caps, event, prepared != nil); err != nil {
		return nil, err
	}
	effects := compositionArray(compositionMap(s["result"])["effects"])
	for _, raw := range effects {
		if err := compositionAdmit(compositionMap(raw), caps, state, kind); err != nil {
			return nil, err
		}
	}
	values := map[string]any{}
	var staged *preparedBoundary
	if prepared != nil {
		staged = prepared.clone()
		values, err = staged.values(event)
		if err != nil {
			return nil, err
		}
	}
	if candidate := compositionMap(state["candidate"]); candidate != nil {
		if kind == "user.elicitation.request" {
			if staged == nil || staged.snapshot == nil {
				return nil, fmt.Errorf("elicitation candidate requires an original request snapshot")
			}
			if err := validateElicitationAnswer(event, staged.snapshot, candidate["value"]); err != nil {
				return nil, err
			}
		}
		if kind == "context.compact.before" || kind == "model.request.before" {
			if err := validateSuppliedValue(kind, candidate["value"]); err != nil {
				return nil, err
			}
		}
	}
	tool := compositionMap(event["tool"])
	if value, ok := tool["input"]; ok {
		values["input"] = value
	}

	initial, _ := json.Marshal(values)
	for _, raw := range effects {
		e := compositionMap(raw)
		if e["type"] != "modify" {
			continue
		}
		target := compositionString(e["target"])
		v := e["value"]
		if e["operation"] == "merge" && inlineListTarget(kind, target) {
			base, ok := values[target].([]any)
			if !ok {
				return nil, fmt.Errorf("list target unavailable")
			}
			extra, ok := v.([]any)
			if !ok {
				return nil, fmt.Errorf("list merge requires an array")
			}
			v = append(append([]any{}, base...), extra...)
		} else if e["operation"] == "merge" {
			base := compositionMap(values[target])
			if base == nil {
				return nil, fmt.Errorf("merge target %s is not an available object", target)
			}
			merged := make(map[string]any, len(base))
			for k, v := range base {
				merged[k] = v
			}
			for k, v := range compositionMap(e["value"]) {
				merged[k] = v
			}
			v = merged
		}
		if target != "input" {
			if staged == nil {
				return nil, compositionUnsupportedTarget(kind, target)
			}
			bodyValue := v
			if kind == "user.elicitation.result" {
				original, err := selectedElicitation(sdkObj(event["elicitation"]), "result", nil)
				if err != nil {
					return nil, err
				}
				answer := sdkObj(original)
				if answer == nil {
					return nil, fmt.Errorf("elicitation result must be an object")
				}
				// content is the structured MCP answer, not the containing result.
				// Preserve action and all extension fields, including _meta.
				answer["content"] = v
				if err := validateElicitationAnswer(event, staged.snapshot, answer); err != nil {
					return nil, err
				}
				bodyValue = answer
			}
			if err := staged.apply(event, target, bodyValue); err != nil {
				return nil, err
			}
		}
		values[target] = v
		if target == "input" {
			if tool == nil {
				return nil, fmt.Errorf("input target unavailable")
			}
			tool["input"] = v
		}
	}
	if !compositionEqual(compositionObject(initial), values) {
		state["candidate"] = nil
		if state["permission"] == "allow" {
			state["permission"] = "none"
		}
	}
	for _, raw := range effects {
		e := compositionMap(raw)
		switch e["type"] {
		case "deny":
			state["permission"] = "deny"
		case "ask":
			if state["permission"] != "deny" {
				state["permission"] = "ask"
			}
		case "allow":
			if state["permission"] != "deny" && state["permission"] != "ask" {
				state["permission"] = "allow"
			}
		case "return":
			if err := validateSuppliedValue(kind, e["value"]); err != nil {
				return nil, err
			}
			if kind == "user.elicitation.request" {
				if staged == nil || staged.snapshot == nil {
					return nil, fmt.Errorf("elicitation request snapshot unavailable")
				}
				if err := validateElicitationAnswer(event, staged.snapshot, e["value"]); err != nil {
					return nil, err
				}
			}
			if kind == "context.compact.before" {
				if err := validateSuppliedValue(kind, e["value"]); err != nil {
					return nil, err
				}
			}
			state["candidate"] = map[string]any{"value": e["value"]}
		case "flow":
			if e["operation"] == "continue" {
				if instruction, ok := e["instruction"]; ok {
					state["instructions"] = append(compositionArray(state["instructions"]), instruction)
				}
			}
			if state["flow"] != "stop" {
				state["flow"] = e["operation"]
			}
		case "inject":
			state["injections"] = append(compositionArray(state["injections"]), e)
		}
	}
	if state["permission"] == "deny" || state["flow"] == "stop" {
		state["candidate"] = nil
	}
	p["event"] = event
	if err := canonical.Validate("intercept-request", sdkJSON(r)); err != nil {
		return nil, err
	}
	out := &Composition{Response: res.Value.Result, prepared: staged}
	stateBytes, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(stateBytes, &out.State); err != nil {
		return nil, fmt.Errorf("compose state: %w", err)
	}
	if value, ok := values["input"]; ok {
		out.EffectiveInput, err = json.Marshal(value)
		if err != nil {
			return nil, err
		}
	}
	out.Event, err = json.Marshal(event)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func compositionAdmit(e, caps, state map[string]any, event string) error {
	typ, op, target := compositionString(e["type"]), compositionString(e["operation"]), compositionString(e["target"])
	if !compositionContains(caps["effects"], typ) {
		return fmt.Errorf("unadvertised effect %s", typ)
	}

	if !strings.Contains(" "+compositionBounds[event]+" ", " "+typ+" ") {
		return fmt.Errorf("effect %s not permitted at %s", typ, event)
	}
	fields := "type"
	switch typ {
	case "allow", "ask":
	case "deny":
		fields += " reason code extensions"
		if compositionString(e["reason"]) == "" {
			return fmt.Errorf("deny requires reason")
		}
	case "message":
		fields += " text"
	case "return":
		fields += " value"
	case "modify":
		fields += " target operation value"
		if inlineListTarget(event, target) {
			schema := "content-item#messages"
			if target == "instructions" || target == "summary" {
				schema = "content-item#textParts"
			}
			if err := canonical.Validate(schema, sdkJSON(e["value"])); err != nil {
				return fmt.Errorf("modification requires a canonical list")
			}
		} else if event == "user.elicitation.result" && target == "content" && compositionMap(e["value"]) == nil {
			return fmt.Errorf("elicitation content modification requires an answer object")
		}

		if compositionTargets[event] != target || (op != "replace" && op != "merge") || compositionMap(compositionMap(caps["modify"])[target])[op] != true {
			return fmt.Errorf("unadvertised modification")
		}
		if (target == "input" || (op == "merge" && !inlineListTarget(event, target))) && compositionMap(e["value"]) == nil {
			return fmt.Errorf("modification requires an object")
		}
	case "flow":
		f := compositionMap(caps["flow"])
		if !compositionContains(f["operations"], op) {
			return fmt.Errorf("unadvertised flow operation")
		}
		switch op {
		case "stop":
			fields += " operation reason"
			if compositionString(e["reason"]) == "" {
				return fmt.Errorf("stop requires reason")
			}
		case "continue":
			fields += " operation instruction"
			if event != "tool.after" && event != "turn.finish.before" {
				return fmt.Errorf("continuation not permitted at boundary")
			}
			remaining, ok := compositionNatural(f["remainingContinuations"])
			if !ok || (remaining.Sign() == 0 && state["flow"] != "continue") {
				return fmt.Errorf("continuation allowance exhausted or invalid")
			}
			if _, ok := compositionNatural(f["continuationCount"]); !ok {
				return fmt.Errorf("invalid continuation count")
			}
			if instruction, present := e["instruction"]; present && compositionString(instruction) == "" {
				return fmt.Errorf("empty continuation instruction")
			}
		default:
			return fmt.Errorf("unknown flow operation")
		}
	case "inject":
		fields += " target operation deliverAt value"
		c := compositionMap(compositionMap(caps["inject"])["context"])
		delivery := compositionString(e["deliverAt"])
		if target != "context" || op != "append" || c["append"] != true || (delivery != "now" && delivery != "next_turn") || !compositionContains(c["deliverAt"], delivery) {
			return fmt.Errorf("unadvertised injection")
		}
	default:
		return fmt.Errorf("unsupported effect")
	}
	for key := range e {
		if !strings.Contains(" "+fields+" ", " "+key+" ") {
			return fmt.Errorf("unknown effect field %s", key)
		}
	}
	return nil
}

func compositionEventConstraints(event map[string]any) error {
	kind := compositionString(event["type"])
	if kind == "context.compact.before" {
		for _, key := range []string{"summary", "removed", "execution"} {
			if _, ok := event[key]; ok {
				return fmt.Errorf("compaction before contains %s", key)
			}
		}
		if _, ok := compositionMap(event["tokenCounts"])["after"]; ok {
			return fmt.Errorf("compaction before contains after token count")
		}
	}
	if kind == "context.compact.after" {
		execution := compositionMap(event["execution"])
		if execution["status"] == "skipped" && execution["reason"] != "supplied_result" {
			return fmt.Errorf("invalid compaction execution correlation")
		}
	}
	return nil
}

func compositionObject(b []byte) map[string]any {
	var out map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	_ = d.Decode(&out) // Bytes originate in successful canonical encode/parse calls.
	return out
}
func compositionMap(v any) map[string]any { m, _ := v.(map[string]any); return m }
func compositionArray(v any) []any        { a, _ := v.([]any); return a }
func compositionString(v any) string      { s, _ := v.(string); return s }
func compositionContains(v any, s string) bool {
	for _, x := range compositionArray(v) {
		if x == s {
			return true
		}
	}
	return false
}
func compositionNatural(v any) (*big.Int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return nil, false
	}
	r, ok := new(big.Rat).SetString(string(n))
	if !ok || !r.IsInt() || r.Sign() < 0 {
		return nil, false
	}
	return r.Num(), true
}
func compositionEqual(a, b any) bool {
	switch a := a.(type) {
	case json.Number:
		bn, ok := b.(json.Number)
		if !ok {
			return false
		}
		ar, aok := new(big.Rat).SetString(string(a))
		br, bok := new(big.Rat).SetString(string(bn))
		return aok && bok && ar.Cmp(br) == 0
	case map[string]any:
		bm, ok := b.(map[string]any)
		if !ok || len(a) != len(bm) {
			return false
		}
		for k, v := range a {
			bv, ok := bm[k]
			if !ok || !compositionEqual(v, bv) {
				return false
			}
		}
		return true
	case []any:
		bs, ok := b.([]any)
		if !ok || len(a) != len(bs) {
			return false
		}
		for i, v := range a {
			if !compositionEqual(v, bs[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(a, b)
	}
}

var compositionBounds = map[string]string{
	"session.start": "inject message", "config.change.before": "deny message", "turn.start": "deny modify inject flow message",
	"turn.finish.before": "modify flow message", "model.request.before": "deny modify inject return flow message", "model.response.after": "modify flow message", "model.switch.before": "deny flow message",
	"tool.before": "deny allow ask modify inject flow return message", "tool.after": "modify inject flow message", "tool.permission.request": "allow deny modify flow message", "tool.batch.after": "flow inject message",
	"context.compact.before": "deny modify return inject message", "context.compact.after": "inject modify message", "task.change.before": "deny message", "user.elicitation.request": "deny return message", "user.elicitation.result": "modify message", "user.message.inbound": "deny modify message", "user.message.outbound": "deny modify message", "workspace.change.before": "deny modify message",
}

var compositionTargets = map[string]string{"turn.start": "prompt", "turn.finish.before": "response", "model.request.before": "request", "model.response.after": "response", "tool.before": "input", "tool.after": "output", "tool.permission.request": "input", "context.compact.before": "instructions", "context.compact.after": "summary", "user.elicitation.result": "content", "user.message.inbound": "prompt", "user.message.outbound": "content", "workspace.change.before": "workspace"}

// validateInitial performs protocol-only validation before dispatch or upload.
func validateInitial(request ahp.InterceptRequest) error {
	raw, err := ahp.EncodeInterceptRequest(request)
	if err != nil {
		return err
	}
	r := compositionObject(raw)
	responseBytes, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": r["id"], "result": map[string]any{"protocolVersion": "draft", "effects": []any{}}})
	if err != nil {
		return err
	}
	response := ahp.ParseInterceptResponse(responseBytes)
	if !response.OK {
		return fmt.Errorf("invalid request correlation ID")
	}
	_, err = compose(request, response.Value)
	return err
}

func compositionCapabilities(caps, event map[string]any) error {
	return compositionCapabilitiesPrepared(caps, event, false)
}
func compositionCapabilitiesPrepared(caps, event map[string]any, prepared bool) error {
	kind := compositionString(event["type"])
	for _, raw := range compositionArray(caps["effects"]) {
		effect := compositionString(raw)
		if !strings.Contains(" "+compositionBounds[kind]+" ", " "+effect+" ") {
			return fmt.Errorf("capability %s not permitted at %s", effect, kind)
		}
	}
	if kind == "user.elicitation.request" || kind == "user.elicitation.result" {
		mode := compositionString(compositionMap(event["elicitation"])["mode"])
		if mode != "form" && mode != "url" {
			return fmt.Errorf("invalid elicitation mode")
		}
		// AHP mode grants are independent of effect grants (interaction-payloads,
		// MCP elicitation binding). Returning, denying, or modifying an interaction
		// enforces that mode, even when no answer content is produced. An absent
		// or empty AHP grant is not MCP's legacy implicit form support. Passive
		// delivery and informational messages do not decide or alter the interaction.
		modeDecision := compositionContains(caps["effects"], "return") ||
			compositionContains(caps["effects"], "deny") ||
			compositionContains(caps["effects"], "modify")
		if modeDecision && compositionMap(compositionMap(caps["elicitation"])[mode]) == nil {
			return fmt.Errorf("elicitation mode is not advertised")
		}
		if !prepared && compositionContains(caps["effects"], "return") {
			return &CapabilityAdmissionError{Event: kind, Effect: "return", Reason: "elicitation answers require the original MCP request body and requester/mode correlation; wire descriptors cannot establish form-schema or URL consent validity"}
		}
	}
	for target, grant := range compositionMap(caps["modify"]) {
		if !prepared && target != "input" && strings.Contains(" output prompt request response content instructions summary workspace ", " "+target+" ") {
			operations := compositionMap(grant)
			if operations["replace"] == true || operations["merge"] == true {
				return compositionUnsupportedTarget(kind, target)
			}
		}
		// Unknown capability fields are ignorable, not grants.
		if strings.Contains(" input output prompt request response content instructions summary workspace ", " "+target+" ") && target != compositionTargets[kind] {
			return fmt.Errorf("modification target not permitted at boundary")
		}
	}
	flow := compositionMap(caps["flow"])
	for _, operation := range compositionArray(flow["operations"]) {
		if !strings.Contains(" "+compositionBounds[kind]+" ", " flow ") {
			return fmt.Errorf("flow capability not permitted at boundary")
		}
		if operation == "continue" {
			if kind != "turn.finish.before" && kind != "tool.after" {
				return fmt.Errorf("continuation capability not permitted at boundary")
			}
			if _, ok := compositionNatural(flow["remainingContinuations"]); !ok {
				return fmt.Errorf("invalid continuation allowance")
			}
			if _, ok := compositionNatural(flow["continuationCount"]); !ok {
				return fmt.Errorf("invalid continuation count")
			}
			if count, present := event["continuationCount"]; present && !compositionEqual(count, flow["continuationCount"]) {
				return fmt.Errorf("continuation count correlation mismatch")
			}
		}
	}
	return nil
}

func compositionUnsupportedTarget(event, target string) error {
	reason := "target requires an explicit native-to-wire projection, unavailable to the protocol-only composer"
	if target != "workspace" {
		reason = "target requires resolved content and immutable descriptor re-publication, unavailable to the protocol-only composer"
	}
	return &CapabilityAdmissionError{Event: event, Effect: "modify", Target: target, Reason: reason}
}
