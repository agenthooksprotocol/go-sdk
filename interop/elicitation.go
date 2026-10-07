package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	ahp "github.com/agenthooksprotocol/go-sdk"
	hooks "github.com/agenthooksprotocol/go-sdk/client"
	"io"
	"net/http"
)

// ValidateElicitationExchange binds complete uploaded MCP objects to normalized
// metadata. Resolve and validate are host-owned. Principal MUST come from the
// authenticated transport, never event.source or elicitation.server.
func ValidateElicitationExchange(request, result Object, resolve func(Object) ([]byte, error), validate func(string, any) error, principal string, effect Object) (Object, error) {
	fail := func() (Object, error) { return nil, fmt.Errorf("invalid elicitation binding or effect grant") }
	if principal == "" {
		return fail()
	}
	for _, e := range []Object{request, result} {
		if err := validate("intercept-request", e); err != nil {
			return nil, err
		}
		if e["id"] != obj(obj(e["params"])["event"])["id"] {
			return fail()
		}
	}
	rp, sp := obj(request["params"]), obj(result["params"])
	re, se := obj(rp["event"]), obj(sp["event"])
	if re["type"] != "user.elicitation.request" || se["type"] != "user.elicitation.result" {
		return fail()
	}
	if err := ValidateElicitationCorrelation(request, result); err != nil {
		return nil, err
	}
	if effect != nil {
		// Legacy single-effect checks share public admission with atomic apply.
		// Return/deny belong to the request; only modify dispatches the result.
		var effectResult Object
		if effect["type"] == "modify" {
			effectResult = result
		}
		if err := acceptElicitationEffects(request, effectResult, resolve, []any{effect}); err != nil {
			return nil, err
		}
	}
	req, res := obj(re["elicitation"]), obj(se["elicitation"])
	payload, err := ReadSelectedElicitation(req, "request", resolve, validate)
	if err != nil {
		return nil, err
	}
	answer, err := ReadSelectedElicitation(res, "result", resolve, validate)
	if err != nil {
		return nil, err
	}
	if req["mode"] != res["mode"] || req["server"] != res["server"] {
		return fail()
	}
	if payload == nil || answer == nil {
		if effect != nil {
			return fail()
		}
		return Object{"selection": Object{"request": elicitationSelection(req, "request"), "result": elicitationSelection(res, "result")}, "bodyValidation": "not-selected", "provenance": Object{"kind": "mcp", "authenticatedSource": principal}, "externalCompletion": false}, nil
	}
	if err = ValidateElicitationAnswer(payload, answer, validate); err != nil {
		return nil, err
	}
	mode := payload["mode"]
	if mode == nil {
		mode = "form"
	}
	if req["mode"] != mode || res["mode"] != mode || req["server"] != res["server"] || res["action"] != answer["action"] {
		return fail()
	}
	if _, ok := answer["content"]; ok && (mode == "url" || answer["action"] != "accept") {
		return fail()
	}
	provenance := Object{"kind": "mcp", "authenticatedSource": principal}
	if effect != nil {
		if err := validateEffectShape(effect); err != nil {
			return nil, err
		}
		if err := validate("effect", effect); err != nil {
			return nil, err
		}
		kind := str(effect["type"])
		boundary := rp
		if kind == "modify" {
			boundary = sp
		}
		if (kind != "return" && kind != "deny" && kind != "modify") || !has(obj(boundary["capabilities"])["effects"], kind) {
			return fail()
		}
		if kind == "modify" && (effect["target"] != "content" || (effect["operation"] != "replace" && effect["operation"] != "merge") || obj(obj(obj(boundary["capabilities"])["modify"])["content"])[str(effect["operation"])] != true) {
			return fail()
		}
		provenance = Object{"kind": "hook", "authenticatedSource": principal, "effect": kind}
	}
	return Object{"request": payload, "result": answer, "provenance": provenance, "externalCompletion": false}, nil
}

// ValidateElicitationAnswer validates submitted values; schema defaults remain
// annotations and are neither applied nor checked against the declared type.
func ValidateElicitationAnswer(request, answer Object, validate func(string, any) error) error {
	if err := validate("mcp-elicitation#result", answer); err != nil {
		return err
	}
	mode := request["mode"]
	if mode == nil {
		mode = "form"
	}
	if _, ok := answer["content"]; ok && (mode == "url" || answer["action"] != "accept") {
		return fmt.Errorf("content only permitted for accepted forms")
	}
	if mode == "form" && answer["action"] == "accept" {
		content, ok := answer["content"]
		if !ok {
			content = Object{}
		}
		return validate("form-answer", Object{"schema": request["requestedSchema"], "value": content})
	}
	return nil
}

func ValidateElicitationMode(mode string, capabilities Object, origin string) (Object, error) {
	if (origin != "ahp" && origin != "mcp") || (mode != "form" && mode != "url") {
		return nil, fmt.Errorf("unknown origin or mode")
	}
	caps := Object{}
	for k, v := range capabilities {
		if k != "form" && k != "url" {
			continue
		}
		if obj(v) == nil {
			return nil, fmt.Errorf("invalid capabilities")
		}
		caps[k] = v
	}
	if origin == "mcp" && capabilities != nil && len(capabilities) == 0 {
		caps["form"] = Object{}
	}
	if _, ok := caps[mode]; !ok {
		return nil, fmt.Errorf("mode not registered")
	}
	return caps, nil
}

// ApplyElicitationEffects stages a complete list without mutating inputs or
// uploads. A nil result means a before-request return/deny boundary. Callers
// publish only the returned validated state, after uploading its complete JSON.
func ApplyElicitationEffects(request, result Object, resolve func(Object) ([]byte, error), validate func(string, any) error, principal string, effects []any) (Object, error) {
	fail := func() (Object, error) { return nil, fmt.Errorf("invalid effect, boundary, or grant") }
	if principal == "" || len(effects) == 0 {
		return fail()
	}
	if err := validate("intercept-request", request); err != nil {
		return nil, err
	}
	event := obj(obj(request["params"])["event"])
	if request["id"] != event["id"] || event["type"] != "user.elicitation.request" {
		return fail()
	}
	if result != nil {
		if err := ValidateElicitationCorrelation(request, result); err != nil {
			return nil, err
		}
	}
	// Admission belongs to the public runtime, before fixture body resolution.
	if err := acceptElicitationEffects(request, result, resolve, effects); err != nil {
		return nil, err
	}
	meta := obj(event["elicitation"])
	payload, err := ReadSelectedElicitation(meta, "request", resolve, validate)
	if err != nil {
		return nil, err
	}
	if payload == nil {
		return fail()
	}
	mode := payload["mode"]
	if mode == nil {
		mode = "form"
	}
	if meta["mode"] != mode {
		return fail()
	}
	boundary := request
	var staged Object
	if result != nil {
		boundary = result
		summary, e := ValidateElicitationExchange(request, result, resolve, validate, principal, nil)
		if e != nil {
			return nil, e
		}
		staged = obj(summary["result"])
		if staged == nil {
			return fail()
		}
	}
	caps := obj(obj(boundary["params"])["capabilities"])
	kinds := []any{}
	for _, value := range effects {
		effect := obj(value)
		if err = validateEffectShape(effect); err != nil {
			return nil, err
		}
		if err = validate("effect", effect); err != nil {
			return nil, err
		}
		kind := str(effect["type"])
		if !has(caps["effects"], kind) || (result == nil && kind != "return" && kind != "deny") || (result != nil && kind != "modify") {
			return fail()
		}
		if kind == "return" || kind == "deny" {
			if len(kinds) > 0 {
				return fail()
			}
			if kind == "return" {
				staged = obj(clone(effect["value"]))
				if staged == nil {
					return fail()
				}
			} else {
				staged = Object{"action": "decline"}
			}
		} else {
			op := str(effect["operation"])
			if effect["target"] != "content" || (op != "replace" && op != "merge") || obj(obj(caps["modify"])["content"])[op] != true {
				return fail()
			}
			if op == "replace" {
				staged["content"] = clone(effect["value"])
			} else {
				value := obj(clone(effect["value"]))
				if value == nil {
					return fail()
				}
				content := obj(staged["content"])
				if content == nil {
					content = Object{}
				}
				for k, v := range value {
					content[k] = v
				}
				staged["content"] = content
			}
		}
		kinds = append(kinds, kind)
	}
	if err = ValidateElicitationAnswer(payload, staged, validate); err != nil {
		return nil, err
	}
	return Object{"request": payload, "result": staged, "provenance": Object{"kind": "hook", "authenticatedSource": principal, "effects": kinds}, "externalCompletion": false}, nil
}

func elicitationSelection(meta Object, stage string) string {
	item := obj(meta[stage])
	if item == nil {
		return "omit"
	}
	return str(item["selection"])
}

// ReadSelectedElicitation never resolves metadata/omit; selected gaps fail closed.
func ReadSelectedElicitation(meta Object, stage string, resolve func(Object) ([]byte, error), validate func(string, any) error) (Object, error) {
	item := obj(meta[stage])
	if item == nil {
		return nil, nil
	}
	if err := validate("content-item", item); err != nil {
		return nil, err
	}
	if item["mediaType"] != "application/json" {
		return nil, fmt.Errorf("MCP body must be application/json")
	}
	if item["selection"] != "body" {
		return nil, nil
	}
	body := obj(item["body"])
	if body == nil {
		return nil, fmt.Errorf("selected body unavailable (fail closed)")
	}
	raw, err := resolve(body)
	if err != nil {
		return nil, err
	}
	var payload Object
	if err = json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	if err = validate("mcp-elicitation#"+stage, payload); err != nil {
		return nil, err
	}
	if stage == "request" {
		mode := payload["mode"]
		if mode == nil {
			mode = "form"
		}
		if meta["mode"] != mode {
			return nil, fmt.Errorf("mode mismatch")
		}
	}
	if stage == "result" {
		if meta["action"] != payload["action"] {
			return nil, fmt.Errorf("action mismatch")
		}
		if _, ok := payload["content"]; ok && (meta["mode"] == "url" || payload["action"] != "accept") {
			return nil, fmt.Errorf("forbidden content")
		}
	}
	return payload, nil
}

// ValidateElicitationCorrelation must run before body resolution or effects.
func ValidateElicitationCorrelation(request, result Object) error {
	req, res := obj(obj(request["params"])["event"]), obj(obj(result["params"])["event"])
	parent, ok := res["parentEventId"].(string)
	if !ok || parent != req["id"] || res["source"] != req["source"] || obj(res["session"])["id"] != obj(req["session"])["id"] {
		return fmt.Errorf("elicitation parent/source/session mismatch")
	}
	return nil
}

// acceptElicitationEffects uses the same public typed dispatch as wire adapters.
// The offline fixture owns the isolated upload sink and candidate effects only;
// pinned MCP validation, atomic acceptance and snapshots belong to the runtime.
func acceptElicitationEffects(request, result Object, resolve func(Object) ([]byte, error), effects []any) error {
	return acceptElicitationEffectsObserved(request, result, resolve, effects, nil)
}

// The optional observer records actual hook deliveries for admission regressions.
func acceptElicitationEffectsObserved(request, result Object, resolve func(Object) ([]byte, error), effects []any, delivered func(string)) error {
	boundaries := []Object{request}
	if result != nil {
		boundaries = append(boundaries, result)
	}
	events := []any{}
	names := []any{}
	refs := map[string]Object{}
	for _, req := range boundaries {
		p := obj(req["params"])
		e := obj(p["event"])
		name := str(e["type"])
		caps := obj(clone(p["capabilities"]))
		events = append(events, Object{"event": name, "modes": []any{"intercept"}, "capabilities": caps})
		names = append(names, name)
		for _, field := range []string{"request", "result"} {
			ref := obj(obj(obj(e["elicitation"])[field])["body"])
			if ref != nil {
				refs[str(ref["ref"])] = ref
			}
		}
	}
	reg := ahp.ParseRegistration(jsonBytes(Object{"protocolVersion": "draft", "hooks": []any{Object{"id": "org.agenthooks.elicitation-fixture", "transport": Object{"type": "http", "url": "https://fixture.invalid/hooks"}, "subscriptions": []any{Object{"events": names, "mode": "intercept", "timeoutMs": 1000, "failurePolicy": "fail-closed", "content": Object{"default": "body"}, "upload": Object{"endpoint": "https://fixture.invalid/upload", "timeoutMs": 1000, "maxBytes": 4 << 20}}}}}}))
	if !reg.OK {
		return fmt.Errorf("invalid elicitation fixture registration")
	}
	var manifest ahp.StaticCapabilityManifest
	if err := json.Unmarshal(jsonBytes(Object{"events": events, "gaps": []any{}, "transports": []any{"http"}, "authentication": []any{}, "toolPaths": []any{"execute"}, "contentCategories": []any{"text"}, "limits": Object{"maxContinuations": 4}, "managedPolicy": Object{"scopes": []any{"user"}, "disableable": true}, "correlationIdentityFields": []any{"event.id"}}), &manifest); err != nil {
		return err
	}
	transport := &fixtureTransport{exchange: func(_ context.Context, _ string, raw []byte) ([]byte, error) {
		var req Object
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if delivered != nil {
			delivered(str(obj(obj(req["params"])["event"])["type"]))
		}
		selected := []any{}
		if result == nil || obj(obj(req["params"])["event"])["type"] == "user.elicitation.result" {
			selected = effects
		}
		return jsonBytes(Object{"jsonrpc": "2.0", "id": req["id"], "result": Object{"protocolVersion": "draft", "effects": selected}}), nil
	}}
	c, err := hooks.New(reg.Value, hooks.Options{Source: str(obj(obj(request["params"])["event"])["source"]), Manifest: manifest, EventClient: &http.Client{Transport: transport}, UploadClient: &http.Client{Transport: memoryUpload{}}, Content: hooks.ContentOptions{Resolver: func(_ context.Context, ref string) (io.ReadCloser, error) {
		descriptor, ok := refs[ref]
		if !ok {
			return nil, fmt.Errorf("unknown original body")
		}
		raw, err := resolve(descriptor)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(raw)), nil
	}, AuthorizeContent: func(context.Context, hooks.ContentAuthorization) (bool, error) { return true, nil }}})
	if err != nil {
		return err
	}
	defer c.Close()
	var snapshot *hooks.ElicitationRequest
	for _, req := range boundaries {
		e := obj(obj(req["params"])["event"])
		var opts []hooks.InterceptOption
		if snapshot != nil {
			opts = append(opts, hooks.WithElicitationRequest(snapshot))
		}
		accepted, err := dispatchPublicBoundary(context.Background(), c, str(e["type"]), e, opts)
		if err != nil {
			return err
		}
		if len(accepted.Errors) > 0 {
			return accepted.Errors[0]
		}
		snapshot = accepted.Snapshot
	}
	return nil
}
