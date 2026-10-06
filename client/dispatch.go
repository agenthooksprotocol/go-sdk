package client

import (
	"context"
	"encoding/json"
	"errors"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
	"time"
)

func (c *Hooks) intercept(ctx context.Context, name string, input any, options ...InterceptOption) (*Result, error) {
	result, err := c.dispatch(ctx, name, input, options...)
	if result == nil && err != nil {
		return nil, &AdmissionError{Kind: "input", Err: err}
	}
	return result, err
}

func (c *Hooks) dispatch(ctx context.Context, name string, input any, options ...InterceptOption) (*Result, error) {
	// Generated inputs expose named source slots without serializing streams.
	if bound, ok := input.(interface {
		AHPContentSources() map[string]*content.Source
	}); ok {
		var bindings []InterceptOption
		for path, source := range bound.AHPContentSources() {
			bindings = append(bindings, WithContentSource(path, source))
		}
		options = append(bindings, options...)
	}
	cfg := contentSourceConfig(options)
	admitted := false
	defer func() {
		cfg.closeSources()
		if admitted {
			c.active.Done()
		}
	}()
	if ctx == nil {
		return nil, errors.New("nil context")
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("client closed")
	}
	c.active.Add(1)
	admitted = true
	c.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.life, cancel)
	defer stop()
	defer cancel()
	event, err := sdkMap(input)
	if err != nil {
		return nil, err
	}
	if event == nil {
		return nil, errors.New("nil boundary input")
	}
	for _, key := range []string{"source", "type", "manifest"} {
		if _, ok := event[key]; ok {
			return nil, errors.New("boundary input contains SDK-owned field")
		}
	}
	event["source"] = c.opts.Source
	event["type"] = name
	if _, ok := event["id"]; !ok {
		id, err := sdkID()
		if err != nil {
			return nil, err
		}
		event["id"] = id
	}
	if _, ok := event["time"]; !ok {
		event["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if name == "session.start" {
		event["manifest"] = c.manifest
	}
	var entry map[string]any
	for _, raw := range sdkArray(c.manifest["events"]) {
		e := sdkObj(raw)
		if e["event"] == name {
			entry = e
			break
		}
	}
	if entry == nil {
		return nil, errors.New("boundary absent from manifest")
	}
	interceptable := sdkHas(entry["modes"], "intercept")
	caps := sdkObj(entry["capabilities"])
	if !interceptable {
		caps = map[string]any{"effects": []any{}}
	}
	caps, state, statePresent, err := resolveOptions(caps, options)
	if err != nil {
		return nil, err
	}
	if cfg.instructions != nil {
		if name != "context.compact.before" {
			return nil, errors.New("instructions template requires compaction before")
		}
		if event["instructions"] == nil {
			cfg.instructionsAbsent = true
			event["instructions"], err = sdkMap(cfg.instructions)
			if err != nil {
				return nil, err
			}
		}
	}
	rpcID, _ := event["id"].(string)
	params := map[string]any{"protocolVersion": "draft", "event": event, "capabilities": caps}
	if statePresent {
		params["state"] = state
	}
	request := map[string]any{"jsonrpc": "2.0", "id": rpcID, "method": "hooks/intercept", "params": params}
	if interceptable {
		parsed := ahp.ParseInterceptRequest(sdkJSON(request))
		if canonical.Validate("intercept-request", sdkJSON(request)) != nil || !parsed.OK {
			return nil, errors.New("invalid boundary input or initial state")
		}
		if err := compositionCapabilitiesPrepared(caps, event, true); err != nil {
			return nil, err
		}
		if err := compositionEventConstraints(event); err != nil {
			return nil, err
		}

	} else {
		if cfg.initial != nil || cfg.capabilities != nil || cfg.instructions != nil || cfg.elicitation != nil || len(cfg.targets) != 0 {
			return nil, errors.New("intercept options on observation-only boundary")
		}
		note := map[string]any{"jsonrpc": "2.0", "method": "hooks/observe", "params": map[string]any{"protocolVersion": "draft", "event": event}}
		if canonical.Validate("observe-notification", sdkJSON(note)) != nil || !ahp.ParseObserveNotification(sdkJSON(note)).OK {
			return nil, errors.New("invalid observation input")
		}
	}
	if candidate := sdkObj(state["candidate"]); candidate != nil {
		if name == "context.compact.before" {
			if _, ok := candidate["value"].(string); !ok {
				return nil, errors.New("compaction candidate summary must be text")
			}
		}
		if name == "user.elicitation.request" && canonical.Validate("mcp-elicitation#result", sdkJSON(candidate["value"])) != nil {
			return nil, errors.New("invalid initial elicitation candidate")
		}
	}
	version := ahp.ProtocolVersion("draft")
	if err := validateElicitationMetadata(event, cfg.elicitation); err != nil {
		return nil, err
	}
	ctx, err = cfg.bindSources(ctx, event)
	if err != nil {
		return nil, err
	}
	prepared, err := c.prepareBoundary(ctx, event, caps, cfg)
	if err != nil {
		return nil, err
	}
	if interceptable {
		initial := ahp.ParseInterceptRequest(sdkJSON(request))
		empty := ahp.ParseInterceptResponse(sdkJSON(map[string]any{"jsonrpc": "2.0", "id": rpcID, "result": map[string]any{"protocolVersion": "draft", "effects": []any{}}}))
		if _, err := composePrepared(initial.Value, empty.Value, prepared); err != nil {
			return nil, err
		}
	}
	ctx = context.WithValue(ctx, preparedContextKey{}, prepared)
	result := &Result{Response: ahp.InterceptResponseResult{ProtocolVersion: &version, Effects: []*ahp.Effect{}}}
	settled := state["permission"] == "deny" || state["flow"] == "stop"
	pending := []observationDelivery{}
	for _, backend := range c.backends {
		for i, sub := range backend.subscriptions {
			if !subscriptionMatches(sub, name) {
				continue
			}
			if sub["mode"] == "observe" || settled || ctx.Err() != nil {
				if ctx.Err() != nil {
					result.Interrupted = true
					settled = true
				}
				pending = append(pending, observationDelivery{backend: backend, sub: sub, index: i})
				continue
			}
			if !interceptable {
				continue
			}
			// Upload preparation has a separate receiver-configured deadline. The
			// interception budget starts after preparation, never before it.
			stage := "prepare"
			projected, deliveryErr := c.projectContent(ctx, event, sub, backend.id)
			if deliveryErr == nil {
				stage = "request"
				params["event"] = projected
				if statePresent {
					params["state"] = state
				} else {
					delete(params, "state")
				}
				parsed := ahp.ParseInterceptRequest(sdkJSON(request))
				if canonical.Validate("intercept-request", sdkJSON(request)) != nil || !parsed.OK {
					deliveryErr = errors.New("invalid projected request")
				} else {
					milliseconds, _ := sdkNumber(sub["timeoutMs"])
					timeout := time.Duration(milliseconds) * time.Millisecond
					callCtx, done := context.WithTimeout(ctx, timeout)
					stage = "delivery"
					raw, e := backend.transport.Exchange(callCtx, sdkJSON(request), false)
					if e == nil && callCtx.Err() != nil {
						e = callCtx.Err()
					}
					if e == nil {
						stage = "acceptance"
						response := ahp.ParseInterceptResponse(raw)
						if canonical.Validate("intercept-response", raw) != nil || !response.OK {
							e = interceptResponseFailure(raw, request["id"])
						} else {
							// Compose against the complete host event, not a subscriber's redacted
							// projection. Projection is a delivery view, not an accepted mutation.
							params["event"] = event
							full := ahp.ParseInterceptRequest(sdkJSON(request))
							accepted, composeErr := composePrepared(full.Value, response.Value, prepared)
							e = composeErr
							if e == nil && callCtx.Err() != nil {
								e = callCtx.Err()
							}
							if e == nil {
								prepared = accepted.prepared
								ctx = context.WithValue(ctx, preparedContextKey{}, prepared)
								result.EffectiveValues = accepted.EffectiveValues
								state, _ = sdkMap(accepted.State)
								statePresent = true
								if len(accepted.Event) > 0 {
									event, _ = sdkMap(accepted.Event)
								}
								result.Response.Effects = append(result.Response.Effects, accepted.Response.Effects...)
							}
						}
					}
					done()
					deliveryErr = e
				}
			}
			if ctx.Err() != nil {
				result.Interrupted = true
				settled = true
			}
			if deliveryErr != nil {
				closed := sub["failurePolicy"] == "fail-closed"
				result.Errors = append(result.Errors, DeliveryError{BackendID: backend.id, Subscription: i, Stage: stage, Code: deliveryCode(stage, deliveryErr), Err: deliveryErr, FailClosed: closed})
				if closed {
					state["permission"] = "deny"
					settled = true
				}
			}
			if state["permission"] == "deny" || state["flow"] == "stop" {
				settled = true
			}
		}
	}
	if ctx.Err() != nil {
		result.Interrupted = true
	}
	result.content = preparedContent(event, prepared)
	result.prepared = prepared
	result.Snapshot = prepared.snapshot
	result.Event = sdkJSON(event)
	if tool := sdkObj(event["tool"]); tool != nil {
		result.EffectiveInput = sdkJSON(tool["input"])
	}
	if err = json.Unmarshal(sdkJSON(state), &result.State); err != nil {
		return nil, err
	}
	result.Permission = result.State.Permission
	result.Diagnostics = append([]DeliveryError(nil), result.Errors...)
	if result.EffectiveValues == nil {
		values, e := prepared.values(event)
		if e != nil {
			return result, e
		}
		result.EffectiveValues = map[string]json.RawMessage{}
		for k, v := range values {
			result.EffectiveValues[k] = sdkJSON(v)
		}
	}
	result.Snapshot = prepared.snapshot
	result.Observations = c.scheduleObservations(ctx, event, pending, prepared)
	result.content = preparedContent(event, prepared)
	// Observer preparation can make original request bytes available, but a
	// failed observer must never reopen settlement or publish an invalid snapshot.
	if prepared.materializeElicitation(event) == nil {
		result.Snapshot = prepared.snapshot
	}
	result.Diagnostics = append(append([]DeliveryError(nil), result.Errors...), result.Observations.errors...)
	if ctx.Err() != nil {
		result.Interrupted = true
	}
	if result.Interrupted {
		return result, ctx.Err()
	}
	return result, nil
}
func subscriptionMatches(sub map[string]any, name string) bool {
	for _, s := range sdkArray(sub["events"]) {
		if sdkMatch(s, name) {
			return true
		}
	}
	return false
}
