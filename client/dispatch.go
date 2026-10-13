package client

import (
	"context"
	"encoding/json"
	"errors"
	ahp "github.com/agenthooksprotocol/go-sdk"
	eventtype "github.com/agenthooksprotocol/go-sdk/event"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
	"github.com/agenthooksprotocol/go-sdk/internal/inputsources"
	"github.com/agenthooksprotocol/go-sdk/internal/ownedcontent"
	"reflect"
	"time"
)

// Dispatch is the advanced canonical boundary entry point. Use generated event
// constants for name. Input uses canonical host fields (including nested
// call/tool envelopes), not flattened
// generated input fields. Source, type, and manifest remain SDK-owned and must
// be absent. An optional harness must match the configured identity. Prefer
// named methods and generated inputs for ordinary callers.
func (c *Hooks) Dispatch(ctx context.Context, name eventtype.Type, input any, options ...InterceptOption) (*Result, error) {
	return c.intercept(ctx, string(name), input, options...)
}

func (c *Hooks) intercept(ctx context.Context, name string, input any, options ...InterceptOption) (*Result, error) {
	result, err := c.dispatch(ctx, name, input, options...)
	if result == nil && err != nil {
		return nil, &AdmissionError{Kind: "input", Err: err}
	}
	return result, err
}

func (c *Hooks) dispatch(ctx context.Context, name string, input any, options ...InterceptOption) (out *Result, dispatchErr error) {
	// Only generated nominal inputs and the internal generic carrier can bind
	// owned sources. Host-defined source-provider methods confer no authority.
	var bindings []InterceptOption
	for path, source := range inputsources.Extract(input) {
		bindings = append(bindings, withHostContentSource(path, source))
	}
	options = append(bindings, options...)
	cfg := contentSourceConfig(options)
	admitted := false
	var prepared *preparedBoundary
	defer func() {
		if out != nil && dispatchErr == nil {
			out.retainAttachments(cfg, ctx, prepared, c.opts.MaxContentBytes)
		}
		cfg.closeSources()
		if prepared != nil {
			for source := range prepared.owned {
				if !cfg.transferredSources[source] {
					_ = ownedcontent.Retire(source)
				}
			}
		}
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
	// Replace local pending descriptors before validation. Only generated schema-owned
	// source slots are accepted; these private placeholders never reach a receiver.
	for path := range cfg.sources {
		item := preparedAt(event, path)
		if item != nil && (sdkObj(item["body"])["ref"] == "ahp:owned:pending" || (cfg.hostSources[path] && item["body"] != nil)) {
			delete(item, "body")
			item["gap"] = map[string]any{"reason": "unavailable"}
		}
	}
	for _, key := range []string{"source", "type", "manifest"} {
		if _, ok := event[key]; ok {
			return nil, errors.New("boundary input contains SDK-owned field")
		}
	}
	harness, err := sdkMap(c.opts.Harness)
	if err != nil {
		return nil, errors.New("invalid configured harness identity")
	}
	if supplied, ok := event["harness"]; ok && !reflect.DeepEqual(supplied, harness) {
		return nil, errors.New("boundary harness conflicts with configured identity")
	}
	event["harness"] = harness
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
			var instruction map[string]any
			instruction, err = sdkMap(cfg.instructions)
			event["instructions"] = []any{instruction}
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
		if cfg.initial != nil || cfg.capabilities != nil || cfg.instructions != nil || cfg.elicitation != nil || len(cfg.targets) != 0 || (cfg.declared != nil && (len(cfg.declared.targets) != 0 || cfg.declared.result != nil || cfg.declared.provenance != nil)) {
			return nil, errors.New("intercept options on observation-only boundary")
		}
		note := map[string]any{"jsonrpc": "2.0", "method": "hooks/observe", "params": map[string]any{"protocolVersion": "draft", "event": event}}
		if canonical.Validate("observe-notification", sdkJSON(note)) != nil || !ahp.ParseObserveNotification(sdkJSON(note)).OK {
			return nil, errors.New("invalid observation input")
		}
	}
	if candidate := sdkObj(state["candidate"]); candidate != nil {
		if name == "context.compact.before" || name == "model.request.before" {
			if err := validateSuppliedValue(name, candidate["value"]); err != nil {
				return nil, err
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
	if err := cfg.declared.validateDeclaration(name); err != nil {
		return nil, err
	}
	if err := cfg.declared.validateHost(event); err != nil {
		return nil, err
	}
	ctx, err = cfg.bindSources(ctx, event)
	if err != nil {
		return nil, err
	}
	prepared, err = c.prepareBoundary(ctx, event, caps, cfg)
	if err != nil {
		return nil, err
	}
	for _, source := range cfg.sources {
		prepared.owned[source] = true
	}
	budget, _ := ctx.Value(contentSourceBudgetKey{}).(*contentSourceBudget)
	if err := budget.reconcile(prepared.sources, prepared.limit); err != nil {
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
	uploads := c.planUploads(ctx, event, prepared)
	ctx = context.WithValue(ctx, uploadPlanContextKey{}, uploads)
	result := &Result{AcceptedResponses: []ahp.ContextualResponse{}, response: ahp.InterceptResponseResult{ProtocolVersion: &version, Effects: ahp.Some([]*ahp.Effect{})}}
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
			receiver := uploadReceiver{backend.id, i}
			deliveryCtx := context.WithValue(ctx, uploadReceiverContextKey{}, receiver)
			deliveryErr := uploads.failure(receiver)
			var projected map[string]any
			if deliveryErr == nil {
				projected, deliveryErr = c.projectContent(deliveryCtx, event, sub, backend.id)
			}
			var receiverState map[string]any
			if deliveryErr == nil && statePresent {
				receiverState, deliveryErr = c.projectReceiverState(deliveryCtx, event, state, sub, backend.id, prepared)
			}

			if deliveryErr == nil {
				stage = "request"
				params["event"] = projected
				deliveryCaps := contentClone(caps).(map[string]any)
				for target, rawGrant := range sdkObj(deliveryCaps["modify"]) {
					if path, ok := inlineTargetPath(event, target); ok && inlineHasHiddenText(inlineAt(projected, path)) {
						grant := sdkObj(rawGrant)
						grant["replace"] = false
					}
				}
				params["capabilities"] = deliveryCaps
				if statePresent {

					params["state"] = receiverState
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
						contextual := eventtype.ResponseForRequest(eventtype.Type(name), raw)
						if canonical.Validate("intercept-response", raw) != nil || !response.OK || !contextual.OK {
							e = interceptResponseFailure(raw, request["id"])
						} else {
							// Compose against the complete host event, not a subscriber's redacted
							// projection. Projection is a delivery view, not an accepted mutation.
							params["event"] = event
							params["capabilities"] = caps
							if statePresent {
								params["state"] = state
							}
							full := ahp.ParseInterceptRequest(sdkJSON(request))
							authorized, authErr := c.authorizeInlineEffects(callCtx, event, projected, sub, backend.id, response.Value)
							if authErr != nil {
								e = authErr
							} else {
								accepted, composeErr := composePrepared(full.Value, authorized, prepared)
								e = composeErr
								if e == nil && callCtx.Err() != nil {
									e = callCtx.Err()
								}
								if e == nil {
									e = budget.reconcile(accepted.prepared.sources, accepted.prepared.limit)
								}
								if e == nil {
									prepared = accepted.prepared
									ctx = context.WithValue(ctx, preparedContextKey{}, prepared)
									state, _ = sdkMap(accepted.State)
									statePresent = true
									if len(accepted.Event) > 0 {
										event, _ = sdkMap(accepted.Event)
									}
									result.response.Effects.Value = append(result.response.Effects.Value, accepted.Response.Effects.Value...)
									result.AcceptedResponses = append(result.AcceptedResponses, contextual.Value)
								}
								prepared.releaseUnused(budget)
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
				result.errors = append(result.errors, DeliveryError{BackendID: backend.id, Subscription: i, Stage: stage, Code: deliveryCode(stage, deliveryErr), Err: deliveryErr, FailClosed: closed})
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
	result.Snapshot = prepared.snapshot
	result.eventWire = sdkJSON(event)
	if err = json.Unmarshal(sdkJSON(state), &result.state); err != nil {
		return nil, err
	}
	result.Diagnostics = append([]DeliveryError(nil), result.errors...)
	if err := result.decodeSettlement(name); err != nil {
		return result, err
	}
	result.Permission = result.state.Permission
	result.Diagnostics = append([]DeliveryError(nil), result.errors...)
	if _, err := prepared.values(event); err != nil {
		return result, err
	}

	result.Snapshot = prepared.snapshot
	observationErrors := c.scheduleObservations(ctx, event, pending, prepared)
	// Observer preparation can make original request bytes available, but a
	// failed observer must never reopen settlement or publish an invalid snapshot.
	if prepared.materializeElicitation(event) == nil {
		result.Snapshot = prepared.snapshot
	}
	result.Diagnostics = append(append([]DeliveryError(nil), result.errors...), observationErrors...)
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
