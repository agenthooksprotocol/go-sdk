package interop

import (
	"encoding/json"
	"fmt"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/capability"
	hooks "github.com/agenthooksprotocol/go-sdk/client"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
	"math/big"
)

// fixtureHost keeps fixture authority in closed generated declarations. Dynamic
// occurrence grants (including opaque extensions) are ALWAYS separately passed
// through WithCapabilities; they can narrow, never expand, these declarations.
// Broad event-safe controls let no-grant occurrences retain an intercept boundary.
// This helper is NOT used to admit discovered catalogue manifests.
func fixtureHost(events []any) (capability.Host, error) {
	var host capability.Host
	for _, raw := range events {
		entry := obj(raw)
		name := str(entry["event"])
		observe, intercept := has(array(entry["modes"]), "observe"), has(array(entry["modes"]), "intercept")
		caps := obj(entry["capabilities"])
		flow := obj(caps["flow"])
		numbers := map[string]uint64{}
		for _, key := range []string{"maxContinuations", "remainingContinuations", "continuationCount"} {
			if raw, present := flow[key]; present {
				number, err := fixtureUint(raw)
				if err != nil {
					return host, fmt.Errorf("fixture %s flow %s: %w", name, key, err)
				}
				numbers[key] = number
			}
		}
		stop := capability.Stop()
		if maximum, ok := numbers["maxContinuations"]; ok {
			stop = stop.WithMaxContinuations(maximum)
		}
		var continuation capability.Flow = stop
		if has(array(flow["operations"]), "continue") {
			remaining, count := uint64(0), uint64(0)
			// Closed continuation builders require explicit counters. Absent counters
			// are not silently invented, even though wire capabilities permit them.
			for key, destination := range map[string]*uint64{"remainingContinuations": &remaining, "continuationCount": &count} {
				raw, present := flow[key]
				if !present {
					return host, fmt.Errorf("fixture %s continuation lacks %s for typed declaration", name, key)
				}
				value, err := fixtureUint(raw)
				if err != nil {
					return host, fmt.Errorf("fixture %s continuation has inexact %s", name, key)
				}
				*destination = value
			}
			if has(array(flow["operations"]), "stop") {
				grant := capability.ContinueAndStop(remaining, count)
				if maximum, ok := numbers["maxContinuations"]; ok {
					grant = grant.WithMaxContinuations(maximum)
				}
				continuation = grant
			} else {
				grant := capability.Continue(remaining, count)
				if maximum, ok := numbers["maxContinuations"]; ok {
					grant = grant.WithMaxContinuations(maximum)
				}
				continuation = grant
			}
		}
		var injection capability.Injection
		for _, delivery := range array(obj(obj(caps["inject"])["context"])["deliverAt"]) {
			switch delivery {
			case "now":
				injection = injection.WithNow()
			case "next_turn":
				injection = injection.WithNextTurn()
			}
		}
		switch name {
		case "config.change.after":
			if intercept {
				return host, fmt.Errorf("fixture event %s is observation-only", name)
			}
			if observe {
				host.ConfigChangeAfter = capability.Observe{}
			}
		case "config.change.before":
			if !intercept {
				host.ConfigChangeBefore = capability.Observe{}
				break
			}
			host.ConfigChangeBefore = capability.ConfigChangeBefore{
				Deny:            true,
				Message:         true,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "context.compact.after":
			if !intercept {
				host.ContextCompactAfter = capability.Observe{}
				break
			}
			host.ContextCompactAfter = capability.ContextCompactAfter{
				Message:         true,
				ModifySummary:   capability.ReplaceAndMerge(),
				InjectContext:   injection,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "context.compact.before":
			if !intercept {
				host.ContextCompactBefore = capability.Observe{}
				break
			}
			host.ContextCompactBefore = capability.ContextCompactBefore{
				Deny:               true,
				Message:            true,
				ReturnResult:       true,
				ModifyInstructions: capability.ReplaceAndMerge(),
				InjectContext:      injection,
				ElicitationForm:    true,
				ElicitationURL:     true,
				Observe:            observe,
			}
		case "file.changed":
			if intercept {
				return host, fmt.Errorf("fixture event %s is observation-only", name)
			}
			if observe {
				host.FileChanged = capability.Observe{}
			}
		case "hook.failure":
			if intercept {
				return host, fmt.Errorf("fixture event %s is observation-only", name)
			}
			if observe {
				host.HookFailure = capability.Observe{}
			}
		case "model.error":
			if intercept {
				return host, fmt.Errorf("fixture event %s is observation-only", name)
			}
			if observe {
				host.ModelError = capability.Observe{}
			}
		case "model.request.before":
			if !intercept {
				host.ModelRequestBefore = capability.Observe{}
				break
			}
			host.ModelRequestBefore = capability.ModelRequestBefore{
				Deny:            true,
				Message:         true,
				ReturnResult:    true,
				ModifyRequest:   capability.ReplaceAndMerge(),
				Flow:            stop,
				InjectContext:   injection,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "model.response.after":
			if !intercept {
				host.ModelResponseAfter = capability.Observe{}
				break
			}
			host.ModelResponseAfter = capability.ModelResponseAfter{
				Message:         true,
				ModifyResponse:  capability.ReplaceAndMerge(),
				Flow:            stop,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "model.switch.after":
			if intercept {
				return host, fmt.Errorf("fixture event %s is observation-only", name)
			}
			if observe {
				host.ModelSwitchAfter = capability.Observe{}
			}
		case "model.switch.before":
			if !intercept {
				host.ModelSwitchBefore = capability.Observe{}
				break
			}
			host.ModelSwitchBefore = capability.ModelSwitchBefore{
				Deny:            true,
				Message:         true,
				Flow:            stop,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "session.end":
			if intercept {
				return host, fmt.Errorf("fixture event %s is observation-only", name)
			}
			if observe {
				host.SessionEnd = capability.Observe{}
			}
		case "session.start":
			if !intercept {
				host.SessionStart = capability.Observe{}
				break
			}
			host.SessionStart = capability.SessionStart{
				Message:         true,
				InjectContext:   injection,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "task.change.after":
			if intercept {
				return host, fmt.Errorf("fixture event %s is observation-only", name)
			}
			if observe {
				host.TaskChangeAfter = capability.Observe{}
			}
		case "task.change.before":
			if !intercept {
				host.TaskChangeBefore = capability.Observe{}
				break
			}
			host.TaskChangeBefore = capability.TaskChangeBefore{
				Deny:            true,
				Message:         true,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "tool.after":
			if !intercept {
				host.ToolAfter = capability.Observe{}
				break
			}
			host.ToolAfter = capability.ToolAfter{
				Message:         true,
				ModifyOutput:    capability.ReplaceAndMerge(),
				Flow:            continuation,
				InjectContext:   injection,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "tool.batch.after":
			if !intercept {
				host.ToolBatchAfter = capability.Observe{}
				break
			}
			host.ToolBatchAfter = capability.ToolBatchAfter{
				Message:         true,
				Flow:            stop,
				InjectContext:   injection,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "tool.before":
			if !intercept {
				host.ToolBefore = capability.Observe{}
				break
			}
			host.ToolBefore = capability.ToolBefore{
				Allow:           true,
				Ask:             true,
				Deny:            true,
				Message:         true,
				ReturnResult:    true,
				ModifyInput:     capability.ReplaceAndMerge(),
				Flow:            stop,
				InjectContext:   injection,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "tool.permission.request":
			if !intercept {
				host.ToolPermissionRequest = capability.Observe{}
				break
			}
			host.ToolPermissionRequest = capability.ToolPermissionRequest{
				Allow:           true,
				Deny:            true,
				Message:         true,
				ModifyInput:     capability.ReplaceAndMerge(),
				Flow:            stop,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "tool.permission.resolved":
			if intercept {
				return host, fmt.Errorf("fixture event %s is observation-only", name)
			}
			if observe {
				host.ToolPermissionResolved = capability.Observe{}
			}
		case "tool.progress":
			if intercept {
				return host, fmt.Errorf("fixture event %s is observation-only", name)
			}
			if observe {
				host.ToolProgress = capability.Observe{}
			}
		case "turn.end":
			if intercept {
				return host, fmt.Errorf("fixture event %s is observation-only", name)
			}
			if observe {
				host.TurnEnd = capability.Observe{}
			}
		case "turn.finish.before":
			if !intercept {
				host.TurnFinishBefore = capability.Observe{}
				break
			}
			host.TurnFinishBefore = capability.TurnFinishBefore{
				Message:         true,
				ModifyResponse:  capability.ReplaceAndMerge(),
				Flow:            continuation,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "turn.progress":
			if intercept {
				return host, fmt.Errorf("fixture event %s is observation-only", name)
			}
			if observe {
				host.TurnProgress = capability.Observe{}
			}
		case "turn.start":
			if !intercept {
				host.TurnStart = capability.Observe{}
				break
			}
			host.TurnStart = capability.TurnStart{
				Deny:            true,
				Message:         true,
				ModifyPrompt:    capability.ReplaceAndMerge(),
				Flow:            stop,
				InjectContext:   injection,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "user.attention":
			if intercept {
				return host, fmt.Errorf("fixture event %s is observation-only", name)
			}
			if observe {
				host.UserAttention = capability.Observe{}
			}
		case "user.elicitation.request":
			if !intercept {
				host.UserElicitationRequest = capability.Observe{}
				break
			}
			host.UserElicitationRequest = capability.UserElicitationRequest{
				Deny:            true,
				Message:         true,
				ReturnResult:    true,
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "user.elicitation.result":
			if !intercept {
				host.UserElicitationResult = capability.Observe{}
				break
			}
			host.UserElicitationResult = capability.UserElicitationResult{
				Message:         true,
				ModifyContent:   capability.ReplaceAndMerge(),
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "user.message.inbound":
			if !intercept {
				host.UserMessageInbound = capability.Observe{}
				break
			}
			host.UserMessageInbound = capability.UserMessageInbound{
				Deny:            true,
				Message:         true,
				ModifyPrompt:    capability.ReplaceAndMerge(),
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "user.message.outbound":
			if !intercept {
				host.UserMessageOutbound = capability.Observe{}
				break
			}
			host.UserMessageOutbound = capability.UserMessageOutbound{
				Deny:            true,
				Message:         true,
				ModifyContent:   capability.ReplaceAndMerge(),
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		case "workspace.change.after":
			if intercept {
				return host, fmt.Errorf("fixture event %s is observation-only", name)
			}
			if observe {
				host.WorkspaceChangeAfter = capability.Observe{}
			}
		case "workspace.change.before":
			if !intercept {
				host.WorkspaceChangeBefore = capability.Observe{}
				break
			}
			host.WorkspaceChangeBefore = capability.WorkspaceChangeBefore{
				Deny:            true,
				Message:         true,
				ModifyWorkspace: capability.ReplaceAndMerge(),
				ElicitationForm: true,
				ElicitationURL:  true,
				Observe:         observe,
			}
		default:
			return host, fmt.Errorf("fixture event %s has no typed host declaration", name)
		}
	}
	return host, nil
}

// fixtureManifestMetadata admits canonical external fixture metadata, but never
// transfers its event authority to a public constructor.
func validateFixtureManifest(manifest Object) error {
	return canonical.Validate("capabilities-response", jsonBytes(Object{"jsonrpc": "2.0", "id": "fixture-admission", "result": Object{"protocolVersion": "draft", "manifest": manifest}}))
}

func fixtureManifestMetadata(manifest Object) (*hooks.ManifestMetadata, error) {
	if err := validateFixtureManifest(manifest); err != nil {
		return nil, err
	}
	var value ahp.StaticCapabilityManifest
	if err := json.Unmarshal(jsonBytes(manifest), &value); err != nil {
		return nil, fmt.Errorf("invalid fixture manifest: %w", err)
	}
	return &hooks.ManifestMetadata{
		Transports:                ahp.Optional[[]ahp.StaticCapabilityManifestTransportsItem]{Present: true, Value: value.Transports},
		Authentication:            ahp.Optional[[]ahp.StaticCapabilityManifestAuthenticationItem]{Present: true, Value: value.Authentication},
		Gaps:                      ahp.Optional[[]ahp.StaticCapabilityManifestGapsItem]{Present: true, Value: value.Gaps},
		ToolPaths:                 ahp.Optional[[]string]{Present: true, Value: value.ToolPaths},
		ContentCategories:         ahp.Optional[[]string]{Present: true, Value: value.ContentCategories},
		CorrelationIdentityFields: ahp.Optional[[]string]{Present: true, Value: value.CorrelationIdentityFields},
		Limits:                    ahp.Optional[ahp.StaticCapabilityManifestLimits]{Present: true, Value: value.Limits},
		ManagedPolicy:             ahp.Optional[ahp.StaticCapabilityManifestManagedPolicy]{Present: true, Value: value.ManagedPolicy},
		AdditionalProperties:      value.AdditionalProperties,
	}, nil
}

func fixtureOccurrenceCapabilities(params Object) (hooks.InterceptOption, error) {
	parsed := ahp.ParseCapabilities(jsonBytes(params["capabilities"]))
	if !parsed.OK {
		return nil, fmt.Errorf("invalid fixture occurrence capabilities: %v", parsed.Diagnostics)
	}
	return hooks.WithCapabilities(parsed.Value), nil
}

// The closed builders use uint64. Never round, overflow, or replace an absent
// continuation counter with zero when importing fixture occurrence grants.
func fixtureUint(value any) (uint64, error) {
	number, ok := new(big.Rat).SetString(string(jsonBytes(value)))
	if !ok || !number.IsInt() || !number.Num().IsUint64() {
		return 0, fmt.Errorf("not an exact uint64")
	}
	return number.Num().Uint64(), nil
}
