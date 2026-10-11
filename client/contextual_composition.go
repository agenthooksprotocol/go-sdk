package client

import (
	"encoding/json"
	"errors"
	"fmt"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

func stageContextualComposition(request ahp.InterceptRequest, response ahp.ContextualResponse, baseResponse ahp.InterceptResponseResult, prepared *preparedBoundary) (*composition, error) {
	event := request.Params.Event
	kind, eventID, err := eventIdentity(event)
	if err != nil {
		return nil, err
	}
	if !compositionEqual(compositionObject(sdkJSON(request))["id"], eventID) {
		return nil, errors.New("intercept correlation mismatch")
	}
	effects, err := contextualEffects(response)
	if err != nil {
		return nil, err
	}
	eventView, err := sdkMap(event)
	if err != nil {
		return nil, err
	}
	caps, err := sdkMap(request.Params.Capabilities)
	if err != nil {
		return nil, err
	}
	state := request.Params.State.Value
	if !request.Params.State.Present {
		state = ahp.InterceptRequestParamsState{Permission: "none"}
	}
	stateView, err := sdkMap(state)
	if err != nil {
		return nil, err
	}
	if err := compositionEventConstraints(eventView); err != nil {
		return nil, err
	}
	if err := compositionCapabilitiesPrepared(caps, eventView, prepared != nil); err != nil {
		return nil, err
	}
	for _, effect := range effects {
		wire, err := sdkMap(effect.wire)
		if err != nil {
			return nil, err
		}
		if err := compositionAdmit(wire, caps, stateView, kind); err != nil {
			return nil, err
		}
	}
	var staged *preparedBoundary
	var declared *declaredContracts
	if prepared != nil {
		staged = prepared.clone()
		declared = staged.declared
		// Attachment materialization is an owner-layer operation. Re-import its
		// canonical output as a generated Event; the composition below stays typed.
		if err := staged.materializeElicitation(eventView); err != nil {
			return nil, err
		}
		converted, err := convertWire[ahp.Event](eventView)
		if err != nil {
			return nil, err
		}
		event = &converted
		request.Params.Event = event
	}
	target := compositionTargets[kind]
	current, err := contextualTarget(event, target)
	if err != nil && target != "" {
		return nil, err
	}
	if declared != nil {
		for key := range declared.targets {
			if key != target || current == nil {
				return nil, errors.New("declared target unavailable")
			}
		}
		if target != "" {
			if err := declared.validateTarget(target, current); err != nil {
				return nil, err
			}
		}
		if err := declared.validateCandidate(stateView); err != nil {
			return nil, err
		}
	}
	candidate, err := stateCandidate(kind, state)
	if err != nil {
		return nil, err
	}
	if candidate != nil {
		if kind == "user.elicitation.request" {
			if staged == nil || staged.snapshot == nil {
				return nil, errors.New("elicitation candidate requires original snapshot")
			}
			if err := validateElicitationAnswer(eventView, staged.snapshot, compositionObject(sdkJSON(candidate))); err != nil {
				return nil, err
			}
		}
	}
	initial := sdkJSON(current)
	for _, effect := range effects {
		if effect.kind != "modify" {
			continue
		}
		if staged == nil && effect.target != "input" {
			return nil, compositionUnsupportedTarget(kind, effect.target)
		}
		value := effect.value
		if effect.merge {
			value, err = mergeContextualValue(current, effect.value)
			if err != nil {
				return nil, err
			}
		}
		if err := declared.validateTarget(effect.target, value); err != nil {
			return nil, err
		}
		if staged != nil {
			if path, list := inlineTargetPath(eventView, effect.target); list && effect.target != "content" {
				if err := staged.validateInlineAttachments(eventView, path, compositionValue(value)); err != nil {
					return nil, err
				}
			}
		}
		if err := setContextualTarget(event, effect.target, value, staged); err != nil {
			return nil, err
		}
		current = value
		eventView, err = sdkMap(event)
		if err != nil {
			return nil, err
		}
	}
	initialValue, _ := contractJSON(initial)
	nextValue, _ := contractJSON(sdkJSON(current))
	if !compositionEqual(initialValue, nextValue) {
		state.Candidate = ahp.Null[ahp.InterceptRequestParamsStateCandidateValue]()
		if state.Permission == "allow" {
			state.Permission = "none"
		}
	}
	for _, effect := range effects {
		switch effect.kind {
		case "deny":
			state.Permission = "deny"
		case "ask":
			if state.Permission != "deny" {
				state.Permission = "ask"
			}
		case "allow":
			if state.Permission != "deny" && state.Permission != "ask" {
				state.Permission = "allow"
			}
		case "return":
			if declared != nil && declared.result != nil {
				if err := declared.result(sdkJSON(effect.value)); err != nil {
					return nil, err
				}
			}
			if kind == "user.elicitation.request" {
				if staged == nil || staged.snapshot == nil {
					return nil, errors.New("elicitation snapshot unavailable")
				}
				if err := validateElicitationAnswer(eventView, staged.snapshot, compositionObject(sdkJSON(effect.value))); err != nil {
					return nil, err
				}
			}
			if err := setStateCandidate(&state, kind, effect.value); err != nil {
				return nil, err
			}
		case "flow":
			switch flow := effect.wire.(type) {
			case *ahp.StopFlowEffect:
				state.Flow = ahp.Some(ahp.InterceptRequestParamsStateFlow("stop"))
			case *ahp.ContinueFlowEffect:
				if flow.Instruction.Present {
					state.Instructions = ahp.Some(append(state.Instructions.Value, flow.Instruction.Value))
				}
				if !state.Flow.Present || state.Flow.Value != "stop" {
					state.Flow = ahp.Some(ahp.InterceptRequestParamsStateFlow("continue"))
				}
			}
		case "inject":
			state.Injections = ahp.Some(append(state.Injections.Value, effect.wire.(*ahp.InjectEffect)))
		}
	}
	if state.Permission == "deny" || (state.Flow.Present && state.Flow.Value == "stop") {
		state.Candidate = ahp.Null[ahp.InterceptRequestParamsStateCandidateValue]()
	}
	if err := declared.validateHost(eventView); err != nil {
		return nil, err
	}
	stateView, err = sdkMap(state)
	if err != nil {
		return nil, err
	}
	if err := declared.validateCandidate(stateView); err != nil {
		return nil, err
	}
	request.Params.State = ahp.Some(state)
	if err := canonical.Validate("intercept-request", sdkJSON(request)); err != nil {
		return nil, err
	}
	if _, err := stateCandidate(kind, state); err != nil {
		return nil, err
	}
	out := &composition{Event: sdkJSON(event), State: state, Response: baseResponse, prepared: staged}
	if tool := eventTool(event); tool != nil {
		out.EffectiveInput = sdkJSON(tool.Input)
	}
	return out, nil
}

// compositionValue is a serialization bridge into existing projection/owner
// indexing, not a known-payload interpreter. Typed composition never edits it.
func compositionValue(value any) any { decoded, _ := contractJSON(sdkJSON(value)); return decoded }

func contextualTarget(event *ahp.Event, target string) (any, error) {
	switch target {
	case "":
		return nil, nil
	case "input":
		tool := eventTool(event)
		if tool == nil {
			return nil, errors.New("tool input unavailable")
		}
		return tool.Input, nil
	case "instructions", "summary":
		return eventTextParts(event)
	case "workspace":
		if event.WorkspaceChangeBeforeEvent.Present {
			return event.WorkspaceChangeBeforeEvent.Value.Workspace.Change, nil
		}
	case "content":
		if event.UserElicitationResultEvent.Present {
			descriptor := event.UserElicitationResultEvent.Value.Elicitation.Result
			// Metadata-only results have no mutable answer value. Neutral
			// delivery remains valid; writes still require eventElicitResult.
			if !descriptor.Present || descriptor.Value == nil || !descriptor.Value.TextBodyPart.Present || descriptor.Value.TextBodyPart.Value == nil {
				return nil, nil
			}
			result, err := eventElicitResult(event)
			if err != nil {
				return nil, err
			}
			return result.Content.Value, nil
		}
		return eventMessages(event)
	case "prompt", "request", "response", "output":
		return eventMessages(event)
	}
	return nil, errors.New("contextual target unavailable")
}

func eventElicitResult(event *ahp.Event) (*ahp.McpElicitationElicitResult, error) {
	if !event.UserElicitationResultEvent.Present {
		return nil, errors.New("elicitation result unavailable")
	}
	descriptor := event.UserElicitationResultEvent.Value.Elicitation.Result
	if !descriptor.Present || descriptor.Value == nil || !descriptor.Value.TextBodyPart.Present || descriptor.Value.TextBodyPart.Value == nil {
		return nil, errors.New("elicitation result body unavailable")
	}
	var result ahp.McpElicitationElicitResult
	if err := json.Unmarshal([]byte(descriptor.Value.TextBodyPart.Value.Text), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func setContextualTarget(event *ahp.Event, target string, value any, prepared *preparedBoundary) error {
	switch target {
	case "input":
		tool := eventTool(event)
		if tool == nil {
			return errors.New("input unavailable")
		}
		decoded, err := convertWire[ahp.ExecutionEventToolInput](value)
		if err != nil {
			return err
		}
		tool.Input = decoded
		return nil
	case "instructions", "summary":
		parts, ok := value.(*ahp.TextParts)
		if !ok {
			return errors.New("expected text parts")
		}
		return setEventTextParts(event, parts)
	case "workspace":
		workspace, ok := value.(*ahp.WorkspaceChange)
		if !ok || !event.WorkspaceChangeBeforeEvent.Present {
			return errors.New("expected workspace change")
		}
		event.WorkspaceChangeBeforeEvent.Value.Workspace.Change = workspace
		return nil
	case "content":
		if event.UserElicitationResultEvent.Present {
			answers, ok := value.(*ahp.FormAnswers)
			if !ok {
				return errors.New("expected form answers")
			}
			wrapper, err := eventElicitResult(event)
			if err != nil {
				return err
			}
			wrapper.Content = ahp.Some(answers)
			if prepared == nil || prepared.snapshot == nil {
				return errors.New("elicitation snapshot unavailable")
			}
			view, _ := sdkMap(event)
			if err := validateElicitationAnswer(view, prepared.snapshot, compositionObject(sdkJSON(wrapper))); err != nil {
				return err
			}
			part := event.UserElicitationResultEvent.Value.Elicitation.Result.Value
			body := *part.TextBodyPart.Value
			body.Text = string(sdkJSON(wrapper))
			copied := *part
			copied.TextBodyPart = ahp.Some(&body)
			event.UserElicitationResultEvent.Value.Elicitation.Result = ahp.Some(&copied)
			return nil
		}
		fallthrough
	case "prompt", "request", "response", "output":
		messages, ok := value.(*ahp.CanonicalMessages)
		if !ok {
			return errors.New("expected canonical messages")
		}
		return setEventMessages(event, messages)
	}
	return errors.New("unsupported contextual target")
}

func mergeContextualValue(base, patch any) (any, error) {
	switch patch := patch.(type) {
	case *ahp.CanonicalMessages:
		old, ok := base.(*ahp.CanonicalMessages)
		if !ok || old == nil || patch == nil {
			return nil, errors.New("message target unavailable")
		}
		merged := append(append(ahp.CanonicalMessages{}, (*old)...), (*patch)...)
		return &merged, nil
	case *ahp.TextParts:
		old, ok := base.(*ahp.TextParts)
		if !ok || old == nil || patch == nil {
			return nil, errors.New("text target unavailable")
		}
		merged := append(append(ahp.TextParts{}, (*old)...), (*patch)...)
		return &merged, nil
	case *ahp.FormAnswers:
		old, ok := base.(*ahp.FormAnswers)
		if !ok || old == nil || patch == nil {
			return nil, errors.New("form target unavailable")
		}
		merged := ahp.FormAnswers{}
		for k, v := range *old {
			merged[k] = v
		}
		for k, v := range *patch {
			merged[k] = v
		}
		return &merged, nil
	case *ahp.WorkspaceChange:
		merged, err := mergeOpaqueObjects(sdkJSON(base), sdkJSON(patch))
		if err != nil {
			return nil, err
		}
		decoded, err := convertWire[ahp.WorkspaceChange](merged)
		return &decoded, err
	case ahp.ToolBeforeModifyEffectValue, ahp.ToolPermissionRequestModifyEffectValue:
		merged, err := mergeOpaqueObjects(sdkJSON(base), sdkJSON(patch))
		if err != nil {
			return nil, err
		}
		return convertWire[ahp.ExecutionEventToolInput](merged)
	default:
		return nil, fmt.Errorf("unsupported contextual merge")
	}
}

// Only caller-defined object values use temporary JSON merge. Members remain
// RawMessage, so omitted/null/nested replacement and exact integers are lossless.
func mergeOpaqueObjects(base, patch []byte) (map[string]json.RawMessage, error) {
	var original, update map[string]json.RawMessage
	if json.Unmarshal(base, &original) != nil || original == nil || json.Unmarshal(patch, &update) != nil || update == nil {
		return nil, errors.New("merge requires objects")
	}
	for key, value := range update {
		original[key] = value
	}
	return original, nil
}
