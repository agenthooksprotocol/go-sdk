package client

import (
	"encoding/json"
	"errors"
	ahp "github.com/agenthooksprotocol/go-sdk"
)

func eventIdentity(event *ahp.Event) (string, string, error) {
	if event == nil {
		return "", "", errors.New("missing event")
	}
	if event.ToolBeforeEvent.Present && event.ToolBeforeEvent.Value != nil {
		value := event.ToolBeforeEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ToolAfterEvent.Present && event.ToolAfterEvent.Value != nil {
		value := event.ToolAfterEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.SessionStartEvent.Present && event.SessionStartEvent.Value != nil {
		value := event.SessionStartEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.SessionEndEvent.Present && event.SessionEndEvent.Value != nil {
		value := event.SessionEndEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ConfigChangeBeforeEvent.Present && event.ConfigChangeBeforeEvent.Value != nil {
		value := event.ConfigChangeBeforeEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ConfigChangeAfterEvent.Present && event.ConfigChangeAfterEvent.Value != nil {
		value := event.ConfigChangeAfterEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.TurnStartEvent.Present && event.TurnStartEvent.Value != nil {
		value := event.TurnStartEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.TurnFinishBeforeEvent.Present && event.TurnFinishBeforeEvent.Value != nil {
		value := event.TurnFinishBeforeEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.TurnEndEvent.Present && event.TurnEndEvent.Value != nil {
		value := event.TurnEndEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.TurnProgressEvent.Present && event.TurnProgressEvent.Value != nil {
		value := event.TurnProgressEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ModelRequestBeforeEvent.Present && event.ModelRequestBeforeEvent.Value != nil {
		value := event.ModelRequestBeforeEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ModelResponseAfterEvent.Present && event.ModelResponseAfterEvent.Value != nil {
		value := event.ModelResponseAfterEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ModelErrorEvent.Present && event.ModelErrorEvent.Value != nil {
		value := event.ModelErrorEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ModelSwitchBeforeEvent.Present && event.ModelSwitchBeforeEvent.Value != nil {
		value := event.ModelSwitchBeforeEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ModelSwitchAfterEvent.Present && event.ModelSwitchAfterEvent.Value != nil {
		value := event.ModelSwitchAfterEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ToolPermissionRequestEvent.Present && event.ToolPermissionRequestEvent.Value != nil {
		value := event.ToolPermissionRequestEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ToolPermissionResolvedEvent.Present && event.ToolPermissionResolvedEvent.Value != nil {
		value := event.ToolPermissionResolvedEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ToolProgressEvent.Present && event.ToolProgressEvent.Value != nil {
		value := event.ToolProgressEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ToolBatchAfterEvent.Present && event.ToolBatchAfterEvent.Value != nil {
		value := event.ToolBatchAfterEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ContextCompactBeforeEvent.Present && event.ContextCompactBeforeEvent.Value != nil {
		value := event.ContextCompactBeforeEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.ContextCompactAfterEvent.Present && event.ContextCompactAfterEvent.Value != nil {
		value := event.ContextCompactAfterEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.TaskChangeBeforeEvent.Present && event.TaskChangeBeforeEvent.Value != nil {
		value := event.TaskChangeBeforeEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.TaskChangeAfterEvent.Present && event.TaskChangeAfterEvent.Value != nil {
		value := event.TaskChangeAfterEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.UserAttentionEvent.Present && event.UserAttentionEvent.Value != nil {
		value := event.UserAttentionEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.UserElicitationRequestEvent.Present && event.UserElicitationRequestEvent.Value != nil {
		value := event.UserElicitationRequestEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.UserElicitationResultEvent.Present && event.UserElicitationResultEvent.Value != nil {
		value := event.UserElicitationResultEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.UserMessageInboundEvent.Present && event.UserMessageInboundEvent.Value != nil {
		value := event.UserMessageInboundEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.UserMessageOutboundEvent.Present && event.UserMessageOutboundEvent.Value != nil {
		value := event.UserMessageOutboundEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.WorkspaceChangeBeforeEvent.Present && event.WorkspaceChangeBeforeEvent.Value != nil {
		value := event.WorkspaceChangeBeforeEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.WorkspaceChangeAfterEvent.Present && event.WorkspaceChangeAfterEvent.Value != nil {
		value := event.WorkspaceChangeAfterEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.FileChangedEvent.Present && event.FileChangedEvent.Value != nil {
		value := event.FileChangedEvent.Value
		return string(value.Type), value.ID, nil
	}
	if event.HookFailureEvent.Present && event.HookFailureEvent.Value != nil {
		value := event.HookFailureEvent.Value
		return string(value.Type), value.ID, nil
	}
	return "", "", errors.New("unknown event has no authority")
}

func eventTool(event *ahp.Event) *ahp.ExecutionEventTool {
	if event.ToolBeforeEvent.Present {
		return event.ToolBeforeEvent.Value.Tool
	}
	if event.ToolAfterEvent.Present {
		return event.ToolAfterEvent.Value.Tool
	}
	if event.ToolPermissionRequestEvent.Present {
		return event.ToolPermissionRequestEvent.Value.Tool
	}
	if event.ToolPermissionResolvedEvent.Present {
		return event.ToolPermissionResolvedEvent.Value.Tool
	}
	if event.ToolProgressEvent.Present {
		return event.ToolProgressEvent.Value.Tool
	}
	return nil
}

func eventMessages(event *ahp.Event) (*ahp.CanonicalMessages, error) {
	if event.ToolAfterEvent.Present {
		value, err := convertWire[ahp.CanonicalMessages](event.ToolAfterEvent.Value.Items)
		return &value, err
	}
	if event.TurnStartEvent.Present {
		value, err := convertWire[ahp.CanonicalMessages](event.TurnStartEvent.Value.Items)
		return &value, err
	}
	if event.TurnFinishBeforeEvent.Present {
		value, err := convertWire[ahp.CanonicalMessages](event.TurnFinishBeforeEvent.Value.Items)
		return &value, err
	}
	if event.ModelRequestBeforeEvent.Present {
		value, err := convertWire[ahp.CanonicalMessages](event.ModelRequestBeforeEvent.Value.Items)
		return &value, err
	}
	if event.ModelResponseAfterEvent.Present {
		value, err := convertWire[ahp.CanonicalMessages](event.ModelResponseAfterEvent.Value.Items)
		return &value, err
	}
	if event.UserMessageInboundEvent.Present {
		value, err := convertWire[ahp.CanonicalMessages](event.UserMessageInboundEvent.Value.Message.Messages)
		return &value, err
	}
	if event.UserMessageOutboundEvent.Present {
		value, err := convertWire[ahp.CanonicalMessages](event.UserMessageOutboundEvent.Value.Message.Messages)
		return &value, err
	}
	return nil, errors.New("canonical message target unavailable")
}

func setEventMessages(event *ahp.Event, messages *ahp.CanonicalMessages) error {
	if event.ToolAfterEvent.Present {
		value, err := convertWire[[]*ahp.ModelVisibleItem](messages)
		if err != nil {
			return err
		}
		event.ToolAfterEvent.Value.Items = value
		return nil
	}
	if event.TurnStartEvent.Present {
		value, err := convertWire[[]*ahp.ModelVisibleItem](messages)
		if err != nil {
			return err
		}
		event.TurnStartEvent.Value.Items = value
		return nil
	}
	if event.TurnFinishBeforeEvent.Present {
		value, err := convertWire[[]*ahp.ModelVisibleItem](messages)
		if err != nil {
			return err
		}
		event.TurnFinishBeforeEvent.Value.Items = value
		return nil
	}
	if event.ModelRequestBeforeEvent.Present {
		value, err := convertWire[[]*ahp.ModelVisibleItem](messages)
		if err != nil {
			return err
		}
		event.ModelRequestBeforeEvent.Value.Items = value
		return nil
	}
	if event.ModelResponseAfterEvent.Present {
		value, err := convertWire[[]*ahp.ModelVisibleItem](messages)
		if err != nil {
			return err
		}
		event.ModelResponseAfterEvent.Value.Items = value
		return nil
	}
	if event.UserMessageInboundEvent.Present {
		value, err := convertWire[[]ahp.UserMessageInboundEventMessageMessagesItem](messages)
		if err != nil {
			return err
		}
		event.UserMessageInboundEvent.Value.Message.Messages = value
		return nil
	}
	if event.UserMessageOutboundEvent.Present {
		value, err := convertWire[[]ahp.UserMessageOutboundEventMessageMessagesItem](messages)
		if err != nil {
			return err
		}
		event.UserMessageOutboundEvent.Value.Message.Messages = value
		return nil
	}
	return errors.New("canonical message target unavailable")
}

func eventTextParts(event *ahp.Event) (*ahp.TextParts, error) {
	if event.ContextCompactBeforeEvent.Present {
		value := event.ContextCompactBeforeEvent.Value.Instructions
		if value.Present && value.Value != nil {
			return value.Value, nil
		}
		empty := ahp.TextParts{}
		return &empty, nil
	}
	if event.ContextCompactAfterEvent.Present {
		return event.ContextCompactAfterEvent.Value.Summary, nil
	}
	return nil, errors.New("text target unavailable")
}

func setEventTextParts(event *ahp.Event, parts *ahp.TextParts) error {
	if event.ContextCompactBeforeEvent.Present {
		event.ContextCompactBeforeEvent.Value.Instructions = ahp.Some(parts)
		return nil
	}
	if event.ContextCompactAfterEvent.Present {
		event.ContextCompactAfterEvent.Value.Summary = parts
		return nil
	}
	return errors.New("text target unavailable")
}

// Decode contextual candidate payloads into generator-owned known types. Generic
// tool values stay raw until a caller codec is declared. All state extension bags
// are carried by the generated base state and never interpreted as authority.
func stateCandidate(kind string, state ahp.InterceptRequestParamsState) (any, error) {
	if !state.Candidate.Valid {
		return nil, nil
	}
	switch kind {
	case "model.request.before":
		value, err := convertWire[ahp.MessagesState](state)
		if err != nil {
			return nil, err
		}
		if value.Candidate.Value == nil {
			return nil, errors.New("missing message candidate")
		}
		return value.Candidate.Value.Value, nil
	case "context.compact.before":
		value, err := convertWire[ahp.TextState](state)
		if err != nil {
			return nil, err
		}
		if value.Candidate.Value == nil {
			return nil, errors.New("missing text candidate")
		}
		return value.Candidate.Value.Value, nil
	case "user.elicitation.request":
		value, err := convertWire[ahp.ElicitResultState](state)
		if err != nil {
			return nil, err
		}
		if value.Candidate.Value == nil {
			return nil, errors.New("missing elicitation candidate")
		}
		return value.Candidate.Value.Value, nil
	default:
		value, err := convertWire[ahp.ToolState](state)
		if err != nil {
			return nil, err
		}
		if value.Candidate.Value == nil {
			return nil, errors.New("missing tool candidate")
		}
		return value.Candidate.Value.Value, nil
	}
}

func setStateCandidate(state *ahp.InterceptRequestParamsState, kind string, value any) error {
	var candidate any
	switch value := value.(type) {
	case *ahp.CanonicalMessages:
		candidate = ahp.MessagesCandidate{Value: value}
	case *ahp.TextParts:
		candidate = ahp.TextCandidate{Value: value}
	case *ahp.McpElicitationElicitResult:
		candidate = ahp.ElicitResultCandidate{Value: value}
	case json.RawMessage:
		candidate = ahp.Candidate[json.RawMessage, json.RawMessage]{Value: value}
	default:
		return errors.New("unsupported contextual candidate")
	}
	decoded, err := convertWire[ahp.InterceptRequestParamsStateCandidateValue](candidate)
	if err != nil {
		return err
	}
	state.Candidate = ahp.NonNull(decoded)
	return nil
}
