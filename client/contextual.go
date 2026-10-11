package client

import (
	"encoding/json"
	"errors"
	ahp "github.com/agenthooksprotocol/go-sdk"
)

// stagedEffect is an execution instruction referencing generator-owned payloads.
// It is not a wire contract. wire retains opaque extras for authority checks and
// the accepted response; known payloads are never inferred from JSON array shape.
type stagedEffect struct {
	kind, target string
	merge        bool
	value        any
	wire         any
}

func contextualEffects(response ahp.ContextualResponse) ([]stagedEffect, error) {
	switch value := response.(type) {
	case *ahp.ConfigChangeBeforeInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.ContextCompactAfterInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.ContextCompactBeforeInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.ModelRequestBeforeInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.ModelResponseAfterInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.ModelSwitchBeforeInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.SessionStartInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.TaskChangeBeforeInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.ToolAfterInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.ToolBatchAfterInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.ToolBeforeInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.ToolPermissionRequestInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.TurnFinishBeforeInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.TurnStartInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.UserElicitationRequestInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.UserElicitationResultInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.UserMessageInboundInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.UserMessageOutboundInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	case *ahp.WorkspaceChangeBeforeInterceptResponse:
		return collectContextualEffects(value.Result.Effects.Value)
	default:
		return nil, errors.New("unknown contextual response")
	}
}

func collectContextualEffects[T any](values []*T) ([]stagedEffect, error) {
	result := make([]stagedEffect, 0, len(values))
	for _, value := range values {
		effect, err := contextualEffect(value)
		if err != nil {
			return nil, err
		}
		result = append(result, effect)
	}
	return result, nil
}

func contextualEffect(raw any) (stagedEffect, error) {
	switch effect := raw.(type) {
	case *ahp.ConfigChangeBeforeEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.DenyEffect.Present {
			value := effect.DenyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "deny", wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.ContextCompactAfterEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.InjectEffect.Present {
			value := effect.InjectEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "inject", target: string(value.Target), value: value.Value, wire: value}, nil
		}
		if effect.ContextCompactAfterModifyEffect.Present {
			value := effect.ContextCompactAfterModifyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			if !value.Operation.Merge.Present && !value.Operation.Replace.Present {
				return stagedEffect{}, errors.New("unknown modification operation")
			}
			return stagedEffect{kind: "modify", target: string(value.Target), merge: value.Operation.Merge.Present, value: value.Value, wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.ContextCompactBeforeEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.DenyEffect.Present {
			value := effect.DenyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "deny", wire: value}, nil
		}
		if effect.ContextCompactBeforeModifyEffect.Present {
			value := effect.ContextCompactBeforeModifyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			if !value.Operation.Merge.Present && !value.Operation.Replace.Present {
				return stagedEffect{}, errors.New("unknown modification operation")
			}
			return stagedEffect{kind: "modify", target: string(value.Target), merge: value.Operation.Merge.Present, value: value.Value, wire: value}, nil
		}
		if effect.ReturnTextEffect.Present {
			value := effect.ReturnTextEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "return", value: value.Value, wire: value}, nil
		}
		if effect.InjectEffect.Present {
			value := effect.InjectEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "inject", target: string(value.Target), value: value.Value, wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.ModelRequestBeforeEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.DenyEffect.Present {
			value := effect.DenyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "deny", wire: value}, nil
		}
		if effect.ModelRequestBeforeModifyEffect.Present {
			value := effect.ModelRequestBeforeModifyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			if !value.Operation.Merge.Present && !value.Operation.Replace.Present {
				return stagedEffect{}, errors.New("unknown modification operation")
			}
			return stagedEffect{kind: "modify", target: string(value.Target), merge: value.Operation.Merge.Present, value: value.Value, wire: value}, nil
		}
		if effect.InjectEffect.Present {
			value := effect.InjectEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "inject", target: string(value.Target), value: value.Value, wire: value}, nil
		}
		if effect.ReturnMessagesEffect.Present {
			value := effect.ReturnMessagesEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "return", value: value.Value, wire: value}, nil
		}
		if effect.StopFlowEffect.Present {
			value := effect.StopFlowEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "flow", wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.ModelResponseAfterEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.ModelResponseAfterModifyEffect.Present {
			value := effect.ModelResponseAfterModifyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			if !value.Operation.Merge.Present && !value.Operation.Replace.Present {
				return stagedEffect{}, errors.New("unknown modification operation")
			}
			return stagedEffect{kind: "modify", target: string(value.Target), merge: value.Operation.Merge.Present, value: value.Value, wire: value}, nil
		}
		if effect.StopFlowEffect.Present {
			value := effect.StopFlowEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "flow", wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.ModelSwitchBeforeEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.DenyEffect.Present {
			value := effect.DenyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "deny", wire: value}, nil
		}
		if effect.StopFlowEffect.Present {
			value := effect.StopFlowEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "flow", wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.SessionStartEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.InjectEffect.Present {
			value := effect.InjectEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "inject", target: string(value.Target), value: value.Value, wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.TaskChangeBeforeEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.DenyEffect.Present {
			value := effect.DenyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "deny", wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.ToolAfterEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.ToolAfterModifyEffect.Present {
			value := effect.ToolAfterModifyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			if !value.Operation.Merge.Present && !value.Operation.Replace.Present {
				return stagedEffect{}, errors.New("unknown modification operation")
			}
			return stagedEffect{kind: "modify", target: string(value.Target), merge: value.Operation.Merge.Present, value: value.Value, wire: value}, nil
		}
		if effect.InjectEffect.Present {
			value := effect.InjectEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "inject", target: string(value.Target), value: value.Value, wire: value}, nil
		}
		if effect.StopFlowEffect.Present {
			value := effect.StopFlowEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "flow", wire: value}, nil
		}
		if effect.ContinueFlowEffect.Present {
			value := effect.ContinueFlowEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "flow", wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.ToolBatchAfterEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.StopFlowEffect.Present {
			value := effect.StopFlowEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "flow", wire: value}, nil
		}
		if effect.InjectEffect.Present {
			value := effect.InjectEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "inject", target: string(value.Target), value: value.Value, wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.ToolBeforeEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.DenyEffect.Present {
			value := effect.DenyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "deny", wire: value}, nil
		}
		if effect.AllowEffect.Present {
			value := effect.AllowEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "allow", wire: value}, nil
		}
		if effect.AskEffect.Present {
			value := effect.AskEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "ask", wire: value}, nil
		}
		if effect.ToolBeforeModifyEffect.Present {
			value := effect.ToolBeforeModifyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			if !value.Operation.Merge.Present && !value.Operation.Replace.Present {
				return stagedEffect{}, errors.New("unknown modification operation")
			}
			return stagedEffect{kind: "modify", target: string(value.Target), merge: value.Operation.Merge.Present, value: value.Value, wire: value}, nil
		}
		if effect.InjectEffect.Present {
			value := effect.InjectEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "inject", target: string(value.Target), value: value.Value, wire: value}, nil
		}
		if effect.StopFlowEffect.Present {
			value := effect.StopFlowEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "flow", wire: value}, nil
		}
		if effect.ReturnToolEffect.Present {
			value := effect.ReturnToolEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "return", value: value.Value, wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.ToolPermissionRequestEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.AllowEffect.Present {
			value := effect.AllowEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "allow", wire: value}, nil
		}
		if effect.DenyEffect.Present {
			value := effect.DenyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "deny", wire: value}, nil
		}
		if effect.ToolPermissionRequestModifyEffect.Present {
			value := effect.ToolPermissionRequestModifyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			if !value.Operation.Merge.Present && !value.Operation.Replace.Present {
				return stagedEffect{}, errors.New("unknown modification operation")
			}
			return stagedEffect{kind: "modify", target: string(value.Target), merge: value.Operation.Merge.Present, value: value.Value, wire: value}, nil
		}
		if effect.StopFlowEffect.Present {
			value := effect.StopFlowEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "flow", wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.TurnFinishBeforeEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.TurnFinishBeforeModifyEffect.Present {
			value := effect.TurnFinishBeforeModifyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			if !value.Operation.Merge.Present && !value.Operation.Replace.Present {
				return stagedEffect{}, errors.New("unknown modification operation")
			}
			return stagedEffect{kind: "modify", target: string(value.Target), merge: value.Operation.Merge.Present, value: value.Value, wire: value}, nil
		}
		if effect.StopFlowEffect.Present {
			value := effect.StopFlowEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "flow", wire: value}, nil
		}
		if effect.ContinueFlowEffect.Present {
			value := effect.ContinueFlowEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "flow", wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.TurnStartEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.DenyEffect.Present {
			value := effect.DenyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "deny", wire: value}, nil
		}
		if effect.TurnStartModifyEffect.Present {
			value := effect.TurnStartModifyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			if !value.Operation.Merge.Present && !value.Operation.Replace.Present {
				return stagedEffect{}, errors.New("unknown modification operation")
			}
			return stagedEffect{kind: "modify", target: string(value.Target), merge: value.Operation.Merge.Present, value: value.Value, wire: value}, nil
		}
		if effect.InjectEffect.Present {
			value := effect.InjectEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "inject", target: string(value.Target), value: value.Value, wire: value}, nil
		}
		if effect.StopFlowEffect.Present {
			value := effect.StopFlowEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "flow", wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.UserElicitationRequestEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.DenyEffect.Present {
			value := effect.DenyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "deny", wire: value}, nil
		}
		if effect.ReturnElicitResultEffect.Present {
			value := effect.ReturnElicitResultEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "return", value: value.Value, wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.UserElicitationResultEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.UserElicitationResultModifyEffect.Present {
			value := effect.UserElicitationResultModifyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			if !value.Operation.Merge.Present && !value.Operation.Replace.Present {
				return stagedEffect{}, errors.New("unknown modification operation")
			}
			return stagedEffect{kind: "modify", target: string(value.Target), merge: value.Operation.Merge.Present, value: value.Value, wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.UserMessageInboundEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.DenyEffect.Present {
			value := effect.DenyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "deny", wire: value}, nil
		}
		if effect.UserMessageInboundModifyEffect.Present {
			value := effect.UserMessageInboundModifyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			if !value.Operation.Merge.Present && !value.Operation.Replace.Present {
				return stagedEffect{}, errors.New("unknown modification operation")
			}
			return stagedEffect{kind: "modify", target: string(value.Target), merge: value.Operation.Merge.Present, value: value.Value, wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.UserMessageOutboundEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.DenyEffect.Present {
			value := effect.DenyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "deny", wire: value}, nil
		}
		if effect.UserMessageOutboundModifyEffect.Present {
			value := effect.UserMessageOutboundModifyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			if !value.Operation.Merge.Present && !value.Operation.Replace.Present {
				return stagedEffect{}, errors.New("unknown modification operation")
			}
			return stagedEffect{kind: "modify", target: string(value.Target), merge: value.Operation.Merge.Present, value: value.Value, wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	case *ahp.WorkspaceChangeBeforeEffect:
		if effect == nil {
			return stagedEffect{}, errors.New("nil contextual effect")
		}
		if effect.DenyEffect.Present {
			value := effect.DenyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "deny", wire: value}, nil
		}
		if effect.WorkspaceChangeBeforeModifyEffect.Present {
			value := effect.WorkspaceChangeBeforeModifyEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			if !value.Operation.Merge.Present && !value.Operation.Replace.Present {
				return stagedEffect{}, errors.New("unknown modification operation")
			}
			return stagedEffect{kind: "modify", target: string(value.Target), merge: value.Operation.Merge.Present, value: value.Value, wire: value}, nil
		}
		if effect.MessageEffect.Present {
			value := effect.MessageEffect.Value
			if value == nil {
				return stagedEffect{}, errors.New("nil known effect")
			}
			return stagedEffect{kind: "message", wire: value}, nil
		}
		return stagedEffect{}, errors.New("unknown contextual effect has no authority")
	default:
		return stagedEffect{}, errors.New("unsupported contextual effect")
	}
}

func convertWire[T any](value any) (T, error) {
	var result T
	raw, err := json.Marshal(value)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(raw, &result)
	return result, err
}
