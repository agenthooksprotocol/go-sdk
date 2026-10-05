package interop

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	hooks "github.com/agenthooksprotocol/go-sdk/client"
	"github.com/agenthooksprotocol/go-sdk/event"
)

// Explicit named dispatch keeps the adapter on the same typed public surface as hosts.
func dispatchPublicBoundary(ctx context.Context, c *hooks.Client, name string, ev Object, opts []hooks.InterceptOption) (*hooks.Result, error) {
	switch name {
	case "config.change.after":
		var input event.ConfigChangeAfterInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ConfigChangeAfter(ctx, input)
	case "config.change.before":
		var input event.ConfigChangeBeforeInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ConfigChangeBefore(ctx, input, opts...)
	case "context.compact.after":
		var input event.ContextCompactAfterInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ContextCompactAfter(ctx, input, opts...)
	case "context.compact.before":
		var input event.ContextCompactBeforeInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ContextCompactBefore(ctx, input, opts...)
	case "file.changed":
		var input event.FileChangedInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.FileChanged(ctx, input)
	case "hook.failure":
		var input event.HookFailureInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.HookFailure(ctx, input)
	case "model.error":
		var input event.ModelErrorInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ModelError(ctx, input)
	case "model.request.before":
		var input event.ModelRequestBeforeInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ModelRequestBefore(ctx, input, opts...)
	case "model.response.after":
		var input event.ModelResponseAfterInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ModelResponseAfter(ctx, input, opts...)
	case "model.switch.after":
		var input event.ModelSwitchAfterInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ModelSwitchAfter(ctx, input)
	case "model.switch.before":
		var input event.ModelSwitchBeforeInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ModelSwitchBefore(ctx, input, opts...)
	case "session.end":
		var input event.SessionEndInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.SessionEnd(ctx, input)
	case "session.start":
		var input event.SessionStartInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.SessionStart(ctx, input, opts...)
	case "task.change.after":
		var input event.TaskChangeAfterInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.TaskChangeAfter(ctx, input)
	case "task.change.before":
		var input event.TaskChangeBeforeInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.TaskChangeBefore(ctx, input, opts...)
	case "tool.after":
		var input event.ToolAfterInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ToolAfter(ctx, input, opts...)
	case "tool.batch.after":
		var input event.ToolBatchAfterInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ToolBatchAfter(ctx, input, opts...)
	case "tool.before":
		var input event.ToolBeforeInput[json.RawMessage]
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		result, err := c.ToolBefore(ctx, input, opts...)
		if result == nil {
			return nil, err
		}
		return result.Result, err
	case "tool.permission.request":
		var input event.ToolPermissionRequestInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ToolPermissionRequest(ctx, input, opts...)
	case "tool.permission.resolved":
		var input event.ToolPermissionResolvedInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ToolPermissionResolved(ctx, input)
	case "tool.progress":
		var input event.ToolProgressInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.ToolProgress(ctx, input)
	case "turn.end":
		var input event.TurnEndInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.TurnEnd(ctx, input)
	case "turn.finish.before":
		var input event.TurnFinishBeforeInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.TurnFinishBefore(ctx, input, opts...)
	case "turn.progress":
		var input event.TurnProgressInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.TurnProgress(ctx, input)
	case "turn.start":
		var input event.TurnStartInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.TurnStart(ctx, input, opts...)
	case "user.attention":
		var input event.UserAttentionInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.UserAttention(ctx, input)
	case "user.elicitation.request":
		var input event.UserElicitationRequestInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.UserElicitationRequest(ctx, input, opts...)
	case "user.elicitation.result":
		var input event.UserElicitationResultInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.UserElicitationResult(ctx, input, opts...)
	case "user.message.inbound":
		var input event.UserMessageInboundInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.UserMessageInbound(ctx, input, opts...)
	case "user.message.outbound":
		var input event.UserMessageOutboundInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.UserMessageOutbound(ctx, input, opts...)
	case "workspace.change.after":
		var input event.WorkspaceChangeAfterInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.WorkspaceChangeAfter(ctx, input)
	case "workspace.change.before":
		var input event.WorkspaceChangeBeforeInput
		if err := decodeBoundaryInput(ev, &input); err != nil {
			return nil, err
		}
		return c.WorkspaceChangeBefore(ctx, input, opts...)
	default:
		return nil, fmt.Errorf("unsupported public boundary %s", name)
	}
}

// Boundary inputs intentionally marshal optionals but are not wire parsers.
// Parse each supplied field with the generated model codecs, preserving absent
// optional fields rather than losing them through encoding/json's struct rules.
func decodeBoundaryInput(ev Object, destination any) error {
	value := reflect.ValueOf(destination).Elem()
	typ := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		raw, exists := ev[name]
		if !exists {
			continue
		}
		if field.Kind() == reflect.Struct && strings.HasPrefix(field.Type().Name(), "Optional[") {
			field.FieldByName("Present").SetBool(true)
			field = field.FieldByName("Value")
		}
		if name == "tool" && strings.HasPrefix(field.Type().Name(), "Input[") {
			if err := decodeBoundaryInput(obj(raw), field.Addr().Interface()); err != nil {
				return err
			}
		} else if err := json.Unmarshal(jsonBytes(raw), field.Addr().Interface()); err != nil {
			return err
		}
	}
	return nil
}
