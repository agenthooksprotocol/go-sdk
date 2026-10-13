package server

import (
	"context"
	"encoding/json"
	"errors"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"net/http"
)

// InterceptContext carries one exact event and its request-scoped grants.
// AdditionalProperties are params extras; EnvelopeExtras are request extras.
// State and opaque data remain authoritative and are not flattened or discarded.
type InterceptContext[E, C any] struct {
	Event                *E
	Capabilities         C
	State                ahp.Optional[ahp.InterceptRequestParamsState]
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// ObserveContext carries one exact observation. The observation wire schema has
// no state or extensions members; future params members survive in extras.
type ObserveContext[E any] struct {
	Event                *E
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// ObserveAnyContext carries an observation routed to ObserveHandlers.Any. Type is
// the canonical event type (for example "session.end"); Event is the validated
// event union with exactly one known variant present.
type ObserveAnyContext struct {
	Type string
	ObserveContext[ahp.Event]
}

// Handlers separates interception from observation, including for the same event.
// Callbacks may run concurrently over HTTP and must cooperate with cancellation.
// Nil event callbacks reject that event. Discovery is independent of dispatch.
type Handlers struct {
	Intercept    InterceptHandlers
	Observe      ObserveHandlers
	Capabilities func(context.Context, ahp.CapabilitiesRequest) (ahp.CapabilitiesResponseResult, error)
}

// InterceptHandlers accepts only event-specific callbacks and replies.
type InterceptHandlers struct {
	ToolBefore             func(context.Context, InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities]) (ToolBeforeReply, error)
	ToolAfter              func(context.Context, InterceptContext[ahp.ToolAfterEvent, ahp.ToolAfterCapabilities]) (ToolAfterReply, error)
	SessionStart           func(context.Context, InterceptContext[ahp.SessionStartEvent, ahp.SessionStartCapabilities]) (SessionStartReply, error)
	ConfigChangeBefore     func(context.Context, InterceptContext[ahp.ConfigChangeBeforeEvent, ahp.ConfigChangeBeforeCapabilities]) (ConfigChangeBeforeReply, error)
	TurnStart              func(context.Context, InterceptContext[ahp.TurnStartEvent, ahp.TurnStartCapabilities]) (TurnStartReply, error)
	TurnFinishBefore       func(context.Context, InterceptContext[ahp.TurnFinishBeforeEvent, ahp.TurnFinishBeforeCapabilities]) (TurnFinishBeforeReply, error)
	ModelRequestBefore     func(context.Context, InterceptContext[ahp.ModelRequestBeforeEvent, ahp.ModelRequestBeforeCapabilities]) (ModelRequestBeforeReply, error)
	ModelResponseAfter     func(context.Context, InterceptContext[ahp.ModelResponseAfterEvent, ahp.ModelResponseAfterCapabilities]) (ModelResponseAfterReply, error)
	ModelSwitchBefore      func(context.Context, InterceptContext[ahp.ModelSwitchBeforeEvent, ahp.ModelSwitchBeforeCapabilities]) (ModelSwitchBeforeReply, error)
	ToolPermissionRequest  func(context.Context, InterceptContext[ahp.ToolPermissionRequestEvent, ahp.ToolPermissionRequestCapabilities]) (ToolPermissionRequestReply, error)
	ToolBatchAfter         func(context.Context, InterceptContext[ahp.ToolBatchAfterEvent, ahp.ToolBatchAfterCapabilities]) (ToolBatchAfterReply, error)
	ContextCompactBefore   func(context.Context, InterceptContext[ahp.ContextCompactBeforeEvent, ahp.ContextCompactBeforeCapabilities]) (ContextCompactBeforeReply, error)
	ContextCompactAfter    func(context.Context, InterceptContext[ahp.ContextCompactAfterEvent, ahp.ContextCompactAfterCapabilities]) (ContextCompactAfterReply, error)
	TaskChangeBefore       func(context.Context, InterceptContext[ahp.TaskChangeBeforeEvent, ahp.TaskChangeBeforeCapabilities]) (TaskChangeBeforeReply, error)
	UserElicitationRequest func(context.Context, InterceptContext[ahp.UserElicitationRequestEvent, ahp.UserElicitationRequestCapabilities]) (UserElicitationRequestReply, error)
	UserElicitationResult  func(context.Context, InterceptContext[ahp.UserElicitationResultEvent, ahp.UserElicitationResultCapabilities]) (UserElicitationResultReply, error)
	UserMessageInbound     func(context.Context, InterceptContext[ahp.UserMessageInboundEvent, ahp.UserMessageInboundCapabilities]) (UserMessageInboundReply, error)
	UserMessageOutbound    func(context.Context, InterceptContext[ahp.UserMessageOutboundEvent, ahp.UserMessageOutboundCapabilities]) (UserMessageOutboundReply, error)
	WorkspaceChangeBefore  func(context.Context, InterceptContext[ahp.WorkspaceChangeBeforeEvent, ahp.WorkspaceChangeBeforeCapabilities]) (WorkspaceChangeBeforeReply, error)
}

// ObserveHandlers accepts exact events without interception grants or replies.
type ObserveHandlers struct {
	ToolBefore             func(context.Context, ObserveContext[ahp.ToolBeforeEvent]) error
	ToolAfter              func(context.Context, ObserveContext[ahp.ToolAfterEvent]) error
	SessionStart           func(context.Context, ObserveContext[ahp.SessionStartEvent]) error
	SessionEnd             func(context.Context, ObserveContext[ahp.SessionEndEvent]) error
	ConfigChangeBefore     func(context.Context, ObserveContext[ahp.ConfigChangeBeforeEvent]) error
	ConfigChangeAfter      func(context.Context, ObserveContext[ahp.ConfigChangeAfterEvent]) error
	TurnStart              func(context.Context, ObserveContext[ahp.TurnStartEvent]) error
	TurnFinishBefore       func(context.Context, ObserveContext[ahp.TurnFinishBeforeEvent]) error
	TurnEnd                func(context.Context, ObserveContext[ahp.TurnEndEvent]) error
	TurnProgress           func(context.Context, ObserveContext[ahp.TurnProgressEvent]) error
	ModelRequestBefore     func(context.Context, ObserveContext[ahp.ModelRequestBeforeEvent]) error
	ModelResponseAfter     func(context.Context, ObserveContext[ahp.ModelResponseAfterEvent]) error
	ModelError             func(context.Context, ObserveContext[ahp.ModelErrorEvent]) error
	ModelSwitchBefore      func(context.Context, ObserveContext[ahp.ModelSwitchBeforeEvent]) error
	ModelSwitchAfter       func(context.Context, ObserveContext[ahp.ModelSwitchAfterEvent]) error
	ToolPermissionRequest  func(context.Context, ObserveContext[ahp.ToolPermissionRequestEvent]) error
	ToolPermissionResolved func(context.Context, ObserveContext[ahp.ToolPermissionResolvedEvent]) error
	ToolProgress           func(context.Context, ObserveContext[ahp.ToolProgressEvent]) error
	ToolBatchAfter         func(context.Context, ObserveContext[ahp.ToolBatchAfterEvent]) error
	ContextCompactBefore   func(context.Context, ObserveContext[ahp.ContextCompactBeforeEvent]) error
	ContextCompactAfter    func(context.Context, ObserveContext[ahp.ContextCompactAfterEvent]) error
	TaskChangeBefore       func(context.Context, ObserveContext[ahp.TaskChangeBeforeEvent]) error
	TaskChangeAfter        func(context.Context, ObserveContext[ahp.TaskChangeAfterEvent]) error
	UserAttention          func(context.Context, ObserveContext[ahp.UserAttentionEvent]) error
	UserElicitationRequest func(context.Context, ObserveContext[ahp.UserElicitationRequestEvent]) error
	UserElicitationResult  func(context.Context, ObserveContext[ahp.UserElicitationResultEvent]) error
	UserMessageInbound     func(context.Context, ObserveContext[ahp.UserMessageInboundEvent]) error
	UserMessageOutbound    func(context.Context, ObserveContext[ahp.UserMessageOutboundEvent]) error
	WorkspaceChangeBefore  func(context.Context, ObserveContext[ahp.WorkspaceChangeBeforeEvent]) error
	WorkspaceChangeAfter   func(context.Context, ObserveContext[ahp.WorkspaceChangeAfterEvent]) error
	FileChanged            func(context.Context, ObserveContext[ahp.FileChangedEvent]) error
	HookFailure            func(context.Context, ObserveContext[ahp.HookFailureEvent]) error
	// Any is an optional catch-all invoked only for a validated observation
	// whose per-event callback above is nil. It never runs in addition to a
	// per-event callback. Without it, such observations are acknowledged silently.
	Any func(context.Context, ObserveAnyContext) error
}

// ToolBeforeReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type ToolBeforeReply struct {
	Effects              []*ahp.ToolBeforeEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// ToolAfterReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type ToolAfterReply struct {
	Effects              []*ahp.ToolAfterEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// SessionStartReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type SessionStartReply struct {
	Effects              []*ahp.SessionStartEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// ConfigChangeBeforeReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type ConfigChangeBeforeReply struct {
	Effects              []*ahp.ConfigChangeBeforeEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// TurnStartReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type TurnStartReply struct {
	Effects              []*ahp.TurnStartEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// TurnFinishBeforeReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type TurnFinishBeforeReply struct {
	Effects              []*ahp.TurnFinishBeforeEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// ModelRequestBeforeReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type ModelRequestBeforeReply struct {
	Effects              []*ahp.ModelRequestBeforeEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// ModelResponseAfterReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type ModelResponseAfterReply struct {
	Effects              []*ahp.ModelResponseAfterEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// ModelSwitchBeforeReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type ModelSwitchBeforeReply struct {
	Effects              []*ahp.ModelSwitchBeforeEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// ToolPermissionRequestReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type ToolPermissionRequestReply struct {
	Effects              []*ahp.ToolPermissionRequestEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// ToolBatchAfterReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type ToolBatchAfterReply struct {
	Effects              []*ahp.ToolBatchAfterEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// ContextCompactBeforeReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type ContextCompactBeforeReply struct {
	Effects              []*ahp.ContextCompactBeforeEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// ContextCompactAfterReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type ContextCompactAfterReply struct {
	Effects              []*ahp.ContextCompactAfterEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// TaskChangeBeforeReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type TaskChangeBeforeReply struct {
	Effects              []*ahp.TaskChangeBeforeEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// UserElicitationRequestReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type UserElicitationRequestReply struct {
	Effects              []*ahp.UserElicitationRequestEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// UserElicitationResultReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type UserElicitationResultReply struct {
	Effects              []*ahp.UserElicitationResultEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// UserMessageInboundReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type UserMessageInboundReply struct {
	Effects              []*ahp.UserMessageInboundEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// UserMessageOutboundReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type UserMessageOutboundReply struct {
	Effects              []*ahp.UserMessageOutboundEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

// WorkspaceChangeBeforeReply contains ordered event-specific effects and opaque result data.
// Its zero value is a valid no-op; the engine supplies protocol correlation.
type WorkspaceChangeBeforeReply struct {
	Effects              []*ahp.WorkspaceChangeBeforeEffect
	Extensions           ahp.Optional[*ahp.Extensions]
	AdditionalProperties map[string]json.RawMessage
	EnvelopeExtras       map[string]json.RawMessage
}

var errMissingHandler = errors.New("server: event handler unavailable")

// NewHandler validates configuration without starting workers or listeners.
// Zero limits select DefaultMaxFrameBytes. The private wire engine validates
// request-scoped grants and buffers responses before writing redacted errors.
func NewHandler(h Handlers, opts Options) (http.Handler, error) {
	return newWireHandler(wireHandlers{
		typedIntercept: h.Intercept.dispatch,
		Observe:        h.Observe.dispatch,
		Capabilities:   h.Capabilities,
	}, opts)
}

// rawCapabilitiesKey carries original external capability bytes only inside the
// validated wire engine, so exact event grants decode at the incoming boundary.
type rawCapabilitiesKey struct{}

func interceptContext[E, C any](ctx context.Context, request ahp.InterceptRequest, event *E) (InterceptContext[E, C], error) {
	c := InterceptContext[E, C]{Event: event, State: request.Params.State, Extensions: request.Params.Extensions, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties}
	raw, ok := ctx.Value(rawCapabilitiesKey{}).(json.RawMessage)
	if !ok {
		return c, errors.New("server: original capabilities unavailable")
	}
	err := json.Unmarshal(raw, &c.Capabilities)
	return c, err
}

func wireReply(extras map[string]json.RawMessage, value any) (any, map[string]json.RawMessage, error) {
	return value, extras, nil
}

func (h InterceptHandlers) dispatch(ctx context.Context, request ahp.InterceptRequest) (any, map[string]json.RawMessage, error) {
	if request.Params.Event == nil {
		return nil, nil, errMissingHandler
	}
	event := request.Params.Event
	if event.ToolBeforeEvent.Present && h.ToolBefore != nil {
		c, err := interceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities](ctx, request, event.ToolBeforeEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.ToolBefore(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.ToolBeforeInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.ToolAfterEvent.Present && h.ToolAfter != nil {
		c, err := interceptContext[ahp.ToolAfterEvent, ahp.ToolAfterCapabilities](ctx, request, event.ToolAfterEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.ToolAfter(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.ToolAfterInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.SessionStartEvent.Present && h.SessionStart != nil {
		c, err := interceptContext[ahp.SessionStartEvent, ahp.SessionStartCapabilities](ctx, request, event.SessionStartEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.SessionStart(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.SessionStartInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.ConfigChangeBeforeEvent.Present && h.ConfigChangeBefore != nil {
		c, err := interceptContext[ahp.ConfigChangeBeforeEvent, ahp.ConfigChangeBeforeCapabilities](ctx, request, event.ConfigChangeBeforeEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.ConfigChangeBefore(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.ConfigChangeBeforeInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.TurnStartEvent.Present && h.TurnStart != nil {
		c, err := interceptContext[ahp.TurnStartEvent, ahp.TurnStartCapabilities](ctx, request, event.TurnStartEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.TurnStart(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.TurnStartInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.TurnFinishBeforeEvent.Present && h.TurnFinishBefore != nil {
		c, err := interceptContext[ahp.TurnFinishBeforeEvent, ahp.TurnFinishBeforeCapabilities](ctx, request, event.TurnFinishBeforeEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.TurnFinishBefore(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.TurnFinishBeforeInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.ModelRequestBeforeEvent.Present && h.ModelRequestBefore != nil {
		c, err := interceptContext[ahp.ModelRequestBeforeEvent, ahp.ModelRequestBeforeCapabilities](ctx, request, event.ModelRequestBeforeEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.ModelRequestBefore(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.ModelRequestBeforeInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.ModelResponseAfterEvent.Present && h.ModelResponseAfter != nil {
		c, err := interceptContext[ahp.ModelResponseAfterEvent, ahp.ModelResponseAfterCapabilities](ctx, request, event.ModelResponseAfterEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.ModelResponseAfter(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.ModelResponseAfterInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.ModelSwitchBeforeEvent.Present && h.ModelSwitchBefore != nil {
		c, err := interceptContext[ahp.ModelSwitchBeforeEvent, ahp.ModelSwitchBeforeCapabilities](ctx, request, event.ModelSwitchBeforeEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.ModelSwitchBefore(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.ModelSwitchBeforeInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.ToolPermissionRequestEvent.Present && h.ToolPermissionRequest != nil {
		c, err := interceptContext[ahp.ToolPermissionRequestEvent, ahp.ToolPermissionRequestCapabilities](ctx, request, event.ToolPermissionRequestEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.ToolPermissionRequest(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.ToolPermissionRequestInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.ToolBatchAfterEvent.Present && h.ToolBatchAfter != nil {
		c, err := interceptContext[ahp.ToolBatchAfterEvent, ahp.ToolBatchAfterCapabilities](ctx, request, event.ToolBatchAfterEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.ToolBatchAfter(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.ToolBatchAfterInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.ContextCompactBeforeEvent.Present && h.ContextCompactBefore != nil {
		c, err := interceptContext[ahp.ContextCompactBeforeEvent, ahp.ContextCompactBeforeCapabilities](ctx, request, event.ContextCompactBeforeEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.ContextCompactBefore(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.ContextCompactBeforeInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.ContextCompactAfterEvent.Present && h.ContextCompactAfter != nil {
		c, err := interceptContext[ahp.ContextCompactAfterEvent, ahp.ContextCompactAfterCapabilities](ctx, request, event.ContextCompactAfterEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.ContextCompactAfter(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.ContextCompactAfterInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.TaskChangeBeforeEvent.Present && h.TaskChangeBefore != nil {
		c, err := interceptContext[ahp.TaskChangeBeforeEvent, ahp.TaskChangeBeforeCapabilities](ctx, request, event.TaskChangeBeforeEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.TaskChangeBefore(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.TaskChangeBeforeInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.UserElicitationRequestEvent.Present && h.UserElicitationRequest != nil {
		c, err := interceptContext[ahp.UserElicitationRequestEvent, ahp.UserElicitationRequestCapabilities](ctx, request, event.UserElicitationRequestEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.UserElicitationRequest(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.UserElicitationRequestInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.UserElicitationResultEvent.Present && h.UserElicitationResult != nil {
		c, err := interceptContext[ahp.UserElicitationResultEvent, ahp.UserElicitationResultCapabilities](ctx, request, event.UserElicitationResultEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.UserElicitationResult(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.UserElicitationResultInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.UserMessageInboundEvent.Present && h.UserMessageInbound != nil {
		c, err := interceptContext[ahp.UserMessageInboundEvent, ahp.UserMessageInboundCapabilities](ctx, request, event.UserMessageInboundEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.UserMessageInbound(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.UserMessageInboundInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.UserMessageOutboundEvent.Present && h.UserMessageOutbound != nil {
		c, err := interceptContext[ahp.UserMessageOutboundEvent, ahp.UserMessageOutboundCapabilities](ctx, request, event.UserMessageOutboundEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.UserMessageOutbound(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.UserMessageOutboundInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	if event.WorkspaceChangeBeforeEvent.Present && h.WorkspaceChangeBefore != nil {
		c, err := interceptContext[ahp.WorkspaceChangeBeforeEvent, ahp.WorkspaceChangeBeforeCapabilities](ctx, request, event.WorkspaceChangeBeforeEvent.Value)
		if err != nil {
			return nil, nil, err
		}
		reply, err := h.WorkspaceChangeBefore(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		return wireReply(reply.EnvelopeExtras, ahp.WorkspaceChangeBeforeInterceptResponseResult{ProtocolVersion: request.Params.ProtocolVersion, Effects: orderedEffects(reply.Effects), Extensions: reply.Extensions, AdditionalProperties: reply.AdditionalProperties})
	}
	return nil, nil, errMissingHandler
}

func (h ObserveHandlers) dispatch(ctx context.Context, request ahp.ObserveNotification) error {
	if request.Params.Event == nil {
		return errMissingHandler
	}
	event := request.Params.Event
	if event.ToolBeforeEvent.Present && h.ToolBefore != nil {
		return h.ToolBefore(ctx, ObserveContext[ahp.ToolBeforeEvent]{Event: event.ToolBeforeEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ToolAfterEvent.Present && h.ToolAfter != nil {
		return h.ToolAfter(ctx, ObserveContext[ahp.ToolAfterEvent]{Event: event.ToolAfterEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.SessionStartEvent.Present && h.SessionStart != nil {
		return h.SessionStart(ctx, ObserveContext[ahp.SessionStartEvent]{Event: event.SessionStartEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.SessionEndEvent.Present && h.SessionEnd != nil {
		return h.SessionEnd(ctx, ObserveContext[ahp.SessionEndEvent]{Event: event.SessionEndEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ConfigChangeBeforeEvent.Present && h.ConfigChangeBefore != nil {
		return h.ConfigChangeBefore(ctx, ObserveContext[ahp.ConfigChangeBeforeEvent]{Event: event.ConfigChangeBeforeEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ConfigChangeAfterEvent.Present && h.ConfigChangeAfter != nil {
		return h.ConfigChangeAfter(ctx, ObserveContext[ahp.ConfigChangeAfterEvent]{Event: event.ConfigChangeAfterEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.TurnStartEvent.Present && h.TurnStart != nil {
		return h.TurnStart(ctx, ObserveContext[ahp.TurnStartEvent]{Event: event.TurnStartEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.TurnFinishBeforeEvent.Present && h.TurnFinishBefore != nil {
		return h.TurnFinishBefore(ctx, ObserveContext[ahp.TurnFinishBeforeEvent]{Event: event.TurnFinishBeforeEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.TurnEndEvent.Present && h.TurnEnd != nil {
		return h.TurnEnd(ctx, ObserveContext[ahp.TurnEndEvent]{Event: event.TurnEndEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.TurnProgressEvent.Present && h.TurnProgress != nil {
		return h.TurnProgress(ctx, ObserveContext[ahp.TurnProgressEvent]{Event: event.TurnProgressEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ModelRequestBeforeEvent.Present && h.ModelRequestBefore != nil {
		return h.ModelRequestBefore(ctx, ObserveContext[ahp.ModelRequestBeforeEvent]{Event: event.ModelRequestBeforeEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ModelResponseAfterEvent.Present && h.ModelResponseAfter != nil {
		return h.ModelResponseAfter(ctx, ObserveContext[ahp.ModelResponseAfterEvent]{Event: event.ModelResponseAfterEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ModelErrorEvent.Present && h.ModelError != nil {
		return h.ModelError(ctx, ObserveContext[ahp.ModelErrorEvent]{Event: event.ModelErrorEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ModelSwitchBeforeEvent.Present && h.ModelSwitchBefore != nil {
		return h.ModelSwitchBefore(ctx, ObserveContext[ahp.ModelSwitchBeforeEvent]{Event: event.ModelSwitchBeforeEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ModelSwitchAfterEvent.Present && h.ModelSwitchAfter != nil {
		return h.ModelSwitchAfter(ctx, ObserveContext[ahp.ModelSwitchAfterEvent]{Event: event.ModelSwitchAfterEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ToolPermissionRequestEvent.Present && h.ToolPermissionRequest != nil {
		return h.ToolPermissionRequest(ctx, ObserveContext[ahp.ToolPermissionRequestEvent]{Event: event.ToolPermissionRequestEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ToolPermissionResolvedEvent.Present && h.ToolPermissionResolved != nil {
		return h.ToolPermissionResolved(ctx, ObserveContext[ahp.ToolPermissionResolvedEvent]{Event: event.ToolPermissionResolvedEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ToolProgressEvent.Present && h.ToolProgress != nil {
		return h.ToolProgress(ctx, ObserveContext[ahp.ToolProgressEvent]{Event: event.ToolProgressEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ToolBatchAfterEvent.Present && h.ToolBatchAfter != nil {
		return h.ToolBatchAfter(ctx, ObserveContext[ahp.ToolBatchAfterEvent]{Event: event.ToolBatchAfterEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ContextCompactBeforeEvent.Present && h.ContextCompactBefore != nil {
		return h.ContextCompactBefore(ctx, ObserveContext[ahp.ContextCompactBeforeEvent]{Event: event.ContextCompactBeforeEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.ContextCompactAfterEvent.Present && h.ContextCompactAfter != nil {
		return h.ContextCompactAfter(ctx, ObserveContext[ahp.ContextCompactAfterEvent]{Event: event.ContextCompactAfterEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.TaskChangeBeforeEvent.Present && h.TaskChangeBefore != nil {
		return h.TaskChangeBefore(ctx, ObserveContext[ahp.TaskChangeBeforeEvent]{Event: event.TaskChangeBeforeEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.TaskChangeAfterEvent.Present && h.TaskChangeAfter != nil {
		return h.TaskChangeAfter(ctx, ObserveContext[ahp.TaskChangeAfterEvent]{Event: event.TaskChangeAfterEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.UserAttentionEvent.Present && h.UserAttention != nil {
		return h.UserAttention(ctx, ObserveContext[ahp.UserAttentionEvent]{Event: event.UserAttentionEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.UserElicitationRequestEvent.Present && h.UserElicitationRequest != nil {
		return h.UserElicitationRequest(ctx, ObserveContext[ahp.UserElicitationRequestEvent]{Event: event.UserElicitationRequestEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.UserElicitationResultEvent.Present && h.UserElicitationResult != nil {
		return h.UserElicitationResult(ctx, ObserveContext[ahp.UserElicitationResultEvent]{Event: event.UserElicitationResultEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.UserMessageInboundEvent.Present && h.UserMessageInbound != nil {
		return h.UserMessageInbound(ctx, ObserveContext[ahp.UserMessageInboundEvent]{Event: event.UserMessageInboundEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.UserMessageOutboundEvent.Present && h.UserMessageOutbound != nil {
		return h.UserMessageOutbound(ctx, ObserveContext[ahp.UserMessageOutboundEvent]{Event: event.UserMessageOutboundEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.WorkspaceChangeBeforeEvent.Present && h.WorkspaceChangeBefore != nil {
		return h.WorkspaceChangeBefore(ctx, ObserveContext[ahp.WorkspaceChangeBeforeEvent]{Event: event.WorkspaceChangeBeforeEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.WorkspaceChangeAfterEvent.Present && h.WorkspaceChangeAfter != nil {
		return h.WorkspaceChangeAfter(ctx, ObserveContext[ahp.WorkspaceChangeAfterEvent]{Event: event.WorkspaceChangeAfterEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.FileChangedEvent.Present && h.FileChanged != nil {
		return h.FileChanged(ctx, ObserveContext[ahp.FileChangedEvent]{Event: event.FileChangedEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if event.HookFailureEvent.Present && h.HookFailure != nil {
		return h.HookFailure(ctx, ObserveContext[ahp.HookFailureEvent]{Event: event.HookFailureEvent.Value, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties})
	}
	if h.Any != nil {
		eventType, err := observedEventType(event)
		if err != nil {
			return err
		}
		return h.Any(ctx, ObserveAnyContext{Type: eventType, ObserveContext: ObserveContext[ahp.Event]{Event: event, AdditionalProperties: request.Params.AdditionalProperties, EnvelopeExtras: request.AdditionalProperties}})
	}
	return errMissingHandler
}

// observedEventType reads the discriminator from the validated event union, so
// the catch-all needs no hand-maintained variant table.
func observedEventType(event *ahp.Event) (string, error) {
	raw, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	var discriminator struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &discriminator); err != nil || discriminator.Type == "" {
		return "", errors.New("server: observed event type unavailable")
	}
	return discriminator.Type, nil
}

// WithToolBeforeArguments binds a declared argument type to ToolBefore without
// widening the event or reply types. The codec rejects dropped opaque members.
// Native arguments decode from tool.input. MCP arguments decode from the selected
// tools/call request body supplied by the caller-owned selectedBody resolver.
// The server never fetches descriptors or guesses a body from opaque extras.
func WithToolBeforeArguments[T any](codec interface {
	DecodeJSON(json.RawMessage) (T, error)
}, callback func(context.Context, InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities], T) (ToolBeforeReply, error), selectedBody ...func(context.Context, *ahp.ToolBeforeEvent) (json.RawMessage, error)) func(context.Context, InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities]) (ToolBeforeReply, error) {
	return func(ctx context.Context, event InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities]) (ToolBeforeReply, error) {
		if callback == nil || event.Event == nil || event.Event.Tool == nil {
			return ToolBeforeReply{}, errors.New("server: tool arguments unavailable")
		}
		var raw json.RawMessage
		var err error
		switch event.Event.Tool.Origin {
		case ahp.ExecutionEventToolOriginNative:
			raw, err = json.Marshal(event.Event.Tool.Input)
		case ahp.ExecutionEventToolOriginMcp:
			if len(selectedBody) != 1 || selectedBody[0] == nil || !event.Event.Tool.Mcp.Present || event.Event.Tool.Mcp.Value == nil {
				return ToolBeforeReply{}, errors.New("server: selected MCP request body unavailable")
			}
			body, resolveErr := selectedBody[0](ctx, event.Event)
			if resolveErr != nil {
				return ToolBeforeReply{}, resolveErr
			}
			var request struct {
				Method string `json:"method"`
				Params struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"`
				} `json:"params"`
			}
			if json.Unmarshal(body, &request) != nil || request.Method != "tools/call" || request.Params.Name != event.Event.Tool.Mcp.Value.ToolName {
				return ToolBeforeReply{}, errors.New("server: MCP request does not match event")
			}
			raw = request.Params.Arguments
			var object map[string]json.RawMessage
			if json.Unmarshal(raw, &object) != nil || object == nil {
				return ToolBeforeReply{}, errors.New("server: MCP arguments unavailable")
			}
		default:
			return ToolBeforeReply{}, errors.New("server: unsupported tool origin")
		}
		if err != nil {
			return ToolBeforeReply{}, err
		}
		arguments, err := codec.DecodeJSON(raw)
		if err != nil {
			return ToolBeforeReply{}, err
		}
		return callback(ctx, event, arguments)
	}
}

func orderedEffects[E any](effects []*E) ahp.Optional[[]*E] {
	if effects == nil {
		effects = []*E{}
	}
	return ahp.Some(effects)
}
