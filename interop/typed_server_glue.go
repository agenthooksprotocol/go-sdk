package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/server"
)

// This glue is private to the dynamic wire fixtures. Every entry point remains
// an event-specific public callback; the fixture engine never becomes a public
// broad callback API.
type fixtureEnvelopeKey struct{}

// Retain correlation independently of typed contexts, which intentionally omit
// JSON-RPC IDs. Only the public server decides whether ingress is accepted.
func newFixtureHandler(callbacks server.Handlers) (http.Handler, error) {
	handler, err := server.NewHandler(callbacks, server.Options{})
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, server.DefaultMaxFrameBytes+1))
		if err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var envelope map[string]json.RawMessage
		_ = json.Unmarshal(body, &envelope)
		handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), fixtureEnvelopeKey{}, envelope)))
	}), nil
}

func fixtureMessage(ctx context.Context, method string, event any, paramsExtras, envelopeExtras map[string]json.RawMessage) (Object, error) {
	params := make(map[string]json.RawMessage, len(paramsExtras)+2)
	for k, v := range paramsExtras {
		params[k] = v
	}
	params["protocolVersion"] = json.RawMessage(`"draft"`)
	raw, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	params["event"] = raw
	envelope := make(map[string]json.RawMessage, len(envelopeExtras)+4)
	for k, v := range envelopeExtras {
		envelope[k] = v
	}
	envelope["jsonrpc"] = json.RawMessage(`"2.0"`)
	envelope["method"], _ = json.Marshal(method)
	original, _ := ctx.Value(fixtureEnvelopeKey{}).(map[string]json.RawMessage)
	if id, ok := original["id"]; ok {
		envelope["id"] = id
	}
	envelope["params"], err = json.Marshal(params)
	if err != nil {
		return nil, err
	}
	raw, err = json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	var message Object
	err = json.Unmarshal(raw, &message)
	return message, err
}

type fixtureReply[F any] struct {
	effects        []*F
	extensions     ahp.Optional[*ahp.Extensions]
	extras         map[string]json.RawMessage
	envelopeExtras map[string]json.RawMessage
}

func fixtureIntercept[E, C, F any](ctx context.Context, request server.InterceptContext[E, C], callback func(context.Context, Object) (Object, error)) (fixtureReply[F], error) {
	var reply fixtureReply[F]
	params := make(map[string]json.RawMessage, len(request.AdditionalProperties)+3)
	for k, v := range request.AdditionalProperties {
		params[k] = v
	}
	raw, err := json.Marshal(request.Capabilities)
	if err != nil {
		return reply, err
	}
	params["capabilities"] = raw
	if request.State.Present {
		params["state"], err = json.Marshal(request.State.Value)
		if err != nil {
			return reply, err
		}
	}
	if request.Extensions.Present {
		params["extensions"], err = json.Marshal(request.Extensions.Value)
		if err != nil {
			return reply, err
		}
	}
	message, err := fixtureMessage(ctx, "hooks/intercept", request.Event, params, request.EnvelopeExtras)
	if err != nil {
		return reply, err
	}
	response, err := callback(ctx, message)
	if err != nil {
		return reply, err
	}
	raw, err = json.Marshal(response["result"])
	if err != nil {
		return reply, err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		return reply, err
	}
	if effects, ok := fields["effects"]; ok {
		if err = json.Unmarshal(effects, &reply.effects); err != nil {
			return reply, err
		}
	}
	if extensions, ok := fields["extensions"]; ok {
		var value *ahp.Extensions
		if err = json.Unmarshal(extensions, &value); err != nil {
			return reply, err
		}
		reply.extensions = ahp.Some(value)
	}
	delete(fields, "effects")
	delete(fields, "extensions")
	delete(fields, "protocolVersion") // The public server supplies this member.
	reply.extras = fields
	raw, err = json.Marshal(response)
	if err != nil {
		return reply, err
	}
	if err = json.Unmarshal(raw, &reply.envelopeExtras); err != nil {
		return reply, err
	}
	for _, key := range []string{"jsonrpc", "id", "result", "error"} {
		delete(reply.envelopeExtras, key)
	}
	return reply, nil
}

func fixtureObserve[E any](ctx context.Context, notification server.ObserveContext[E], callback func(context.Context, Object) error) error {
	message, err := fixtureMessage(ctx, "hooks/observe", notification.Event, notification.AdditionalProperties, notification.EnvelopeExtras)
	if err != nil {
		return err
	}
	return callback(ctx, message)
}

func fixtureInterceptHandlers(callback func(context.Context, Object) (Object, error)) server.InterceptHandlers {
	return server.InterceptHandlers{
		ToolBefore: func(ctx context.Context, request server.InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities]) (server.ToolBeforeReply, error) {
			reply, err := fixtureIntercept[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities, ahp.ToolBeforeEffect](ctx, request, callback)
			return server.ToolBeforeReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		ToolAfter: func(ctx context.Context, request server.InterceptContext[ahp.ToolAfterEvent, ahp.ToolAfterCapabilities]) (server.ToolAfterReply, error) {
			reply, err := fixtureIntercept[ahp.ToolAfterEvent, ahp.ToolAfterCapabilities, ahp.ToolAfterEffect](ctx, request, callback)
			return server.ToolAfterReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		SessionStart: func(ctx context.Context, request server.InterceptContext[ahp.SessionStartEvent, ahp.SessionStartCapabilities]) (server.SessionStartReply, error) {
			reply, err := fixtureIntercept[ahp.SessionStartEvent, ahp.SessionStartCapabilities, ahp.SessionStartEffect](ctx, request, callback)
			return server.SessionStartReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		ConfigChangeBefore: func(ctx context.Context, request server.InterceptContext[ahp.ConfigChangeBeforeEvent, ahp.ConfigChangeBeforeCapabilities]) (server.ConfigChangeBeforeReply, error) {
			reply, err := fixtureIntercept[ahp.ConfigChangeBeforeEvent, ahp.ConfigChangeBeforeCapabilities, ahp.ConfigChangeBeforeEffect](ctx, request, callback)
			return server.ConfigChangeBeforeReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		TurnStart: func(ctx context.Context, request server.InterceptContext[ahp.TurnStartEvent, ahp.TurnStartCapabilities]) (server.TurnStartReply, error) {
			reply, err := fixtureIntercept[ahp.TurnStartEvent, ahp.TurnStartCapabilities, ahp.TurnStartEffect](ctx, request, callback)
			return server.TurnStartReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		TurnFinishBefore: func(ctx context.Context, request server.InterceptContext[ahp.TurnFinishBeforeEvent, ahp.TurnFinishBeforeCapabilities]) (server.TurnFinishBeforeReply, error) {
			reply, err := fixtureIntercept[ahp.TurnFinishBeforeEvent, ahp.TurnFinishBeforeCapabilities, ahp.TurnFinishBeforeEffect](ctx, request, callback)
			return server.TurnFinishBeforeReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		ModelRequestBefore: func(ctx context.Context, request server.InterceptContext[ahp.ModelRequestBeforeEvent, ahp.ModelRequestBeforeCapabilities]) (server.ModelRequestBeforeReply, error) {
			reply, err := fixtureIntercept[ahp.ModelRequestBeforeEvent, ahp.ModelRequestBeforeCapabilities, ahp.ModelRequestBeforeEffect](ctx, request, callback)
			return server.ModelRequestBeforeReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		ModelResponseAfter: func(ctx context.Context, request server.InterceptContext[ahp.ModelResponseAfterEvent, ahp.ModelResponseAfterCapabilities]) (server.ModelResponseAfterReply, error) {
			reply, err := fixtureIntercept[ahp.ModelResponseAfterEvent, ahp.ModelResponseAfterCapabilities, ahp.ModelResponseAfterEffect](ctx, request, callback)
			return server.ModelResponseAfterReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		ModelSwitchBefore: func(ctx context.Context, request server.InterceptContext[ahp.ModelSwitchBeforeEvent, ahp.ModelSwitchBeforeCapabilities]) (server.ModelSwitchBeforeReply, error) {
			reply, err := fixtureIntercept[ahp.ModelSwitchBeforeEvent, ahp.ModelSwitchBeforeCapabilities, ahp.ModelSwitchBeforeEffect](ctx, request, callback)
			return server.ModelSwitchBeforeReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		ToolPermissionRequest: func(ctx context.Context, request server.InterceptContext[ahp.ToolPermissionRequestEvent, ahp.ToolPermissionRequestCapabilities]) (server.ToolPermissionRequestReply, error) {
			reply, err := fixtureIntercept[ahp.ToolPermissionRequestEvent, ahp.ToolPermissionRequestCapabilities, ahp.ToolPermissionRequestEffect](ctx, request, callback)
			return server.ToolPermissionRequestReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		ToolBatchAfter: func(ctx context.Context, request server.InterceptContext[ahp.ToolBatchAfterEvent, ahp.ToolBatchAfterCapabilities]) (server.ToolBatchAfterReply, error) {
			reply, err := fixtureIntercept[ahp.ToolBatchAfterEvent, ahp.ToolBatchAfterCapabilities, ahp.ToolBatchAfterEffect](ctx, request, callback)
			return server.ToolBatchAfterReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		ContextCompactBefore: func(ctx context.Context, request server.InterceptContext[ahp.ContextCompactBeforeEvent, ahp.ContextCompactBeforeCapabilities]) (server.ContextCompactBeforeReply, error) {
			reply, err := fixtureIntercept[ahp.ContextCompactBeforeEvent, ahp.ContextCompactBeforeCapabilities, ahp.ContextCompactBeforeEffect](ctx, request, callback)
			return server.ContextCompactBeforeReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		ContextCompactAfter: func(ctx context.Context, request server.InterceptContext[ahp.ContextCompactAfterEvent, ahp.ContextCompactAfterCapabilities]) (server.ContextCompactAfterReply, error) {
			reply, err := fixtureIntercept[ahp.ContextCompactAfterEvent, ahp.ContextCompactAfterCapabilities, ahp.ContextCompactAfterEffect](ctx, request, callback)
			return server.ContextCompactAfterReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		TaskChangeBefore: func(ctx context.Context, request server.InterceptContext[ahp.TaskChangeBeforeEvent, ahp.TaskChangeBeforeCapabilities]) (server.TaskChangeBeforeReply, error) {
			reply, err := fixtureIntercept[ahp.TaskChangeBeforeEvent, ahp.TaskChangeBeforeCapabilities, ahp.TaskChangeBeforeEffect](ctx, request, callback)
			return server.TaskChangeBeforeReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		UserElicitationRequest: func(ctx context.Context, request server.InterceptContext[ahp.UserElicitationRequestEvent, ahp.UserElicitationRequestCapabilities]) (server.UserElicitationRequestReply, error) {
			reply, err := fixtureIntercept[ahp.UserElicitationRequestEvent, ahp.UserElicitationRequestCapabilities, ahp.UserElicitationRequestEffect](ctx, request, callback)
			return server.UserElicitationRequestReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		UserElicitationResult: func(ctx context.Context, request server.InterceptContext[ahp.UserElicitationResultEvent, ahp.UserElicitationResultCapabilities]) (server.UserElicitationResultReply, error) {
			reply, err := fixtureIntercept[ahp.UserElicitationResultEvent, ahp.UserElicitationResultCapabilities, ahp.UserElicitationResultEffect](ctx, request, callback)
			return server.UserElicitationResultReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		UserMessageInbound: func(ctx context.Context, request server.InterceptContext[ahp.UserMessageInboundEvent, ahp.UserMessageInboundCapabilities]) (server.UserMessageInboundReply, error) {
			reply, err := fixtureIntercept[ahp.UserMessageInboundEvent, ahp.UserMessageInboundCapabilities, ahp.UserMessageInboundEffect](ctx, request, callback)
			return server.UserMessageInboundReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		UserMessageOutbound: func(ctx context.Context, request server.InterceptContext[ahp.UserMessageOutboundEvent, ahp.UserMessageOutboundCapabilities]) (server.UserMessageOutboundReply, error) {
			reply, err := fixtureIntercept[ahp.UserMessageOutboundEvent, ahp.UserMessageOutboundCapabilities, ahp.UserMessageOutboundEffect](ctx, request, callback)
			return server.UserMessageOutboundReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
		WorkspaceChangeBefore: func(ctx context.Context, request server.InterceptContext[ahp.WorkspaceChangeBeforeEvent, ahp.WorkspaceChangeBeforeCapabilities]) (server.WorkspaceChangeBeforeReply, error) {
			reply, err := fixtureIntercept[ahp.WorkspaceChangeBeforeEvent, ahp.WorkspaceChangeBeforeCapabilities, ahp.WorkspaceChangeBeforeEffect](ctx, request, callback)
			return server.WorkspaceChangeBeforeReply{Effects: reply.effects, Extensions: reply.extensions, AdditionalProperties: reply.extras, EnvelopeExtras: reply.envelopeExtras}, err
		},
	}
}

func fixtureObserveHandlers(callback func(context.Context, Object) error) server.ObserveHandlers {
	return server.ObserveHandlers{
		ToolBefore: func(ctx context.Context, notification server.ObserveContext[ahp.ToolBeforeEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ToolAfter: func(ctx context.Context, notification server.ObserveContext[ahp.ToolAfterEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		SessionStart: func(ctx context.Context, notification server.ObserveContext[ahp.SessionStartEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		SessionEnd: func(ctx context.Context, notification server.ObserveContext[ahp.SessionEndEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ConfigChangeBefore: func(ctx context.Context, notification server.ObserveContext[ahp.ConfigChangeBeforeEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ConfigChangeAfter: func(ctx context.Context, notification server.ObserveContext[ahp.ConfigChangeAfterEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		TurnStart: func(ctx context.Context, notification server.ObserveContext[ahp.TurnStartEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		TurnFinishBefore: func(ctx context.Context, notification server.ObserveContext[ahp.TurnFinishBeforeEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		TurnEnd: func(ctx context.Context, notification server.ObserveContext[ahp.TurnEndEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		TurnProgress: func(ctx context.Context, notification server.ObserveContext[ahp.TurnProgressEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ModelRequestBefore: func(ctx context.Context, notification server.ObserveContext[ahp.ModelRequestBeforeEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ModelResponseAfter: func(ctx context.Context, notification server.ObserveContext[ahp.ModelResponseAfterEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ModelError: func(ctx context.Context, notification server.ObserveContext[ahp.ModelErrorEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ModelSwitchBefore: func(ctx context.Context, notification server.ObserveContext[ahp.ModelSwitchBeforeEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ModelSwitchAfter: func(ctx context.Context, notification server.ObserveContext[ahp.ModelSwitchAfterEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ToolPermissionRequest: func(ctx context.Context, notification server.ObserveContext[ahp.ToolPermissionRequestEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ToolPermissionResolved: func(ctx context.Context, notification server.ObserveContext[ahp.ToolPermissionResolvedEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ToolProgress: func(ctx context.Context, notification server.ObserveContext[ahp.ToolProgressEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ToolBatchAfter: func(ctx context.Context, notification server.ObserveContext[ahp.ToolBatchAfterEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ContextCompactBefore: func(ctx context.Context, notification server.ObserveContext[ahp.ContextCompactBeforeEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		ContextCompactAfter: func(ctx context.Context, notification server.ObserveContext[ahp.ContextCompactAfterEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		TaskChangeBefore: func(ctx context.Context, notification server.ObserveContext[ahp.TaskChangeBeforeEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		TaskChangeAfter: func(ctx context.Context, notification server.ObserveContext[ahp.TaskChangeAfterEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		UserAttention: func(ctx context.Context, notification server.ObserveContext[ahp.UserAttentionEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		UserElicitationRequest: func(ctx context.Context, notification server.ObserveContext[ahp.UserElicitationRequestEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		UserElicitationResult: func(ctx context.Context, notification server.ObserveContext[ahp.UserElicitationResultEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		UserMessageInbound: func(ctx context.Context, notification server.ObserveContext[ahp.UserMessageInboundEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		UserMessageOutbound: func(ctx context.Context, notification server.ObserveContext[ahp.UserMessageOutboundEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		WorkspaceChangeBefore: func(ctx context.Context, notification server.ObserveContext[ahp.WorkspaceChangeBeforeEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		WorkspaceChangeAfter: func(ctx context.Context, notification server.ObserveContext[ahp.WorkspaceChangeAfterEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		FileChanged: func(ctx context.Context, notification server.ObserveContext[ahp.FileChangedEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
		HookFailure: func(ctx context.Context, notification server.ObserveContext[ahp.HookFailureEvent]) error {
			return fixtureObserve(ctx, notification, callback)
		},
	}
}
