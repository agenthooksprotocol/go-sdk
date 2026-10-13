// Package server adapts AHP callbacks to standard HTTP and owned stdio streams.
// Applications own routing, authentication, admission, persistence and shutdown.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	ahp "github.com/agenthooksprotocol/go-sdk"
	canonicalpkg "github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

// DefaultMaxFrameBytes is the finite HTTP and stdio frame ceiling (4 MiB).
const DefaultMaxFrameBytes int64 = 4 << 20

// wireHandlers is the private validated transport callback seam.
type wireHandlers struct {
	typedIntercept func(context.Context, ahp.InterceptRequest) (any, map[string]json.RawMessage, error)
	Intercept      func(context.Context, ahp.InterceptRequest) (ahp.InterceptResponseResult, error)
	Observe        func(context.Context, ahp.ObserveNotification) error
	Capabilities   func(context.Context, ahp.CapabilitiesRequest) (ahp.CapabilitiesResponseResult, error)
}
type Options struct {
	MaxRequestBytes  int64
	MaxResponseBytes int64
	// Diagnostic, when non-nil, receives conditions the protocol deliberately
	// keeps silent on the wire, such as ErrObserverUnavailable. It must be safe
	// for concurrent use and must not block. Errors never carry payload values.
	Diagnostic func(context.Context, error)
}

// ErrObserverUnavailable is reported to Options.Diagnostic when a valid observe
// notification arrives for an event without a registered observer. The peer
// still receives the silent 204 success the notification contract requires.
var ErrObserverUnavailable = errors.New("server: no observer registered for event")

// interceptEventTypes lists the event types the draft schema admits for
// hooks/intercept. Any other type is answered with -32002 unsupported_event.
var interceptEventTypes = map[string]bool{
	"tool.before": true, "tool.after": true, "session.start": true,
	"config.change.before": true, "turn.start": true, "turn.finish.before": true,
	"model.request.before": true, "model.response.after": true, "model.switch.before": true,
	"tool.permission.request": true, "tool.batch.after": true,
	"context.compact.before": true, "context.compact.after": true,
	"task.change.before": true, "user.elicitation.request": true, "user.elicitation.result": true,
	"user.message.inbound": true, "user.message.outbound": true, "workspace.change.before": true,
}

// JSON-RPC error codes emitted by the handler. AHP reserves -32001..-32004.
const (
	codeParseError         = -32700
	codeInvalidRequest     = -32600
	codeMethodNotFound     = -32601
	codeInvalidParams      = -32602
	codeUnsupportedVersion = -32001
	codeUnsupportedEvent   = -32002
	codeBackendInternal    = -32004
)

// unsupportedInterceptEvent reports whether params.event names a type that
// hooks/intercept cannot carry, so the peer learns the event is unsupported
// rather than malformed.
func unsupportedInterceptEvent(event json.RawMessage) bool {
	var fields struct {
		Type *string `json:"type"`
	}
	if json.Unmarshal(event, &fields) != nil || fields.Type == nil {
		return false
	}
	return !interceptEventTypes[*fields.Type]
}

// newWireHandler validates configuration without starting workers or listeners.
// Zero limits select DefaultMaxFrameBytes. Responses are buffered and validated
// before writing. Callback errors and panics are never exposed to peers.
func newWireHandler(h wireHandlers, opts Options) (http.Handler, error) {
	if opts.MaxRequestBytes < 0 || opts.MaxResponseBytes < 0 {
		return nil, errors.New("server: negative frame limit")
	}
	if opts.MaxRequestBytes == 0 {
		opts.MaxRequestBytes = DefaultMaxFrameBytes
	}
	if opts.MaxResponseBytes == 0 {
		opts.MaxResponseBytes = DefaultMaxFrameBytes
	}
	if opts.MaxResponseBytes < 128 {
		return nil, errors.New("server: response limit must be at least 128 bytes")
	}
	if opts.MaxRequestBytes == int64(^uint64(0)>>1) {
		return nil, errors.New("server: request limit too large")
	}
	if err := canonicalpkg.Load(); err != nil {
		return nil, errors.New("server: canonical schemas unavailable")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		if r.Body == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, opts.MaxRequestBytes+1))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if int64(len(b)) > opts.MaxRequestBytes {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		var fields map[string]json.RawMessage
		var id json.RawMessage = []byte("null")
		notify := false
		send := func(data []byte) { w.Header().Set("Content-Type", "application/json"); _, _ = w.Write(data) }
		diagnostic := func(err error) {
			if opts.Diagnostic != nil {
				opts.Diagnostic(r.Context(), err)
			}
		}
		rpcErrorData := func(code int, message string, data any) {
			if notify {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			body := map[string]any{"code": code, "message": message}
			if data != nil {
				body["data"] = data
			}
			out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": body})
			if int64(len(out)) > opts.MaxResponseBytes {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			send(out)
		}
		rpcError := func(code int, message string) { rpcErrorData(code, message, nil) }
		defer func() {
			if recover() != nil {
				if notify {
					// A failed notification is an empty transport failure, never a reply.
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				rpcError(codeBackendInternal, "Backend internal error")
			}
		}()
		if !utf8.Valid(b) || !json.Valid(b) {
			rpcError(codeParseError, "Parse error")
			return
		}
		if json.Unmarshal(b, &fields) != nil || fields == nil {
			rpcError(codeInvalidRequest, "Invalid Request")
			return
		}
		var version, method string
		if json.Unmarshal(fields["jsonrpc"], &version) != nil || version != "2.0" || json.Unmarshal(fields["method"], &method) != nil {
			rpcError(codeInvalidRequest, "Invalid Request")
			return
		}
		rawID, hasID := fields["id"]
		if hasID {
			if !canonical("jsonRpcId", rawID) {
				rpcError(codeInvalidRequest, "Invalid Request")
				return
			}
			id = rawID
		}
		notify = !hasID
		if method == "" {
			rpcError(codeInvalidRequest, "Invalid Request")
			return
		}
		var params map[string]json.RawMessage
		if json.Unmarshal(fields["params"], &params) != nil || params == nil {
			rpcError(codeInvalidParams, "Invalid params")
			return
		}
		if method == "hooks/intercept" || method == "hooks/observe" || method == "hooks/capabilities" {
			var version string
			if json.Unmarshal(params["protocolVersion"], &version) == nil && version != "draft" {
				rpcErrorData(codeUnsupportedVersion, "Unsupported AHP protocol version", map[string]any{"supported": []string{ahp.ProtocolVersionValue}})
				return
			}
		}
		var envelopeExtras map[string]json.RawMessage
		var result any
		switch method {
		case "hooks/intercept":
			if !notify && unsupportedInterceptEvent(params["event"]) {
				rpcError(codeUnsupportedEvent, "Unsupported event")
				return
			}
			p := ahp.ParseInterceptRequest(b)
			if !p.OK || !canonical("intercept-request", b) || !validInterceptContext(b) {
				rpcError(codeInvalidParams, "Invalid params")
				return
			}
			if h.Intercept == nil && h.typedIntercept == nil {
				rpcError(codeUnsupportedEvent, "Unsupported event")
				return
			}
			if h.typedIntercept != nil {
				ctx := context.WithValue(r.Context(), rawCapabilitiesKey{}, params["capabilities"])
				result, envelopeExtras, err = h.typedIntercept(ctx, p.Value)
			} else {
				result, err = h.Intercept(r.Context(), p.Value)
			}
		case "hooks/observe":
			p := ahp.ParseObserveNotification(b)
			if !p.OK || !canonical("observe-notification", b) {
				rpcError(codeInvalidParams, "Invalid params")
				return
			}
			if h.Observe != nil {
				err = h.Observe(r.Context(), p.Value)
			} else {
				err = errMissingHandler
			}
			// A notification never receives an RPC envelope, even on failure.
			// A missing observer is a silent success, visible only to diagnostics.
			switch {
			case errors.Is(err, errMissingHandler):
				diagnostic(ErrObserverUnavailable)
				w.WriteHeader(http.StatusNoContent)
			case err != nil:
				w.WriteHeader(http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNoContent)
			}
			return
		case "hooks/capabilities":
			p := ahp.ParseCapabilitiesRequest(b)
			if !p.OK || !canonical("capabilities-request", b) {
				rpcError(codeInvalidParams, "Invalid params")
				return
			}
			if h.Capabilities == nil {
				rpcError(codeMethodNotFound, "Method not found")
				return
			}
			result, err = h.Capabilities(r.Context(), p.Value)
		default:
			rpcError(codeMethodNotFound, "Method not found")
			return
		}
		if errors.Is(err, errMissingHandler) {
			// Only intercept dispatch reports a missing per-event handler.
			rpcError(codeUnsupportedEvent, "Unsupported event")
			return
		}
		if err != nil {
			rpcError(codeBackendInternal, "Backend internal error")
			return
		}
		envelope := make(map[string]any, len(envelopeExtras)+3)
		for key, value := range envelopeExtras {
			if key != "error" {
				envelope[key] = value
			}
		}
		envelope["jsonrpc"], envelope["id"], envelope["result"] = "2.0", id, result
		out, err := json.Marshal(envelope)
		kind := "intercept-response"
		valid := false
		if method == "hooks/capabilities" {
			kind = "capabilities-response"
			valid = ahp.ParseCapabilitiesResponse(out).OK
		} else {
			valid = ahp.ParseInterceptResponse(out).OK
		}
		if err != nil || !valid || !canonical(kind, out) || (method == "hooks/intercept" && !validEffects(b, out)) || int64(len(out)) > opts.MaxResponseBytes {
			rpcError(codeBackendInternal, "Backend internal error")
			return
		}
		send(out)
	}), nil
}
