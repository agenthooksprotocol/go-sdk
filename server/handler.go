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

// Handlers receive canonical wire requests. Nil callbacks reject the method.
// Callbacks may run concurrently over HTTP and must cooperate with cancellation.
type Handlers struct {
	Intercept    func(context.Context, ahp.InterceptRequest) (ahp.InterceptResponseResult, error)
	Observe      func(context.Context, ahp.ObserveNotification) error
	Capabilities func(context.Context, ahp.CapabilitiesRequest) (ahp.CapabilitiesResponseResult, error)
}
type Options struct {
	MaxRequestBytes  int64
	MaxResponseBytes int64
}

// NewHandler validates configuration without starting workers or listeners.
// Zero limits select DefaultMaxFrameBytes. Responses are buffered and validated
// before writing. Callback errors and panics are never exposed to peers.
func NewHandler(h Handlers, opts Options) (http.Handler, error) {
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
		rpcError := func(code int, message string) {
			if notify {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
			if int64(len(out)) > opts.MaxResponseBytes {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			send(out)
		}
		defer func() {
			if recover() != nil {
				rpcError(-32004, "Backend internal error")
			}
		}()
		if !utf8.Valid(b) || !json.Valid(b) {
			rpcError(-32700, "Parse error")
			return
		}
		if json.Unmarshal(b, &fields) != nil || fields == nil {
			rpcError(-32600, "Invalid Request")
			return
		}
		var version, method string
		if json.Unmarshal(fields["jsonrpc"], &version) != nil || version != "2.0" || json.Unmarshal(fields["method"], &method) != nil {
			rpcError(-32600, "Invalid Request")
			return
		}
		rawID, hasID := fields["id"]
		if hasID {
			if !canonical("jsonRpcId", rawID) {
				rpcError(-32600, "Invalid Request")
				return
			}
			id = rawID
		}
		notify = !hasID
		if method == "" {
			rpcError(-32600, "Invalid Request")
			return
		}
		var params map[string]json.RawMessage
		if json.Unmarshal(fields["params"], &params) != nil || params == nil {
			rpcError(-32602, "Invalid params")
			return
		}
		if method == "hooks/intercept" || method == "hooks/observe" || method == "hooks/capabilities" {
			var version string
			if json.Unmarshal(params["protocolVersion"], &version) == nil && version != "draft" {
				rpcError(-32001, "Unsupported AHP protocol version")
				return
			}
		}
		var result any
		switch method {
		case "hooks/intercept":
			p := ahp.ParseInterceptRequest(b)
			if !p.OK || !canonical("intercept-request", b) || !validInterceptContext(b) {
				rpcError(-32602, "Invalid params")
				return
			}
			if h.Intercept == nil {
				rpcError(-32601, "Method not found")
				return
			}
			result, err = h.Intercept(r.Context(), p.Value)
		case "hooks/observe":
			p := ahp.ParseObserveNotification(b)
			if !p.OK || !canonical("observe-notification", b) {
				rpcError(-32602, "Invalid params")
				return
			}
			if h.Observe == nil {
				rpcError(-32601, "Method not found")
				return
			}
			err = h.Observe(r.Context(), p.Value)
			// A notification never receives an RPC envelope, even on failure.
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
			return
		case "hooks/capabilities":
			p := ahp.ParseCapabilitiesRequest(b)
			if !p.OK || !canonical("capabilities-request", b) {
				rpcError(-32602, "Invalid params")
				return
			}
			if h.Capabilities == nil {
				rpcError(-32601, "Method not found")
				return
			}
			result, err = h.Capabilities(r.Context(), p.Value)
		default:
			rpcError(-32601, "Method not found")
			return
		}
		if err != nil {
			rpcError(-32004, "Backend internal error")
			return
		}
		out, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
		kind := "intercept-response"
		valid := false
		if method == "hooks/capabilities" {
			kind = "capabilities-response"
			valid = ahp.ParseCapabilitiesResponse(out).OK
		} else {
			valid = ahp.ParseInterceptResponse(out).OK
		}
		if err != nil || !valid || !canonical(kind, out) || (method == "hooks/intercept" && !validEffects(b, out)) || int64(len(out)) > opts.MaxResponseBytes {
			rpcError(-32004, "Backend internal error")
			return
		}
		send(out)
	}), nil
}
