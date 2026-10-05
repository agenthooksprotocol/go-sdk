package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/server"
)

// publicHandler mounts real public callbacks. The optional raw writer is used
// only for adversarial stdio fixtures: those must bypass the stdio shim's own
// output-envelope validation, not merely callback-output validation.
func (s *serverState) publicHandler(rawOutput io.Writer) (http.Handler, error) {
	handler, err := server.NewHandler(server.Handlers{
		Intercept: func(ctx context.Context, request ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
			encoded, err := json.Marshal(request)
			if err != nil {
				return ahp.InterceptResponseResult{}, err
			}
			reply, err := s.fixtureIntercept(ctx, encoded)
			if err != nil {
				return ahp.InterceptResponseResult{}, err
			}
			parsed := ahp.ParseInterceptResponse(reply)
			if !parsed.OK {
				return ahp.InterceptResponseResult{}, fmt.Errorf("invalid fixture response")
			}
			return parsed.Value.Result, nil
		},
		Observe: func(ctx context.Context, notification ahp.ObserveNotification) error {
			var message Object
			if err := json.Unmarshal(jsonBytes(notification), &message); err != nil {
				return err
			}
			event := obj(obj(message["params"])["event"])
			if err := checkContent(event, "", nil); err != nil {
				return err
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			s.requests = append(s.requests, Object{"id": event["id"], "method": "hooks/observe", "accepted": true, "message": message})
			return nil
		},
		Capabilities: func(context.Context, ahp.CapabilitiesRequest) (ahp.CapabilitiesResponseResult, error) {
			var result ahp.CapabilitiesResponseResult
			err := json.Unmarshal(jsonBytes(Object{"protocolVersion": "draft", "manifest": fixtureManifest()}), &result)
			return result, err
		},
	}, server.Options{})
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, server.DefaultMaxFrameBytes+1))
		if err != nil || int64(len(body)) > server.DefaultMaxFrameBytes {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		var request Object
		_ = json.Unmarshal(body, &request)
		id := str(obj(obj(request["params"])["event"])["id"])
		if request["method"] == "hooks/intercept" {
			for _, scenario := range s.scenarios {
				if scenario.ID != id || !scenario.ExpectError {
					continue
				}
				reply, err := s.fixtureIntercept(ctx, body)
				if err != nil {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(rpcError(request["id"]))
					return
				}
				if rawOutput != nil {
					frame, err := ndjson(reply)
					if err == nil {
						_, err = rawOutput.Write(frame)
					}
					if err != nil {
						http.Error(w, "raw fixture write failed", http.StatusInternalServerError)
					}
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(reply)
				return
			}
		}
		handler.ServeHTTP(w, r.WithContext(ctx))
	}), nil
}

func fixtureManifest() Object {
	return Object{
		"events":     []any{Object{"event": "tool.before", "modes": []any{"intercept"}, "capabilities": ToolCapabilities()}, Object{"event": "turn.finish.before", "modes": []any{"intercept"}, "capabilities": Object{"effects": []any{"flow", "message"}, "flow": obj(Capabilities()["flow"])}}},
		"gaps":       []any{Object{"path": "events.other", "reason": "Synthetic tool.before and turn.finish.before application only"}},
		"transports": []any{"http", "stdio"}, "authentication": []any{"bearer", "oauth", "workload", "mtls"},
		"toolPaths": []any{"native"}, "contentCategories": []any{}, "limits": Object{"maxContinuations": 4},
		"managedPolicy": Object{"scopes": []any{"user"}, "disableable": true}, "correlationIdentityFields": []any{"event.id", "call.id"},
	}
}
