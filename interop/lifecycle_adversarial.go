package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/server"
)

// These exact cancellation schedules deliberately return an ungranted
// flow.continue to probe cancellation before publication. Ordinary callbacks
// still reject it. The public handler validates ingress; only these configured
// adversarial responses have raw egress.
func (s *lifecycleReceiver) withAdversarialLifecycleReply(ordinary http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, server.DefaultMaxFrameBytes+1))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var message Object
		_ = json.Unmarshal(body, &message)
		if !s.adversarialCancellationReply(message) && !s.adversarialFailurePolicyReply(message) {
			ordinary.ServeHTTP(w, r)
			return
		}
		// A request-only public acceptance probe. Its empty success is never sent:
		// the separately scheduled raw response below is the adversarial wire data.
		accepted := false
		ingress, err := server.NewHandler(server.Handlers{Intercept: func(context.Context, ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
			accepted = true
			var empty ahp.InterceptResponseResult
			err := json.Unmarshal([]byte(`{"protocolVersion":"draft","effects":[]}`), &empty)
			return empty, err
		}}, server.Options{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		checked := httptest.NewRecorder()
		ingress.ServeHTTP(checked, r)
		if !accepted {
			for key, values := range checked.Header() {
				w.Header()[key] = values
			}
			w.WriteHeader(checked.Code)
			_, _ = w.Write(checked.Body.Bytes())
			return
		}
		reply, err := s.acceptedDispatch(r.Context(), message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	})
}

// Keep this allowlist aligned with canonical cancellation controls, not general
// response-validation failures or scenario flags. A known ID alone is insufficient.
func (s *lifecycleReceiver) adversarialCancellationReply(message Object) bool {
	if (s.suite != "" && s.suite != "lifecycle") || message["method"] != "hooks/intercept" {
		return false
	}
	id := str(message["id"])
	switch id {
	case "cancel-before-reply:a", "cancel-after-reply-before-acceptance:a", "cancelled-boundary-observed:a":
	default:
		return false
	}
	params := obj(message["params"])
	if obj(params["event"])["id"] != id {
		return false
	}
	operations := obj(obj(params["capabilities"])["flow"])["operations"]
	if !has(operations, "stop") || has(operations, "continue") {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Canonical cancellation controls have one configured response, not a
	// response sequence with potentially different acceptance semantics.
	if len(s.sequences[lifecycleID(message)]) != 0 {
		return false
	}
	reply := s.responses[lifecycleID(message)]
	if reply["id"] != id {
		return false
	}
	for _, raw := range array(obj(reply["result"])["effects"]) {
		effect := obj(raw)
		if effect["type"] == "flow" && effect["operation"] == "continue" {
			return true
		}
	}
	return false
}

// The first response of these two canonical failure-policy controls must reach
// the client as a schema-valid, ungranted effect. Replacing it with a JSON-RPC
// error aborts the Rust stdio router, preventing fail-open's next intercept.
// Later sequence responses and every other ID retain public response checking.
func (s *lifecycleReceiver) adversarialFailurePolicyReply(message Object) bool {
	if (s.suite != "" && s.suite != "lifecycle") || message["method"] != "hooks/intercept" {
		return false
	}
	id := str(message["id"])
	if id != "observation-chain-fail-open" && id != "observation-chain-fail-closed" {
		return false
	}
	params := obj(message["params"])
	if obj(params["event"])["id"] != id || has(obj(params["capabilities"])["effects"], "return") {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := lifecycleID(message)
	replies := s.sequences[key]
	if s.occurrences[key] != 0 || len(replies) != 2 || replies[0]["id"] != id {
		return false
	}
	effects := array(obj(replies[0]["result"])["effects"])
	if len(effects) != 1 {
		return false
	}
	effect := obj(effects[0])
	value := obj(effect["value"])
	return effect["type"] == "return" && len(value) == 1 && value["unadvertised"] == true
}
