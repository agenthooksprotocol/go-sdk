package interop

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestRuntimeDraftAtomicEffects(t *testing.T) {
	for _, effect := range []Object{
		{"type": "message", "text": "bad", "future": true},
		{"type": "future"},
		{"type": "modify", "target": "input", "operation": "future", "value": Object{"task": float64(3)}},
	} {
		req := request("atomic-extension")
		before := clone(req)
		caps := obj(obj(req["params"])["capabilities"])
		caps["effects"] = append(array(caps["effects"]), "future")
		obj(obj(caps["modify"])["input"])["future"] = true
		before = clone(req)
		state, err := Apply(req, response("atomic-extension", Object{"type": "modify", "target": "input", "operation": "merge", "value": Object{"task": float64(2)}}, effect))
		if err == nil || state != nil || !reflect.DeepEqual(req, before) {
			t.Fatalf("effect %v committed: %v, %v", effect, state, err)
		}
	}
	req := request("optional-instruction")
	obj(req["params"])["capabilities"] = clone(Capabilities())
	state, err := Apply(req, response("optional-instruction", Object{"type": "flow", "operation": "continue"}))
	if err != nil || state["flow"] != "continue" || len(array(state["continuationInstructions"])) != 0 || state["continuationRemaining"] != float64(3) {
		t.Fatalf("optional instruction: %v, %v", state, err)
	}
	if _, err := Apply(req, response("optional-instruction", Object{"type": "flow", "operation": "continue", "instruction": ""})); err == nil {
		t.Fatal("empty recognized instruction accepted")
	}
}

func TestRuntimeDraftUnknownFields(t *testing.T) {
	v, err := NewValidator(schemaPath(t))
	if err != nil {
		t.Fatal(err)
	}
	req := request("extensions")
	p := obj(req["params"])
	p["future"] = Object{"enabled": true}
	obj(p["state"])["future"] = []any{true}
	obj(p["capabilities"])["future"] = Object{"enabled": true}
	if _, err := v.Validate("intercept-request", wire(req)); err != nil {
		t.Fatal(err)
	}
	obj(p["capabilities"])["effects"] = "invalid"
	if _, err := v.Validate("intercept-request", wire(req)); err == nil {
		t.Fatal("invalid recognized capability accepted")
	}
	var config Config
	if err := json.Unmarshal([]byte(`{"future":true,"auth":{"mode":"bearer","token":"local","future":[]}}`), &config); err != nil || config.Auth.Token != "local" {
		t.Fatal(config, err)
	}
	if err := json.Unmarshal([]byte(`{"auth":{"token":false}}`), &config); err == nil {
		t.Fatal("invalid recognized auth field accepted")
	}
	if _, err := ValidateElicitationMode("form", Object{"form": Object{}, "future": false}, "ahp"); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateElicitationMode("form", Object{"form": false}, "ahp"); err == nil {
		t.Fatal("invalid recognized mode accepted")
	}
	if _, err := ProjectContent(Object{}, map[string]string{"default": "metadata", "future": "new-value"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := ProjectContent(Object{}, map[string]string{"default": "new-value"}, false); err == nil {
		t.Fatal("invalid recognized selection accepted")
	}
}

func TestRuntimeDraftObservationIDsStayLocal(t *testing.T) {
	prepared := make(chan string, 2)
	delivered := make(chan Object, 2)
	DispatchObservations(Object{"id": "event", "source": "urn:test", "type": "tool.before"}, []Object{{"id": "called", "mode": "intercept"}, {"id": "remaining", "mode": "intercept"}, {"id": "observer", "mode": "observe"}}, map[string]bool{"called": true}, func(event, sub Object) (Object, error) { prepared <- str(sub["id"]); return event, nil }, func(note Object) error { delivered <- note; return nil })
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case id := <-prepared:
			seen[id] = true
		case <-time.After(time.Second):
			t.Fatal("preparation blocked")
		}
	}
	if seen["called"] || !seen["remaining"] || !seen["observer"] {
		t.Fatal(seen)
	}
	for i := 0; i < 2; i++ {
		select {
		case note := <-delivered:
			p := obj(note["params"])
			if _, ok := p["subscriptionId"]; ok {
				t.Fatal("wire subscription identity", note)
			}
			if len(p) != 2 {
				t.Fatal(note)
			}
		case <-time.After(time.Second):
			t.Fatal("delivery blocked")
		}
	}
}

func TestRuntimeDraftAuthRecognizedClaims(t *testing.T) {
	auth := Auth{Mode: "workload", SigningKey: "test", Issuer: "issuer", Audience: "audience", Purpose: "workload", Clock: 1893456000}
	if !auth.verifyJWT(signed(auth, Object{"future": true})) {
		t.Fatal("unknown JWT claim rejected")
	}
	if auth.verifyJWT(signed(auth, Object{"nbf": "invalid"})) {
		t.Fatal("invalid recognized JWT claim accepted")
	}
}

func TestRuntimeDraftCatalogueReceipt(t *testing.T) {
	v, err := newLifecycleValidator(schemaPath(t))
	if err != nil {
		t.Fatal(err)
	}
	receiver := &lifecycleReceiver{validator: v, changed: make(chan struct{}), uploads: map[string]string{}}
	event := obj(request("catalogue-receipt")["params"])["event"]
	note := Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": event}}
	if _, err := receiver.catalogueDispatch(note); err != nil {
		t.Fatal(err)
	}
	expected := Object{"kind": "observed", "eventId": "catalogue-receipt", "event": clone(event), "message": clone(note)}
	if len(receiver.entries) != 1 || !reflect.DeepEqual(receiver.entries[0], expected) {
		t.Fatalf("noncanonical catalogue receipt: %v", receiver.entries)
	}
}

func TestRuntimeDraftCompactionRejectsUnknownEffectFields(t *testing.T) {
	hook := CompactionHook{Supplier: "local", FailurePolicy: "fail-open", Run: func(Object) ([]Object, error) {
		return []Object{
			{"type": "modify", "target": "instructions", "operation": "replace", "value": "must not commit"},
			{"type": "message", "text": "must not commit", "future": true},
		}, nil
	}}
	state, err := RunCompaction("original", "summary", []CompactionHook{hook}, nil, nil, false)
	if err != nil || state["instructions"] != "original" || len(array(state["messages"])) != 0 || len(array(state["failures"])) != 1 {
		t.Fatal(state, err)
	}
}

func TestRuntimeDraftCanonicalRequestCorrelation(t *testing.T) {
	v, err := NewValidator(schemaPath(t))
	if err != nil {
		t.Fatal(err)
	}
	req := request("event-identity")
	req["id"] = "rpc-identity"
	if _, err := v.Validate("intercept-request", wire(req)); err == nil {
		t.Fatal("mismatched request/event IDs accepted")
	}
	req["id"] = "event-identity"
	if _, err := v.Validate("intercept-request", wire(req)); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(req, response("event-identity", Object{"type": "message", "text": "accepted"})); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(req, response("other-request", Object{"type": "message", "text": "rejected"})); err == nil {
		t.Fatal("mismatched response ID accepted")
	}
}
