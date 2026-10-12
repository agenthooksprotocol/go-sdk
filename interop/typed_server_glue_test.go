package interop

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/server"
)

func TestTypedFixtureGluePreservesInterceptWire(t *testing.T) {
	message := request("typed-glue")
	message["futureEnvelope"] = Object{"keep": true}
	params := obj(message["params"])
	params["futureParams"] = []any{"keep", nil}
	params["extensions"] = Object{"vendor.example": Object{"nested": true}}
	obj(params["state"])["futureState"] = Object{"keep": "state"}
	obj(params["event"])["futureEvent"] = Object{"keep": "event"}
	obj(params["capabilities"])["futureGrant"] = Object{"keep": "grant"}
	first := Object{"type": "message", "text": "first"}
	second := Object{"type": "message", "text": "second"}
	result := Object{"protocolVersion": "draft", "effects": []any{first, second}, "extensions": Object{"vendor.example": Object{"nested": true}}, "futureResult": Object{"keep": "result"}}
	called := false
	handlers := fixtureInterceptHandlers(func(_ context.Context, got Object) (Object, error) {
		called = true
		if !reflect.DeepEqual(got, message) {
			t.Errorf("fixture request changed:\n got %s\nwant %s", jsonBytes(got), jsonBytes(message))
		}
		return Object{"jsonrpc": "2.0", "id": message["id"], "result": result, "futureReplyEnvelope": Object{"keep": true}}, nil
	})
	h, err := newFixtureHandler(server.Handlers{Intercept: handlers})
	if err != nil {
		t.Fatal(err)
	}
	w := publicLifecycleCall(t, h, message)
	if !called {
		t.Fatalf("callback not entered: %d %s", w.Code, w.Body.String())
	}
	var reply Object
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || reply["id"] != message["id"] || !reflect.DeepEqual(reply["futureReplyEnvelope"], Object{"keep": true}) || !reflect.DeepEqual(reply["result"], result) {
		t.Fatalf("fixture reply changed: %d %s", w.Code, w.Body.String())
	}
}

func TestTypedFixtureGluePreservesObservationWire(t *testing.T) {
	message := publicLifecycleObservation("typed-glue-observe")
	message["futureEnvelope"] = Object{"keep": true}
	params := obj(message["params"])
	params["futureParams"] = []any{"keep", nil}
	// The observation schema has no state/extensions fields. Keep them as extras.
	params["state"] = Object{"opaque": true}
	params["extensions"] = nil
	obj(params["event"])["futureEvent"] = Object{"keep": "event"}
	called := false
	h, err := newFixtureHandler(server.Handlers{Observe: fixtureObserveHandlers(func(_ context.Context, got Object) error {
		called = true
		if !reflect.DeepEqual(got, message) {
			t.Errorf("fixture observation changed:\n got %s\nwant %s", jsonBytes(got), jsonBytes(message))
		}
		return nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	w := publicLifecycleCall(t, h, message)
	if !called || w.Code != 204 || w.Body.Len() != 0 {
		t.Fatalf("notification result: entered=%v %d %s", called, w.Code, w.Body.String())
	}
}

// The canonical effect schema currently rejects extra message-effect members at
// publication. The private bridge must nevertheless retain them, not silently
// sanitize a fixture into a schema-valid response.
func TestTypedFixtureGluePreservesEffectExtras(t *testing.T) {
	effects := []any{Object{"type": "message", "text": "first", "futureEffect": Object{"keep": true}}, Object{"type": "message", "text": "second"}}
	reply, err := fixtureIntercept[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities, ahp.ToolBeforeEffect](context.Background(), server.InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities]{}, func(context.Context, Object) (Object, error) {
		return Object{"result": Object{"protocolVersion": "draft", "effects": effects}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []any
	raw, err := json.Marshal(reply.effects)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, effects) {
		t.Fatalf("effect extras/order changed: %s", raw)
	}
}
