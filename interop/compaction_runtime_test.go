package interop

import (
	"context"
	"testing"
)

func TestReceiveBoundaryPublicAdmission(t *testing.T) {
	request := Object{"jsonrpc": "2.0", "id": "compact", "method": "hooks/intercept", "params": Object{"protocolVersion": "draft", "event": Object{"id": "compact", "source": "urn:test:host", "time": "2026-09-15T12:00:00Z", "type": "context.compact.before", "trigger": "manual", "items": []any{}}, "capabilities": Object{"effects": []any{"return"}}}}
	called := false
	callback := func(req Object) (Object, error) {
		called = true
		return Object{"result": Object{"protocolVersion": "draft", "effects": []any{Object{"type": "return", "value": "candidate"}}}}, nil
	}
	accepted, err := ReceiveBoundary(context.Background(), request, callback)
	if err != nil || !called || accepted["id"] != "compact" {
		t.Fatalf("accepted=%v called=%v err=%v", accepted, called, err)
	}
	called = false
	bad := obj(clone(request))
	bad["id"] = "wrong"
	if _, err = ReceiveBoundary(context.Background(), bad, callback); err == nil || called {
		t.Fatalf("correlation admitted: called=%v err=%v", called, err)
	}
	called = false
	if _, err = ReceiveBoundary(context.Background(), request, func(Object) (Object, error) {
		called = true
		return Object{"result": Object{"protocolVersion": "draft", "effects": []any{Object{"type": "modify", "target": "summary", "operation": "replace", "value": "wrong"}}}}, nil
	}); err == nil || !called {
		t.Fatalf("ungranted effect accepted: called=%v err=%v", called, err)
	}
}
