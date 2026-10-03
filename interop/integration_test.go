package interop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestBinaryUploadBinding(t *testing.T) {
	t.Setenv("GO_UPLOAD_TOKEN", "upload-only")
	s := &lifecycleReceiver{changed: make(chan struct{}), uploads: map[string]string{}}
	policy := map[string]UploadBinding{"body": {Endpoint: "http://127.0.0.1/exact?scope=1", Auth: &UploadAuth{Type: "bearer", TokenEnv: "GO_UPLOAD_TOKEN"}}, "anonymous": {Endpoint: "http://127.0.0.1/anonymous"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/exact?scope=1" && r.URL.RequestURI() != "/anonymous" {
			w.WriteHeader(404)
			return
		}
		s.upload(w, r, policy)
	}))
	defer server.Close()
	binding := UploadBinding{Endpoint: server.URL + "/exact?scope=1", Auth: policy["body"].Auth}
	body := []byte{0, 255, 128, 'a', 0}
	ref, status, e := UploadContent(context.Background(), binding, "body", "urn:binary", body)
	if e != nil || status != 201 {
		t.Fatalf("%d %v", status, e)
	}
	if e = checkContent(Object{"items": []any{Object{"body": ref}}}, "body", s.uploads); e != nil {
		t.Fatal(e)
	}
	if e = checkContent(Object{"items": []any{Object{"body": ref}}}, "other", s.uploads); e == nil {
		t.Fatal("cross-subscription reference")
	}
	if str(ref["ref"]) == "" || ref["ref"] == "urn:binary" {
		t.Fatal("sender alias used as receiver reference", ref)
	}
	retry, status, e := UploadContent(context.Background(), binding, "body", "urn:binary", body)
	if e != nil || status != 201 {
		t.Fatal("retry", status, e)
	}
	if e = checkContent(Object{"items": []any{Object{"body": retry}}}, "body", s.uploads); e != nil {
		t.Fatal(e)
	}
	changed, status, e := UploadContent(context.Background(), binding, "body", "urn:binary", []byte("changed"))
	if e != nil || status != 201 || changed["ref"] == ref["ref"] || s.uploads[contentKey("body", str(ref["ref"]))] != string(body) {
		t.Fatal("later upload mutated original reference", status, e)
	}
	if _, status, e = UploadContent(context.Background(), binding, "body", "urn:empty", nil); e != nil || status != 201 {
		t.Fatal("zero bytes", status, e)
	}
	anonymous := binding
	anonymous.Auth = nil
	if _, status, _ = UploadContent(context.Background(), anonymous, "body", "x", body); status != 403 {
		t.Fatal("anonymous scope authorized on protected route", status)
	}
	t.Setenv("GO_BAD_UPLOAD_TOKEN", "invalid")
	bad := binding
	bad.Auth = &UploadAuth{Type: "bearer", TokenEnv: "GO_BAD_UPLOAD_TOKEN"}
	if _, status, _ = UploadContent(context.Background(), bad, "body", "x", body); status != 401 {
		t.Fatal("invalid credentials accepted", status)
	}
	// A local alias cannot select or grant an authorization scope.
	aliased, status, e := UploadContent(context.Background(), binding, "unknown", "x", body)
	if e != nil || status != 201 || checkContent(Object{"items": []any{Object{"body": aliased}}}, "unknown", s.uploads) == nil {
		t.Fatal("sender alias changed authorized scope", status, e)
	}
	anonymous.Endpoint = server.URL + "/anonymous"
	if _, status, e = UploadContent(context.Background(), anonymous, "anonymous", "x", body); e != nil || status != 201 {
		t.Fatal("explicit anonymous", status, e)
	}
	// Same-size bad hash, chunked framing, and JSON are rejected, not persisted.
	for _, mode := range []string{"hash", "chunked", "json"} {
		r, _ := http.NewRequest("POST", binding.Endpoint, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/octet-stream")
		r.Header.Set("Authorization", "Bearer upload-only")
		r.Header.Set("AHP-Content-SHA256", fmt.Sprintf("%x", sha256.Sum256(body)))
		if mode == "hash" {
			r.Header.Set("AHP-Content-SHA256", fmt.Sprintf("%x", sha256.Sum256([]byte("wrong"))))
		}
		if mode == "chunked" {
			r.ContentLength = -1
		}
		if mode == "json" {
			r.Header.Set("Content-Type", "application/json")
		}
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 400 {
			t.Fatal(mode, res.StatusCode)
		}
	}
	var leaked bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true; w.WriteHeader(204) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	binding.Endpoint = redirect.URL
	if _, status, _ = UploadContent(context.Background(), binding, "body", "redirect", body); status != 307 || leaked {
		t.Fatal("redirect followed")
	}
}

func TestTaskLineage(t *testing.T) {
	event := func(id, parent, typ, task string) Object {
		e := Object{"id": id, "source": "urn:source", "type": typ, "task": Object{"id": task, "operation": "update", "change": Object{"status": "native-done"}}}
		if parent != "" {
			e["parentEventId"] = parent
		}
		return e
	}
	var l TaskLineage
	if e := l.Accept(event("after", "before", "task.change.after", "task-1")); e != nil {
		t.Fatal(e)
	}
	if e := l.Accept(event("before", "", "task.change.before", "wrong-task")); e == nil {
		t.Fatal("late mismatched proposal")
	}
	if e := l.Accept(event("before", "", "task.change.before", "task-1")); e != nil {
		t.Fatal(e)
	}
	if e := l.Accept(event("before", "after", "task.change.before", "task-1")); e == nil {
		t.Fatal("changed parent")
	}
	var cycle TaskLineage
	if e := cycle.Accept(event("a", "b", "task.change.before", "t")); e != nil {
		t.Fatal(e)
	}
	if e := cycle.Accept(event("b", "a", "task.change.before", "t")); e == nil {
		t.Fatal("late cycle")
	}
	producer := TaskLineage{RequireKnownParents: true}
	if e := producer.Accept(event("a", "missing", "task.change.before", "t")); e == nil {
		t.Fatal("unknown producer parent")
	}
	same := event("same", "", "task.change.after", "t")
	obj(same["task"])["prior"] = clone(obj(same["task"])["change"])
	if e := l.Accept(same); e == nil {
		t.Fatal("no-op actual update")
	}
}

func TestPermissionAndAtomicFailure(t *testing.T) {
	req := obj(clone(request("permission")))
	before := clone(req)
	for _, effects := range [][]any{
		{Object{"type": "allow"}, Object{"type": "ask"}, Object{"type": "deny", "reason": "policy"}},
		{Object{"type": "deny", "reason": "policy"}, Object{"type": "ask"}, Object{"type": "allow"}},
	} {
		state, e := Apply(req, response("permission", effects...))
		if e != nil || state["decision"] != "deny" {
			t.Fatal(state, e)
		}
	}
	bad := response("permission", Object{"type": "message", "text": "not committed"}, Object{"type": "inject", "target": "context", "operation": "append", "deliverAt": "unsupported", "value": "x"})
	if state, e := Apply(req, bad); e == nil || state != nil || !reflect.DeepEqual(before, req) {
		t.Fatal("partial application", state, e)
	}
}

func TestRequiredTypedPayloads(t *testing.T) {
	v, e := newLifecycleValidator(schemaPath(t))
	if e != nil {
		t.Fatal(e)
	}
	req := request("typed")
	if e = v.validate("intercept-request", req); e != nil {
		t.Fatal(e)
	}
	ev := obj(obj(req["params"])["event"])
	for _, field := range []string{"call", "path", "tool"} {
		old := ev[field]
		delete(ev, field)
		if e = v.validate("intercept-request", req); e == nil {
			t.Fatal("missing required", field)
		}
		ev[field] = old
	}
	delete(obj(ev["tool"]), "origin")
	if e = v.validate("intercept-request", req); e == nil {
		t.Fatal("missing tool origin")
	}
	for _, typ := range []string{"task.change.after", "workspace.change.after", "file.changed"} {
		ev := Object{"id": "typed", "source": "urn:source", "time": "2026-01-01T00:00:00Z", "type": typ}
		m := Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": ev}}
		if e = v.validate("observe", m); e == nil {
			t.Fatal("missing typed payload", typ)
		}
	}
}

func TestContentProjection(t *testing.T) {
	event := Object{"items": []any{Object{"id": "reason", "kind": "reasoning", "category": "text", "mediaType": "text/plain", "selection": "body", "body": Object{"ref": "private"}}, Object{"id": "skill", "kind": "skill", "category": "skills", "mediaType": "text/plain", "selection": "body", "body": Object{"ref": "skill"}}}}
	original := clone(event)
	projected, e := ProjectContent(event, map[string]string{"default": "metadata", "reasoning": "omit", "skills": "metadata"}, false)
	if e != nil || len(array(projected["items"])) != 1 || obj(array(projected["items"])[0])["body"] != nil || !reflect.DeepEqual(event, original) {
		t.Fatal(projected, e)
	}
	if _, e = ProjectContent(event, map[string]string{"default": "body"}, false); e == nil {
		t.Fatal("selection conferred permission")
	}
}

// This separately tests the canonical integration contract. Runtime must ALSO
// pass regenerated Go codecs; this is not a fallback around a codec rejection.
func TestCanonicalSettledTypedMessages(t *testing.T) {
	v, e := newLifecycleValidator(schemaPath(t))
	if e != nil {
		t.Fatal(e)
	}
	req := obj(clone(request("canonical")))
	if e = v.core.schemas["intercept-request"].Validate(req); e != nil {
		t.Fatal(e)
	}
	event := obj(obj(req["params"])["event"])
	{
		m := Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": event}}
		if e = v.observe.Validate(m); e != nil {
			t.Fatal(e)
		}
	}
	for _, tc := range []struct {
		kind, field string
		payload     any
	}{
		{"task.change.after", "task", Object{"id": "durable", "operation": "update", "change": Object{"status": "custom-native"}}},
		{"workspace.change.after", "workspace", Object{"kind": "cwd", "change": Object{"cwd": "/new"}}},
		{"file.changed", "changes", []any{Object{"path": "/new/file", "operation": "create", "agentCaused": true}}},
	} {
		ev := Object{"id": "event", "source": "urn:source", "time": "2026-01-01T00:00:00Z", "type": tc.kind, tc.field: tc.payload}
		m := Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": ev}}
		if e = v.observe.Validate(m); e != nil {
			t.Fatal(tc.kind, e)
		}
	}
}

func TestEffectiveOperationRequiresNativePolicy(t *testing.T) {
	req := obj(clone(request("effective")))
	obj(req["params"])["state"] = Object{"permission": "allow", "nativePermission": "ask", "candidate": Object{"value": "stale"}}
	r := response("effective", Object{"type": "modify", "target": "input", "operation": "merge", "value": Object{"task": float64(2)}})
	result, e := Apply(req, r)
	if e != nil || result["decision"] != "ask" || result["executed"] != false || result["result"] != nil {
		t.Fatal(result, e)
	}
	obj(obj(req["params"])["state"])["permission"] = "none"
	result, e = Apply(req, response("effective", Object{"type": "allow"}))
	if e != nil || result["decision"] != "allow" {
		t.Fatal("allow cannot suppress ordinary native prompt", result, e)
	}
	obj(obj(req["params"])["state"])["permission"] = "ask"
	obj(obj(req["params"])["state"])["nativePermission"] = "allow"
	r = response("effective", Object{"type": "allow"}, Object{"type": "modify", "target": "input", "operation": "merge", "value": Object{"task": float64(2)}})
	result, e = Apply(req, r)
	if e != nil || result["decision"] != "ask" {
		t.Fatal("allow erased applicable ask", result, e)
	}
}

// Generated codec coverage remains TestSharedScenarios. This isolates the Go
// evaluator against current canonical wire fixtures while regeneration is owned
// by the schema coordinator; it never substitutes for runtime codec validation.
func TestCanonicalEvaluatorScenarios(t *testing.T) {
	v, e := NewValidator(schemaPath(t))
	if e != nil {
		t.Fatal(e)
	}
	ss, e := scenarios("../../agent-hooks-protocol/interop/scenarios.json")
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range ss {
		t.Run(s.ID, func(t *testing.T) {
			var req, res Object
			if e := json.Unmarshal(s.Request, &req); e != nil {
				t.Fatal(e)
			}
			if e := v.schemas["intercept-request"].Validate(req); e != nil {
				t.Fatal(e)
			}
			e := json.Unmarshal(s.Response, &res)
			if e == nil {
				e = v.schemas["intercept-response"].Validate(res)
			}
			var result Object
			if e == nil {
				result, e = Apply(req, res)
			}
			if s.ExpectError {
				if e == nil {
					t.Fatal("expected rejection")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			for k, want := range s.Expected {
				if !reflect.DeepEqual(result[k], want) {
					t.Fatalf("%s: got %v want %v", k, result[k], want)
				}
			}
		})
	}
}

func TestTaskWorkspaceCapabilities(t *testing.T) {
	validator, e := newLifecycleValidator(schemaPath(t))
	if e != nil {
		t.Fatal(e)
	}
	for _, family := range []string{"task", "workspace"} {
		t.Run(family, func(t *testing.T) {
			payload := Object{"id": "durable-task", "operation": "update", "change": Object{"status": "custom-state"}}
			if family == "workspace" {
				payload = Object{"kind": "cwd", "change": Object{"cwd": "/new"}}
			}
			event := Object{"id": "boundary", "source": "urn:go:test", "time": "2026-01-01T00:00:00Z", "type": family + ".change.before", family: payload}
			req := Object{"jsonrpc": "2.0", "id": "boundary", "method": "hooks/intercept", "params": Object{"protocolVersion": "draft", "event": event, "capabilities": Object{"effects": []any{"deny", "message"}}}}
			if e := validator.validate("intercept-request", req); e != nil {
				t.Fatal(e)
			}
			original := clone(event)
			for _, decision := range []string{"allow", "deny"} {
				res := response("boundary", Object{"type": decision, "reason": "policy"})
				if decision == "allow" {
					res = lifecycleReply("boundary")
				}
				if e := validator.validate("intercept-response", res); e != nil {
					t.Fatal(e)
				}
				state, e := Apply(req, res)
				if e != nil || state["decision"] != decision || state["executed"] != false || !reflect.DeepEqual(event, original) {
					t.Fatal("proposal falsely applied", state, e)
				}
			}
			// No synthetic task/workspace modification or candidate application is
			// advertised. Even forged capability claims cannot invent host support.
			obj(req["params"])["capabilities"] = Capabilities()
			for _, effect := range []Object{
				{"type": "modify", "target": "input", "operation": "merge", "value": Object{"cwd": "/unapproved"}},
				{"type": "modify", "target": "workspace", "operation": "replace", "value": Object{"cwd": "/unapproved"}},
				{"type": "return", "value": Object{"status": "done"}},
			} {
				if state, e := Apply(req, response("boundary", effect)); e == nil || state != nil {
					t.Fatal("unsupported host capability accepted", effect)
				}
			}
		})
	}
}

func TestUploadConfiguredLimits(t *testing.T) {
	max := int64(0)
	binding := UploadBinding{Endpoint: "https://unused.example/bytes", MaxBytes: &max}
	if _, status, e := UploadContent(context.Background(), binding, "s", "r", []byte{1}); e == nil || status != 0 {
		t.Fatal("maxBytes ignored")
	}
}
