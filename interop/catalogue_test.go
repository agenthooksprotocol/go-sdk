package interop

import "testing"

func TestCatalogueManifest(t *testing.T) {
	v, e := NewValidator(schemaPath(t))
	if e != nil {
		t.Fatal(e)
	}
	response := Object{"jsonrpc": "2.0", "id": "discovery", "result": Object{"protocolVersion": "draft", "manifest": catalogueManifest()}}
	if e = v.schemas["capabilities-response"].Validate(clone(response)); e != nil {
		t.Fatal(e)
	}
	if _, e = v.Validate("capabilities-response", wire(response)); e != nil {
		t.Fatal(e)
	}
}

func TestCatalogueWireFixtures(t *testing.T) {
	v, e := newLifecycleValidator(schemaPath(t))
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range catalogueEvents {
		t.Run(kind, func(t *testing.T) {
			var message Object
			path := "../../agent-hooks-protocol/fixtures/draft/http/catalogue-" + kind + ".valid.json"
			if kind == "tool.after" {
				path = "../../agent-hooks-protocol/fixtures/draft/http/observe-tool-after.valid.json"
			}
			if kind == "tool.before" {
				message = Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": obj(request("typed-tool")["params"])["event"]}}
			} else if e := Load(path, &message); e != nil {
				t.Fatal(e)
			}
			if e := v.validate("observe", message); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestCatalogueRegistrationEnforcement(t *testing.T) {
	v, e := NewValidator(schemaPath(t))
	if e != nil {
		t.Fatal(e)
	}
	manifest := obj(clone(catalogueManifest()))
	registration := Object{"protocolVersion": "draft", "hooks": []any{Object{"id": "com.example.go-test", "transport": Object{"type": "http", "url": "https://policy.example.invalid/hooks"}, "subscriptions": []any{Object{"events": []any{"tool.before"}, "mode": "intercept", "timeoutMs": float64(500), "failurePolicy": "fail-closed", "content": Object{"default": "metadata"}}}}}}
	context := Object{"interactive": true, "environment": Object{}}
	requirement := Object{"event": "tool.before", "mode": "intercept", "effects": []any{"modify"}, "modify": Object{"input": Object{"merge": true}}}
	if e := validateRegistration(v, registration, manifest, []any{requirement}, context); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []string{"duplicate", "event", "mode", "modify", "ask", "auth", "scope", "failurePolicy", "content", "contentDefault"} {
		t.Run(tc, func(t *testing.T) {
			doc := obj(clone(registration))
			ctx := obj(clone(context))
			req := obj(clone(requirement))
			backend := obj(array(doc["hooks"])[0])
			sub := obj(array(backend["subscriptions"])[0])
			switch tc {
			case "duplicate":
				doc["hooks"] = append(array(doc["hooks"]), clone(backend))
			case "event":
				sub["events"] = []any{"hook.failure"}
			case "mode":
				sub["events"] = []any{"model.error"}
			case "modify":
				req["modify"] = Object{"workspace": Object{"replace": true}}
			case "ask":
				req["effects"] = []any{"ask"}
				ctx["interactive"] = false
			case "auth":
				backend["authentication"] = Object{"type": "bearer", "tokenEnv": "MISSING_CREDENTIAL"}
			case "scope":
				sub["scope"] = "managed"
				sub["disableable"] = false
			case "failurePolicy":
				delete(sub, "failurePolicy")
			case "content":
				delete(sub, "content")
			case "contentDefault":
				delete(obj(sub["content"]), "default")
			}
			if e := validateRegistration(v, doc, manifest, []any{req}, ctx); e == nil {
				t.Fatal("unsupported registration accepted")
			}
		})
	}
	wildcard := obj(clone(registration))
	wildSub := obj(array(obj(array(wildcard["hooks"])[0])["subscriptions"])[0])
	wildSub["events"] = []any{"model.*"}
	wildSub["mode"] = "observe"
	delete(wildSub, "timeoutMs")
	delete(wildSub, "failurePolicy")
	if e := validateRegistration(v, wildcard, manifest, []any{Object{"event": "model.response.after", "mode": "observe"}}, context); e != nil {
		t.Fatal("family wildcard failed", e)
	}
	backend := obj(array(registration["hooks"])[0])
	backend["authentication"] = Object{"type": "bearer", "tokenEnv": "RESOLVED"}
	context["environment"] = Object{"RESOLVED": "test-only-secret"}
	if e := validateRegistration(v, registration, manifest, nil, context); e != nil {
		t.Fatal(e)
	}
}

func TestCatalogueReceiverRejectionDoesNotPoisonLineage(t *testing.T) {
	v, e := newLifecycleValidator(schemaPath(t))
	if e != nil {
		t.Fatal(e)
	}
	receiver := &lifecycleReceiver{suite: "catalogue", validator: v, changed: make(chan struct{}), uploads: map[string]string{}}
	event := Object{"id": "a", "source": "urn:go:catalogue", "type": "task.change.before", "time": "2026-01-01T00:00:00Z", "task": Object{"id": "task", "operation": "update", "change": Object{"status": "working"}}}
	message := Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": event}}
	if _, e := receiver.catalogueDispatch(message); e != nil {
		t.Fatal(e)
	}
	event["id"] = "b"
	event["parentEventId"] = "a"
	event["type"] = "task.change.after"
	obj(event["task"])["id"] = "wrong"
	if _, e := receiver.catalogueDispatch(message); e == nil {
		t.Fatal("mismatched proposal accepted")
	}
	obj(event["task"])["id"] = "task"
	if _, e := receiver.catalogueDispatch(message); e != nil {
		t.Fatal("rejected edge mutated lineage", e)
	}
	bad := obj(clone(message))
	delete(obj(obj(bad["params"])["event"]), "task")
	if _, e := receiver.catalogueDispatch(bad); e == nil {
		t.Fatal("untyped payload accepted")
	}
	if len(receiver.entries) != 4 {
		t.Fatal("missing delivery/rejection evidence")
	}
	for _, index := range []int{1, 3} {
		receipt := obj(receiver.entries[index])
		if receipt["kind"] != "rejected" || receipt["message"] == nil {
			t.Fatal(receipt)
		}
	}
}

func TestReviewedExecutionWire(t *testing.T) {
	v, e := newLifecycleValidator(schemaPath(t))
	if e != nil {
		t.Fatal(e)
	}
	req := request("synthesized")
	event := obj(obj(req["params"])["event"])
	event["synthesized"] = true
	obj(event["call"])["synthesized"] = true
	if e = v.validate("intercept-request", req); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"turn.progress", "tool.progress", "context.compact.after", "model.response.after"} {
		t.Run(kind, func(t *testing.T) {
			var notification Object
			if e := Load("../../agent-hooks-protocol/fixtures/draft/http/catalogue-"+kind+".valid.json", &notification); e != nil {
				t.Fatal(e)
			}
			if e := v.validate("observe", notification); e != nil {
				t.Fatal(e)
			}
			event := obj(obj(notification["params"])["event"])
			if kind == "model.response.after" {
				req := Object{"jsonrpc": "2.0", "id": event["id"], "method": "hooks/intercept", "params": Object{"protocolVersion": "draft", "event": event, "capabilities": Object{"effects": []any{"message"}}}}
				if e := v.validate("intercept-request", req); e != nil {
					t.Fatal(e)
				}
			} else {
				field := map[string]string{"turn.progress": "delta", "tool.progress": "partialOutput", "context.compact.after": "summary"}[kind]
				delete(obj(event[field]), "role")
				if e := v.validate("observe", notification); e == nil {
					t.Fatal("missing model-visible role accepted")
				}
			}
		})
	}
}

func TestContentReferenceHashExactFormat(t *testing.T) {
	v, e := newLifecycleValidator(schemaPath(t))
	if e != nil {
		t.Fatal(e)
	}
	good := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	item := Object{"id": "i", "kind": "text", "mediaType": "text/plain", "selection": "body", "body": Object{"ref": "r", "size": float64(0), "sha256": good}}
	if e := v.item.Validate(item); e != nil {
		t.Fatal(e)
	}
	for _, hash := range []string{good + "\n", good[:63], "G" + good[1:]} {
		obj(item["body"])["sha256"] = hash
		if e := v.item.Validate(item); e == nil {
			t.Fatal("malformed hash accepted")
		}
	}
}
