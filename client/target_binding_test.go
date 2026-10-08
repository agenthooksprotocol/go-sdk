package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

func targetTestItem(id, media, raw string) (map[string]any, map[string][]byte) {
	ref := "urn:test:" + id
	item := contentTestItem(map[string]any{"ref": ref})
	item["id"], item["mediaType"], item["selection"] = id, media, "body"
	return item, map[string][]byte{ref: []byte(raw)}
}
func targetTestClient(bodies map[string][]byte) *Client {
	return &Client{opts: Options{Content: ContentOptions{Resolver: func(_ context.Context, ref string) (io.ReadCloser, error) {
		raw, ok := bodies[ref]
		if !ok {
			return nil, fmt.Errorf("unknown reference %s", ref)
		}
		return io.NopCloser(bytes.NewReader(raw)), nil
	}}}}
}
func targetTestCaps(target string) map[string]any {
	return map[string]any{"effects": []any{"modify", "message"}, "modify": map[string]any{target: map[string]any{"replace": true, "merge": true}}}
}
func targetTestPrepare(t *testing.T, event map[string]any, target string, bodies map[string][]byte, binding ModificationTarget) *preparedBoundary {
	t.Helper()
	cfg := interceptConfig{}
	WithModificationTarget(target, binding)(&cfg)
	p, err := targetTestClient(bodies).prepareBoundary(context.Background(), event, targetTestCaps(target), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func targetTestRequest(t *testing.T, event map[string]any, target string) ahp.InterceptRequest {
	t.Helper()
	base := compositionTestRequest(t)
	raw, _ := ahp.EncodeInterceptRequest(base)
	obj := compositionObject(raw)
	params := sdkObj(obj["params"])
	params["event"], params["capabilities"] = event, targetTestCaps(target)
	delete(params, "state")
	parsed := ahp.ParseInterceptRequest(sdkJSON(obj))
	if !parsed.OK {
		t.Fatal(parsed.Diagnostics)
	}
	return parsed.Value
}
func targetTestEvent(t *testing.T, items []any) map[string]any {
	t.Helper()
	raw, _ := ahp.EncodeInterceptRequest(compositionTestRequest(t))
	event := sdkObj(sdkObj(compositionObject(raw)["params"])["event"])
	event["type"], event["outcome"], event["execution"], event["items"] = "tool.after", "ok", map[string]any{"status": "executed"}, items
	return event
}
func targetTestCompose(t *testing.T, event map[string]any, target string, p *preparedBoundary, effects string) *Composition {
	t.Helper()
	out, err := composePrepared(targetTestRequest(t, event, target), compositionTestResponse(t, effects), p)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func targetTestTemplate(t *testing.T, id, media string) ahp.ContentItem {
	t.Helper()
	item, _ := targetTestItem(id, media, "old template bytes")
	var v ahp.ContentItem
	if err := json.Unmarshal(sdkJSON(item), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTargetBindingMappings(t *testing.T) {
	for _, tc := range []struct{ event, target, path string }{
		{"tool.after", "output", "/items"}, {"turn.start", "prompt", "/items"}, {"turn.finish.before", "response", "/items"},
		{"model.request.before", "request", "/items"}, {"model.response.after", "response", "/items"},
		{"user.message.inbound", "prompt", "/message/text"}, {"user.message.outbound", "content", "/message/payload"},
	} {
		t.Run(tc.event, func(t *testing.T) {
			item, bodies := targetTestItem("one", "application/json", ` { "native": 1 } `)
			event := targetTestCanonicalEvent(t, tc.event, []any{item})
			if _, err := targetTestClient(bodies).prepareBoundary(context.Background(), event, targetTestCaps(tc.target), interceptConfig{}); err == nil {
				t.Fatal("ambiguous target admitted without binding")
			}
			for _, suffix := range []string{"", "/0"} {
				p := targetTestPrepare(t, event, tc.target, bodies, ModificationTarget{Path: tc.path + suffix})
				values, err := p.values(event)
				if err != nil {
					t.Fatal(err)
				}
				expected := any(map[string]any{"native": json.Number("1")})
				if suffix == "" {
					expected = []any{expected}
				}
				if !reflect.DeepEqual(values[tc.target], expected) {
					t.Fatalf("%s resolved descriptor instead of body: %#v", suffix, values)
				}
				replacement := any(map[string]any{"changed": true})
				if suffix == "" {
					replacement = []any{replacement}
				}
				effects := string(sdkJSON([]any{map[string]any{"type": "modify", "target": tc.target, "operation": "replace", "value": replacement}}))
				out := targetTestCompose(t, event, tc.target, p, effects)
				path := tc.path + "/0"
				changed := preparedAt(compositionObject(out.Event), path)
				ref := compositionString(sdkObj(changed["body"])["ref"])
				if !compositionEqual(compositionObject(out.prepared.bodies[ref]), map[string]any{"changed": true}) {
					t.Fatalf("wrong canonical body changed: %s", path)
				}
			}
		})
	}
	for _, tc := range []struct{ event, target, path string }{{"context.compact.before", "instructions", "/instructions"}, {"context.compact.after", "summary", "/summary"}, {"user.elicitation.result", "content", "/elicitation/result"}} {
		paths, err := preparedItemPaths(map[string]any{"type": tc.event}, tc.target)
		if err != nil || !reflect.DeepEqual(paths, []string{tc.path}) {
			t.Fatalf("fixed mapping %s: %v %v", tc.event, paths, err)
		}
	}
}

func TestTargetScalarMergeAndExactUntouchedBytes(t *testing.T) {
	original := " { \"keep\": 1, \"nested\": {\"old\": true} }\n"
	item, bodies := targetTestItem("one", "application/json", original)
	event := targetTestEvent(t, []any{item})
	p := targetTestPrepare(t, event, "output", bodies, ModificationTarget{Path: "/items/0"})
	for _, effects := range []string{`[]`, `[{"type":"modify","target":"output","operation":"replace","value":{"keep":1,"nested":{"old":true}}}]`} {
		out := targetTestCompose(t, event, "output", p, effects)
		if !reflect.DeepEqual(out.prepared.bodies, p.bodies) {
			t.Fatal("unchanged semantic value rewrote exact JSON bytes")
		}
		if !compositionEqual(compositionObject(out.Event), compositionObject(sdkJSON(event))) {
			t.Fatal("unchanged event descriptor was rewritten")
		}
	}
	out := targetTestCompose(t, event, "output", p, `[{"type":"modify","target":"output","operation":"merge","value":{"nested":{"new":2},"literal":null}}]`)
	expected := compositionObject([]byte(`{"keep":1,"nested":{"new":2},"literal":null}`))
	if !compositionEqual(compositionObject(out.EffectiveValues["output"]), expected) {
		t.Fatalf("merge used descriptor: %s", out.EffectiveValues["output"])
	}
	changed := preparedAt(compositionObject(out.Event), "/items/0")
	ref := compositionString(sdkObj(changed["body"])["ref"])
	if !compositionEqual(compositionObject(out.prepared.bodies[ref]), expected) {
		t.Fatal("effective body not updated")
	}
	if changed["id"] != item["id"] || changed["mediaType"] != item["mediaType"] {
		t.Fatal("host descriptor identity lost")
	}
	if string(p.bodies["urn:test:one"]) != original {
		t.Fatal("caller prepared store mutated")
	}
	text, textBodies := targetTestItem("text", "text/plain", "before")
	textEvent := targetTestEvent(t, []any{text})
	textP := targetTestPrepare(t, textEvent, "output", textBodies, ModificationTarget{Path: "/items/0"})
	textOut := targetTestCompose(t, textEvent, "output", textP, `[{"type":"modify","target":"output","operation":"replace","value":"after"}]`)
	if string(textOut.EffectiveValues["output"]) != `"after"` {
		t.Fatal("scalar string replacement failed")
	}
}

func TestTargetCollectionAddRemoveAndRollback(t *testing.T) {
	item, bodies := targetTestItem("one", "application/json", `{"n":1}`)
	event := targetTestEvent(t, []any{item})
	binding := ModificationTarget{Path: "/items", Templates: []ahp.ContentItem{targetTestTemplate(t, "unused", "application/json"), targetTestTemplate(t, "added", "text/plain")}}
	p := targetTestPrepare(t, event, "output", bodies, binding)
	out := targetTestCompose(t, event, "output", p, `[{"type":"modify","target":"output","operation":"replace","value":[{"n":2},"new"]}]`)
	gotEvent := compositionObject(out.Event)
	items := sdkArray(gotEvent["items"])
	if len(items) != 2 || sdkObj(items[0])["id"] != "one" || sdkObj(items[1])["id"] != "added" {
		t.Fatalf("wrong host templates: %#v", items)
	}
	addedRef := compositionString(sdkObj(sdkObj(items[1])["body"])["ref"])
	if string(out.prepared.bodies[addedRef]) != "new" {
		t.Fatal("template body reused instead of new bytes")
	}
	removed := targetTestCompose(t, gotEvent, "output", out.prepared, `[{"type":"modify","target":"output","operation":"replace","value":[]}]`)
	if len(sdkArray(compositionObject(removed.Event)["items"])) != 0 || len(removed.prepared.bodies) != 0 || string(removed.EffectiveValues["output"]) != "[]" {
		t.Fatal("empty replacement failed to remove descriptors and bodies")
	}
	for _, tc := range []struct {
		name, effects string
		templates     bool
	}{
		{"singleton-object", `[{"type":"modify","target":"output","operation":"replace","value":{"n":2}}]`, true},
		{"missing-template", `[{"type":"modify","target":"output","operation":"replace","value":[{"n":2},"new"]}]`, false},
		{"wrong-template-body", `[{"type":"modify","target":"output","operation":"replace","value":[{"n":2},{"not":"text"}]}]`, true},
		{"later-invalid-shape", `[{"type":"modify","target":"output","operation":"replace","value":[{"n":2}]},{"type":"message","text":"must not publish"},{"type":"modify","target":"output","operation":"replace","value":null}]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := binding
			if !tc.templates {
				b.Templates = nil
			}
			prepared := targetTestPrepare(t, event, "output", bodies, b)
			beforeEvent := string(sdkJSON(event))
			beforeBodies := string(sdkJSON(prepared.bodies))
			beforeSlots := string(sdkJSON(prepared.slots))
			result, err := composePrepared(targetTestRequest(t, event, "output"), compositionTestResponse(t, tc.effects), prepared)
			if err == nil || result != nil {
				t.Fatal("invalid modification published")
			}
			if string(sdkJSON(event)) != beforeEvent || string(sdkJSON(prepared.bodies)) != beforeBodies || string(sdkJSON(prepared.slots)) != beforeSlots {
				t.Fatal("failed response mutated original event/store")
			}
		})
	}
	// Appending to an empty collection still requires a template at output index zero.
	empty := targetTestEvent(t, []any{})
	emptyP := targetTestPrepare(t, empty, "output", nil, ModificationTarget{Path: "/items", Templates: []ahp.ContentItem{targetTestTemplate(t, "first", "text/plain")}})
	added := targetTestCompose(t, empty, "output", emptyP, `[{"type":"modify","target":"output","operation":"replace","value":["hello"]}]`)
	if len(sdkArray(compositionObject(added.Event)["items"])) != 1 {
		t.Fatal("empty collection append failed")
	}
}

func TestTargetBadPathsRejected(t *testing.T) {
	item, bodies := targetTestItem("one", "application/json", `{}`)
	event := targetTestEvent(t, []any{item})
	for _, path := range []string{"", "items", "/items/-1", "/items/01", "/items/1", "/items/0/body", "/items/0/", "/tool/input", "/message/text", "/params", "/items/+0", "/items/0~1body"} {
		t.Run(path, func(t *testing.T) {
			cfg := interceptConfig{}
			WithModificationTarget("output", ModificationTarget{Path: path})(&cfg)
			if _, err := targetTestClient(bodies).prepareBoundary(context.Background(), event, targetTestCaps("output"), cfg); err == nil {
				t.Fatalf("bad path admitted: %q", path)
			}
		})
	}
	cfg := interceptConfig{}
	WithModificationTarget("output", ModificationTarget{Path: "/items/0", Templates: []ahp.ContentItem{targetTestTemplate(t, "bad", "text/plain")}})(&cfg)
	if _, err := targetTestClient(bodies).prepareBoundary(context.Background(), event, targetTestCaps("output"), cfg); err == nil {
		t.Fatal("scalar binding admitted templates")
	}
}

func TestTargetParamsAndWorkspaceMappings(t *testing.T) {
	event := map[string]any{"type": "model.request.before", "params": map[string]any{"temperature": json.Number("1"), "nested": map[string]any{"old": true}}, "items": []any{}}
	p := targetTestPrepare(t, event, "request", nil, ModificationTarget{Path: "/params"})
	values, err := p.values(event)
	if err != nil || !compositionEqual(values["request"], event["params"]) {
		t.Fatalf("params not resolved: %v %v", values, err)
	}
	replacement := map[string]any{"temperature": json.Number("2")}
	if err := p.apply(event, "request", replacement); err != nil {
		t.Fatal(err)
	}
	if !compositionEqual(event["params"], replacement) || len(p.bodies) != 0 {
		t.Fatal("params replaced as descriptor or retained omitted keys")
	}
	if err := p.apply(event, "request", []any{}); err == nil {
		t.Fatal("params accepted nonobject")
	}
	cfg := interceptConfig{}
	WithModificationTarget("request", ModificationTarget{Path: "/params", Templates: []ahp.ContentItem{targetTestTemplate(t, "bad", "text/plain")}})(&cfg)
	if _, err := targetTestClient(nil).prepareBoundary(context.Background(), event, targetTestCaps("request"), cfg); err == nil {
		t.Fatal("params accepted descriptor templates")
	}
	workspace := map[string]any{"type": "workspace.change.before", "workspace": map[string]any{"kind": "cwd", "change": map[string]any{"cwd": "/old"}, "prior": map[string]any{"cwd": "/prior"}}}
	wp, err := targetTestClient(nil).prepareBoundary(context.Background(), workspace, targetTestCaps("workspace"), interceptConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := wp.apply(workspace, "workspace", map[string]any{"cwd": "/new"}); err != nil {
		t.Fatal(err)
	}
	w := sdkObj(workspace["workspace"])
	if w["kind"] != "cwd" || sdkObj(w["prior"])["cwd"] != "/prior" || sdkObj(w["change"])["cwd"] != "/new" {
		t.Fatalf("workspace mapped beyond change: %#v", w)
	}
}

func targetTestCanonicalEvent(t *testing.T, kind string, items []any) map[string]any {
	t.Helper()
	if kind == "tool.after" {
		return targetTestEvent(t, items)
	}
	event := map[string]any{"id": "test", "source": "urn:test", "time": "2026-01-01T00:00:00Z", "type": kind, "items": items}
	switch kind {
	case "turn.start":
		event["turn"] = map[string]any{"id": "turn"}
		event["trigger"] = "user"
	case "turn.finish.before":
		event["turn"] = map[string]any{"id": "turn"}
		event["outcome"] = "completed"
		event["continuationCount"] = 0
	case "model.request.before", "model.response.after":
		event["model"] = map[string]any{"id": "model", "provider": "test"}
		event["attempt"] = map[string]any{"id": "attempt", "number": 1}
		if kind == "model.request.before" {
			event["params"] = map[string]any{}
		} else {
			event["execution"] = map[string]any{"status": "executed"}
			event["finishReason"] = "stop"
		}
	case "user.message.inbound":
		delete(event, "items")
		event["message"] = map[string]any{"channel": "test", "sender": "user", "text": items}
	case "user.message.outbound":
		delete(event, "items")
		event["message"] = map[string]any{"channel": "test", "payload": items}
	}
	return event
}

func TestTargetParamsCompositionMergeAndReplace(t *testing.T) {
	event := targetTestCanonicalEvent(t, "model.request.before", []any{})
	event["params"] = compositionObject([]byte(`{"temperature":1,"nested":{"old":true},"keep":1}`))
	p := targetTestPrepare(t, event, "request", nil, ModificationTarget{Path: "/params"})
	for _, tc := range []struct{ name, op, value, want string }{
		{"merge", "merge", `{"nested":{"new":2},"literal":null}`, `{"temperature":1,"nested":{"new":2},"keep":1,"literal":null}`},
		{"replace", "replace", `{"temperature":2}`, `{"temperature":2}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := targetTestCompose(t, event, "request", p, `[{"type":"modify","target":"request","operation":"`+tc.op+`","value":`+tc.value+`}]`)
			if !compositionEqual(sdkObj(compositionObject(out.Event)["params"]), compositionObject([]byte(tc.want))) {
				t.Fatalf("params semantics: %s", out.Event)
			}
			if len(out.prepared.bodies) != 0 {
				t.Fatal("params modification invented content bodies")
			}
		})
	}
	result, err := composePrepared(targetTestRequest(t, event, "request"), compositionTestResponse(t, `[{"type":"modify","target":"request","operation":"replace","value":[]}]`), p)
	if err == nil || result != nil {
		t.Fatal("nonobject params replacement accepted")
	}
}
