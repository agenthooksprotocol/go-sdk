package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/internal/ownedcontent"
)

func targetTestItem(id, media, raw string) (map[string]any, map[string][]byte) {
	if strings.HasPrefix(media, "text/") || strings.Contains(media, "json") {
		return targetInlineText(id, raw), map[string][]byte{}
	}
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
	item := targetInlineText(id, "old template bytes")
	if media != "text/plain" {
		item["mediaType"] = media
	}
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
		{"user.message.inbound", "prompt", "/message/messages"}, {"user.message.outbound", "content", "/message/messages"},
	} {
		t.Run(tc.event, func(t *testing.T) {
			messages := []any{targetInlineMessage("one", targetInlineText("part", ` { "native": 1 } `))}
			if tc.event == "user.message.inbound" {
				sdkObj(messages[0])["role"] = "user"
			}
			event := targetTestCanonicalEvent(t, tc.event, messages)
			p := targetInlinePrepare(t, event, tc.target, nil)
			values, err := p.values(event)
			if err != nil || !compositionEqual(values[tc.target], messages) {
				t.Fatalf("canonical list mapping: %#v %v", values, err)
			}
			replacement := []any{targetInlineMessage("changed", targetInlineText("new", "replacement"))}
			if tc.event == "user.message.inbound" {
				sdkObj(replacement[0])["role"] = "user"
			}
			out := targetTestCompose(t, event, tc.target, p, string(sdkJSON([]any{map[string]any{"type": "modify", "target": tc.target, "operation": "replace", "value": replacement}})))
			if !compositionEqual(inlineAt(compositionObject(out.Event), tc.path), replacement) || len(out.prepared.sources) != 0 || len(out.prepared.owned) != 0 {
				t.Fatal("inline modification allocated a body owner", string(out.Event))
			}
			if !compositionEqual(inlineAt(event, tc.path), messages) {
				t.Fatal("host input mutated")
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
	messages := []any{targetInlineMessage("one", targetInlineText("json", original))}
	event := targetTestCanonicalEvent(t, "model.request.before", messages)
	p := targetInlinePrepare(t, event, "request", nil)
	for _, operation := range []string{"none", "replace"} {
		effects := `[]`
		if operation == "replace" {
			effects = string(sdkJSON([]any{map[string]any{"type": "modify", "target": "request", "operation": "replace", "value": messages}}))
		}
		out := targetTestCompose(t, event, "request", p, effects)
		part := sdkObj(sdkArray(sdkObj(sdkArray(compositionObject(out.Event)["items"])[0])["parts"])[0])
		if part["text"] != original || part["body"] != nil || len(out.prepared.sources) != 0 || len(out.prepared.owned) != 0 {
			t.Fatal("exact inline JSON rewritten or snapshotted", part)
		}
	}
	// Lists append whole messages, preserving duplicate identities and text bytes.
	appended := targetTestCompose(t, event, "request", p, string(sdkJSON([]any{map[string]any{"type": "modify", "target": "request", "operation": "merge", "value": messages}})))
	if len(sdkArray(compositionObject(appended.Event)["items"])) != 2 {
		t.Fatal("merge did not append duplicate messages")
	}
	// Actual objects still merge shallowly, retaining literal null and replacing nested values.
	req := compositionTestRequest(t)
	out, err := compose(req, compositionTestResponse(t, `[{"type":"modify","target":"input","operation":"merge","value":{"nested":{"new":2},"literal":null}}]`))
	if err != nil {
		t.Fatal(err)
	}
	input := compositionObject(out.EffectiveInput)
	nested := sdkObj(input["nested"])
	if nested["a"] != nil || !compositionEqual(nested["new"], json.Number("2")) {
		t.Fatal("nested object merged recursively", input)
	}
	if value, ok := input["literal"]; !ok || value != nil {
		t.Fatal("literal null removed", input)
	}
	parsed := ahp.ParseInterceptResponse([]byte(`{"jsonrpc":"2.0","id":"test","result":{"effects":[{"type":"modify","target":"request","operation":"merge","value":"not a message list"}]}}`))
	if parsed.OK {
		t.Fatal("scalar list merge accepted")
	}
}

func TestTargetCollectionAddRemoveAndRollback(t *testing.T) {

	attachment := map[string]any{"id": "binary", "kind": "attachment", "mediaType": "application/octet-stream", "selection": "body", "body": map[string]any{"ref": "original-ref"}}
	textMessage := targetInlineMessage("text", targetInlineText("part", "original text"))
	binaryMessage := targetInlineMessage("binary-message", attachment)
	event := targetTestCanonicalEvent(t, "model.request.before", []any{textMessage, binaryMessage})
	p := targetInlinePrepare(t, event, "request", map[string][]byte{"original-ref": []byte("immutable binary")})
	owner := p.sources["/items/1/parts/0"]
	if owner == nil {
		t.Fatal("binary owner missing")
	}
	defer owner.Retire()
	replacement := []any{binaryMessage, targetInlineMessage("new", targetInlineText("new-part", "new text"))}
	out := targetTestCompose(t, event, "request", p, string(sdkJSON([]any{map[string]any{"type": "modify", "target": "request", "operation": "replace", "value": replacement}})))
	if out.prepared.sources["/items/0/parts/0"] != owner || len(out.prepared.sources) != 1 || len(out.prepared.owned) != 1 {
		t.Fatal("reordering replaced immutable owner")
	}
	if _, ok := ownedcontent.Available(owner); ok {
		t.Fatal("text edit materialized binary owner")
	}
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"introduced-attachment", []any{targetInlineMessage("new", map[string]any{"id": "unknown", "kind": "attachment", "mediaType": "application/octet-stream", "selection": "metadata"})}},
		{"retargeted-attachment", []any{targetInlineMessage("binary-message", map[string]any{"id": "binary", "kind": "attachment", "mediaType": "application/octet-stream", "selection": "body", "body": map[string]any{"ref": "different"}})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := string(sdkJSON(event))
			beforeSources := p.clone().sources
			effects := []any{map[string]any{"type": "modify", "target": "request", "operation": "replace", "value": []any{textMessage}}, map[string]any{"type": "message", "text": "must not publish"}, map[string]any{"type": "modify", "target": "request", "operation": "replace", "value": tc.value}}
			result, err := composePrepared(targetTestRequest(t, event, "request"), compositionTestResponse(t, string(sdkJSON(effects))), p)
			if err == nil || result != nil {
				t.Fatal("invalid staged attachment edit published")
			}
			if string(sdkJSON(event)) != before || !reflect.DeepEqual(p.sources, beforeSources) || len(p.owned) != 1 {
				t.Fatal("atomic failure changed original owner index")
			}
		})
	}
	removed := targetTestCompose(t, compositionObject(out.Event), "request", out.prepared, `[{"type":"modify","target":"request","operation":"replace","value":[]}]`)
	if len(sdkArray(compositionObject(removed.Event)["items"])) != 0 || len(removed.prepared.sources) != 0 || string(compositionTestEffectiveValue(t, removed, "request")) != "[]" {
		t.Fatal("empty replacement retained content positions")
	}
	empty := targetTestCanonicalEvent(t, "model.request.before", []any{})
	emptyP := targetInlinePrepare(t, empty, "request", nil)
	added := targetTestCompose(t, empty, "request", emptyP, string(sdkJSON([]any{map[string]any{"type": "modify", "target": "request", "operation": "merge", "value": []any{textMessage}}})))
	if len(sdkArray(compositionObject(added.Event)["items"])) != 1 || len(added.prepared.sources) != 0 {
		t.Fatal("empty list append required a host template")
	}
}

func TestTargetBadPathsRejected(t *testing.T) {

	event := targetTestEvent(t, []any{targetInlineMessage("one", targetInlineText("text", "{}"))})
	for _, path := range []string{"", "items", "/items/-1", "/items/01", "/items/1", "/items/0/body", "/items/0/", "/tool/input", "/message/text", "/params", "/items/+0", "/items/0~1body", "/items/0"} {
		t.Run(path, func(t *testing.T) {
			cfg := interceptConfig{}
			WithModificationTarget("output", ModificationTarget{Path: path})(&cfg)
			if _, err := targetTestClient(nil).prepareBoundary(context.Background(), event, targetTestCaps("output"), cfg); err == nil {
				t.Fatal("legacy indexed body target accepted", path)
			}
		})
	}
	cfg := interceptConfig{}
	WithModificationTarget("output", ModificationTarget{Path: "/items/0", Templates: []ahp.ContentItem{targetTestTemplate(t, "bad", "text/plain")}})(&cfg)
	if _, err := targetTestClient(nil).prepareBoundary(context.Background(), event, targetTestCaps("output"), cfg); err == nil {
		t.Fatal("scalar legacy target accepted item templates")
	}
}

func TestTargetParamsAndWorkspaceMappings(t *testing.T) {

	event := targetTestCanonicalEvent(t, "model.request.before", []any{})
	opaque := map[string]any{"temperature": json.Number("1"), "nested": map[string]any{"old": true}, "lookalike": map[string]any{"kind": "text", "text": "native", "body": map[string]any{"ref": "never-resolve"}}}
	event["params"] = opaque
	p := targetInlinePrepare(t, event, "request", nil)
	values, err := p.values(event)
	if err != nil || !compositionEqual(values["request"], []any{}) || len(p.sources) != 0 {
		t.Fatalf("native params treated as canonical content: %v %v", values, err)
	}
	out := targetTestCompose(t, event, "request", p, string(sdkJSON([]any{map[string]any{"type": "modify", "target": "request", "operation": "replace", "value": []any{targetInlineMessage("new", targetInlineText("part", "new"))}}})))
	if !compositionEqual(compositionObject(out.Event)["params"], opaque) {
		t.Fatal("canonical edit changed opaque params")
	}
	cfg := interceptConfig{}
	WithModificationTarget("request", ModificationTarget{Path: "/params", Templates: []ahp.ContentItem{targetTestTemplate(t, "bad", "text/plain")}})(&cfg)
	if _, err := targetTestClient(nil).prepareBoundary(context.Background(), event, targetTestCaps("request"), cfg); err == nil {
		t.Fatal("native params accepted descriptor templates")
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
		event["message"] = map[string]any{"channel": "test", "sender": "user", "messages": items}
	case "user.message.outbound":
		delete(event, "items")
		event["message"] = map[string]any{"channel": "test", "messages": items}
	}
	return event
}

func TestTargetParamsCompositionMergeAndReplace(t *testing.T) {

	event := targetTestCanonicalEvent(t, "model.request.before", []any{targetInlineMessage("original", targetInlineText("part", "old"))})
	event["params"] = compositionObject([]byte(`{"temperature":1,"nested":{"old":true},"keep":1}`))
	p := targetInlinePrepare(t, event, "request", nil)
	for _, operation := range []string{"merge", "replace"} {
		t.Run(operation, func(t *testing.T) {
			legacy := `{"jsonrpc":"2.0","id":"test","result":{"effects":[{"type":"modify","target":"request","operation":"` + operation + `","value":{"temperature":2}}]}}`
			if ahp.ParseInterceptResponse([]byte(legacy)).OK {
				t.Fatal("legacy native params object edit accepted")
			}
			out := targetTestCompose(t, event, "request", p, string(sdkJSON([]any{map[string]any{"type": "modify", "target": "request", "operation": operation, "value": []any{targetInlineMessage("new", targetInlineText("new-part", "new"))}}})))
			if !compositionEqual(compositionObject(out.Event)["params"], event["params"]) || len(out.prepared.sources) != 0 || len(out.prepared.owned) != 0 {
				t.Fatal("canonical edit mutated native params or invented bodies")
			}
			want := 1
			if operation == "merge" {
				want = 2
			}
			if len(sdkArray(compositionObject(out.Event)["items"])) != want {
				t.Fatal("wrong list operation")
			}
		})
	}
}

func compositionTestEffectiveValue(t *testing.T, c *Composition, target string) []byte {
	t.Helper()
	raw, err := c.EffectiveValue(target)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCompositionEffectiveValueUsesOwnerOnDemand(t *testing.T) {

	event := targetTestCanonicalEvent(t, "model.request.before", []any{targetInlineMessage("one", targetInlineText("part", "original"))})
	p := targetInlinePrepare(t, event, "request", nil)
	result := targetTestCompose(t, event, "request", p, `[]`)
	raw := compositionTestEffectiveValue(t, result, "request")
	original := string(raw)
	raw[1] = 'X'
	if got := string(compositionTestEffectiveValue(t, result, "request")); got != original {
		t.Fatal("accessor returned shared mutable bytes", got)
	}
	if len(p.sources) != 0 || len(p.owned) != 0 {
		t.Fatal("inline accessor created content owners")
	}
	if _, err := result.EffectiveValue("missing"); err == nil {
		t.Fatal("unknown target available")
	}
	if _, err := result.EffectiveValue("input"); err == nil {
		t.Fatal("non-input accessor exposed input")
	}
}

func TestCompositionEffectiveValueDoesNotOpenLazyOwner(t *testing.T) {

	attachment := map[string]any{"id": "binary", "kind": "attachment", "mediaType": "application/octet-stream", "selection": "body", "body": map[string]any{"ref": "inbound"}}
	event := targetTestCanonicalEvent(t, "model.request.before", []any{targetInlineMessage("one", targetInlineText("text", "inline"), attachment)})
	var opens int
	c := targetTestClient(map[string][]byte{"inbound": []byte("binary bytes")})
	resolver := c.opts.Content.Resolver
	c.opts.Content.Resolver = func(ctx context.Context, ref string) (io.ReadCloser, error) { opens++; return resolver(ctx, ref) }
	p, err := c.prepareBoundary(context.Background(), event, targetTestCaps("request"), interceptConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for owner := range p.owned {
			_ = owner.Retire()
		}
	}()
	result := &Composition{Event: sdkJSON(event), prepared: p}
	raw, err := result.EffectiveValue("request")
	if err != nil || !compositionEqual(sdkArray(jsonMustDecode(t, raw)), event["items"]) {
		t.Fatalf("canonical value unavailable: %s %v", raw, err)
	}
	if opens != 0 {
		t.Fatal("accessor opened lazy binary owner")
	}
	if _, ok := ownedcontent.Available(p.sources["/items/0/parts/1"]); ok {
		t.Fatal("accessor snapshotted lazy owner")
	}
}

func targetInlineText(id, text string) map[string]any {
	return map[string]any{"id": id, "kind": "text", "mediaType": "text/plain", "selection": "body", "text": text}
}
func targetInlineMessage(id string, parts ...any) map[string]any {
	return map[string]any{"id": id, "role": "assistant", "parts": parts}
}
func targetInlinePrepare(t *testing.T, event map[string]any, target string, bodies map[string][]byte) *preparedBoundary {
	t.Helper()
	c := targetTestClient(bodies)
	c.opts.Content.AuthorizeContent = contentTestAllow
	p, err := c.prepareBoundary(context.Background(), event, targetTestCaps(target), interceptConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func jsonMustDecode(t *testing.T, raw []byte) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestToolAfterOutputCanonicalLists(t *testing.T) {
	for _, operation := range []string{"replace", "merge"} {
		t.Run(operation, func(t *testing.T) {
			attachment := map[string]any{"id": "binary", "kind": "attachment", "mediaType": "application/octet-stream", "selection": "body", "body": map[string]any{"ref": "host-binary"}}
			first := map[string]any{"id": "first", "role": "assistant", "parts": []any{map[string]any{"id": "first-text", "kind": "text", "mediaType": "text/plain", "selection": "body", "text": "first"}, attachment}}
			second := map[string]any{"id": "second", "role": "assistant", "parts": []any{map[string]any{"id": "second-text", "kind": "text", "mediaType": "text/plain", "selection": "body", "text": "second"}}}
			original := []any{first, second}
			event := map[string]any{"id": "test", "source": "urn:test", "time": "2026-01-01T00:00:00Z", "type": "tool.after", "call": map[string]any{"id": "call"}, "path": "execute", "tool": map[string]any{"name": "task", "kind": "task", "origin": "native", "input": map[string]any{"native": "opaque"}}, "outcome": "ok", "execution": map[string]any{"status": "executed"}, "items": original}
			before := string(sdkJSON(event))
			caps := map[string]any{"effects": []any{"modify"}, "modify": map[string]any{"output": map[string]any{"replace": true, "merge": true}}}
			opens := 0
			c := &Client{opts: Options{Content: ContentOptions{Resolver: func(context.Context, string) (io.ReadCloser, error) {
				opens++
				return io.NopCloser(strings.NewReader("immutable binary")), nil
			}}}}
			p, err := c.prepareBoundary(context.Background(), event, caps, interceptConfig{})
			if err != nil {
				t.Fatal(err)
			}
			owner := p.sources["/items/0/parts/1"]
			if owner == nil {
				t.Fatal("existing binary owner missing")
			}
			defer owner.Retire()
			request := ahp.ParseInterceptRequest(sdkJSON(map[string]any{"jsonrpc": "2.0", "id": "test", "method": "hooks/intercept", "params": map[string]any{"protocolVersion": "draft", "event": event, "capabilities": caps}}))
			if !request.OK {
				t.Fatal(request.Diagnostics)
			}
			incoming := []any{second, first, first}
			response := ahp.ParseInterceptResponse(sdkJSON(map[string]any{"jsonrpc": "2.0", "id": "test", "result": map[string]any{"protocolVersion": "draft", "effects": []any{map[string]any{"type": "modify", "target": "output", "operation": operation, "value": incoming}}}}))
			if !response.OK {
				t.Fatal(response.Diagnostics)
			}
			encodedRequest, _ := ahp.EncodeInterceptRequest(request.Value)
			if parsed := ahp.ParseInterceptRequest(encodedRequest); !parsed.OK {
				t.Fatalf("encoded request invalid: %v %s", parsed.Diagnostics, encodedRequest)
			}
			accepted, err := composePrepared(request.Value, response.Value, p)
			if err != nil {
				t.Fatal(err)
			}
			want := incoming
			if operation == "merge" {
				want = append(append([]any{}, original...), incoming...)
			}
			effective := compositionObject(accepted.Event)
			if !compositionEqual(effective["items"], want) {
				t.Fatal("output list lost ordering or duplicate messages", effective["items"])
			}
			for i, message := range sdkArray(effective["items"]) {
				if sdkObj(message)["id"] == "first" && accepted.prepared.sources[fmt.Sprintf("/items/%d/parts/1", i)] != owner {
					t.Fatal("output edit replaced existing immutable owner", i)
				}
			}
			if len(accepted.prepared.owned) != 1 || opens != 0 {
				t.Fatal("output edit created/snapshotted owners", len(accepted.prepared.owned), opens)
			}
			if string(sdkJSON(event)) != before || !compositionEqual(sdkObj(effective["tool"])["input"], sdkObj(event["tool"])["input"]) {
				t.Fatal("output list edit changed host/native JSON")
			}
		})
	}
}
