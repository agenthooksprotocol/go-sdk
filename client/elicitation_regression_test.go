package client

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestElicitationContentTargetsAnswerOnly(t *testing.T) {
	request, bodies := elicitationFixture("request", "form", `{"message":"choose","requestedSchema":{"type":"object","properties":{"x":{"type":"string"},"keep":{"type":"string"}},"required":["x"]}}`)
	snapshot, err := prepareElicitation(request, nil, elicitationOwners(request, bodies))
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"replace", "merge"} {
		t.Run(operation, func(t *testing.T) {
			result, resultBodies := elicitationFixture("result", "form", ` {"action":"accept","content":{"x":"old","keep":"retained","flag":false},"_meta":{"preserve":true},"extension":"untouched"} `)
			originalText := preparedAt(result, "/elicitation/result")["text"]
			result["id"] = "test"
			result["time"] = "2026-01-01T00:00:00Z"
			caps := targetTestCaps("content")
			caps["elicitation"] = map[string]any{"form": map[string]any{}}
			cfg := interceptConfig{elicitation: snapshot}
			prepared, err := targetTestClient(resultBodies).prepareBoundary(context.Background(), result, caps, cfg)
			if err != nil {
				t.Fatal(err)
			}
			values, err := prepared.values(result)
			if err != nil || sdkObj(values["content"])["x"] != "old" || sdkObj(values["content"])["action"] != nil {
				t.Fatal("wrong modify base", values, err)
			}
			req := compositionBoundaryRequest(t, result, caps)
			effect := `[{"type":"modify","target":"content","operation":"` + operation + `","value":{"x":"new","flag":true,"number":2,"action":"cancel","_meta":"inside"}}]`
			accepted, err := composePrepared(req, compositionTestResponse(t, effect), prepared)
			if err != nil {
				t.Fatal(err)
			}
			item := preparedAt(compositionObject(accepted.Event), "/elicitation/result")
			if item["kind"] != "text" || item["mediaType"] != "text/plain" || item["selection"] != "body" || item["body"] != nil {
				t.Fatal("structured answer lost inline serialization", item)
			}
			answer := compositionObject([]byte(compositionString(item["text"])))
			if answer["action"] != "accept" || sdkObj(answer["_meta"])["preserve"] != true || answer["extension"] != "untouched" || answer["x"] != nil || sdkObj(answer["content"])["x"] != "new" {
				t.Fatal("MCP wrapper changed", answer)
			}
			content := sdkObj(answer["content"])
			if content["flag"] != true || !compositionEqual(content["number"], json.Number("2")) || content["action"] != "cancel" || content["_meta"] != "inside" {
				t.Fatal("structured content fields edited wrapper fields", answer)
			}

			_, keep := sdkObj(answer["content"])["keep"]
			if keep != (operation == "merge") {
				t.Fatal("incorrect structured answer replacement/merge", answer)
			}
			if sdkObj(compositionObject(compositionTestEffectiveValue(t, accepted, "content")))["x"] != "new" {
				t.Fatal("effective value not answer fields")
			}
			if len(accepted.prepared.sources) != 0 || len(accepted.prepared.owned) != 0 {
				t.Fatal("structured inline edit allocated owners")
			}
			if preparedAt(result, "/elicitation/result")["text"] != originalText {
				t.Fatal("host result mutated")
			}

		})
	}
}

func TestElicitationPassiveModeAndAnswerGrantAdmission(t *testing.T) {
	for _, returns := range []bool{false, true} {
		c, _ := testClient(t, "fail-open")
		caps := map[string]any{"effects": []any{"message"}}
		if returns {
			caps["effects"] = []any{"return"}
		}
		setDispatchBoundary(c, "user.elicitation.request", caps)
		reads := 0
		c.opts.Content.Resolver = func(context.Context, string) (io.ReadCloser, error) {
			reads++
			return io.NopCloser(strings.NewReader(elicitationForm)), nil
		}
		result, err := c.intercept(context.Background(), "user.elicitation.request", elicitationDispatchInput("request", "form", elicitationForm))
		if returns {
			if err == nil || result != nil || reads != 0 {
				t.Fatal("unadvertised answer mode admitted", err, reads)
			}
		} else {
			if err != nil || result == nil || result.Snapshot == nil {
				t.Fatal("passive delivery required an answer grant", err)
			}
			waitObservations(t, result)
		}
	}
}

func TestContentPreservesExplicitUnavailableGap(t *testing.T) {
	original := map[string]any{"path": "items.logical-item", "reason": "content permission denied"}
	item := contentTestItem(nil)
	delete(item, "text")
	item["selection"] = "body"
	item["gap"] = original
	c := &Client{opts: Options{Content: ContentOptions{AuthorizeContent: contentTestAllow}}}
	projected, err := c.projectContent(context.Background(), map[string]any{"items": []any{item}}, map[string]any{"content": map[string]any{"default": "body"}}, "receiver")
	if err != nil {
		t.Fatal(err)
	}
	gap := sdkObj(contentTestBody(t, projected)["gap"])
	if gap["path"] != "items.logical-item" || gap["reason"] != "content permission denied" {
		t.Fatal("explicit gap changed", gap)
	}
	original["reason"] = "mutated"
	if gap["reason"] != "content permission denied" {
		t.Fatal("explicit gap aliases caller")
	}
}

func TestCompositionEffectiveValueKeepsSnapshotLocal(t *testing.T) {
	event, bodies := elicitationFixture("request", "form", elicitationForm)
	owners := elicitationOwners(event, bodies)
	defer func() {
		for _, owner := range owners {
			_ = owner.Retire()
		}
	}()
	item := preparedAt(event, "/elicitation/request")
	item["selection"] = "metadata"
	delete(item, "text")
	snapshot, err := prepareElicitation(event, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := &preparedBoundary{sources: owners, snapshot: snapshot, limit: 4 << 20}
	c := &Composition{Event: sdkJSON(event), prepared: p}
	done := make(chan bool, 16)
	for i := 0; i < cap(done); i++ {
		go func() {
			_, err := c.EffectiveValue("missing")
			done <- err != nil
		}()
	}
	for i := 0; i < cap(done); i++ {
		if !<-done {
			t.Fatal("unavailable target became available")
		}
	}
	if p.snapshot != snapshot || p.snapshot.requestValid {
		t.Fatal("accessor mutated the shared elicitation snapshot")
	}
}

func TestElicitationStructuredEditPinnedValidationAtomic(t *testing.T) {
	request, _ := elicitationFixture("request", "form", elicitationForm)
	snapshot, err := prepareElicitation(request, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, operation string
		value           any
	}{
		{"replace-missing-required", "replace", map[string]any{"unrelated": true}},
		{"merge-invalid-enum", "merge", map[string]any{"x": "outside"}},
		{"replace-invalid-type", "replace", map[string]any{"x": 12}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, _ := elicitationFixture("result", "form", ` {"action":"accept","content":{"x":"a"},"_meta":{"preserved":true},"extension":"unchanged"} `)
			result["time"] = "2026-01-01T00:00:00Z"
			before := string(sdkJSON(result))
			caps := elicitationDispatchCaps("result", "form")
			prepared, err := targetTestClient(nil).prepareBoundary(context.Background(), result, caps, interceptConfig{elicitation: snapshot})
			if err != nil {
				t.Fatal(err)
			}
			effects := []any{map[string]any{"type": "message", "text": "must not publish"}, map[string]any{"type": "modify", "target": "content", "operation": tc.operation, "value": tc.value}}
			accepted, err := composePrepared(compositionBoundaryRequest(t, result, caps), compositionTestResponse(t, string(sdkJSON(effects))), prepared)
			if err == nil || accepted != nil {
				t.Fatal("edit bypassed pinned answer validation")
			}
			if string(sdkJSON(result)) != before || len(prepared.sources) != 0 || len(prepared.owned) != 0 {
				t.Fatal("invalid structured edit changed host result or allocated owners")
			}
		})
	}
}
