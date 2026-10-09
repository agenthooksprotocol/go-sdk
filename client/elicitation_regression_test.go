package client

import (
	"context"
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
			result, resultBodies := elicitationFixture("result", "form", ` {"action":"accept","content":{"x":"old","keep":"retained"},"_meta":{"preserve":true},"extension":"untouched"} `)
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
			effect := `[{"type":"modify","target":"content","operation":"` + operation + `","value":{"x":"new"}}]`
			accepted, err := composePrepared(req, compositionTestResponse(t, effect), prepared)
			if err != nil {
				t.Fatal(err)
			}
			event := compositionObject(accepted.Event)
			item := preparedAt(event, "/elicitation/result")
			body, err := preparedDecode(item, preparedTestBytes(accepted.prepared, "/elicitation/result"))
			if err != nil {
				t.Fatal(err)
			}
			answer := sdkObj(body)
			if answer["action"] != "accept" || sdkObj(answer["_meta"])["preserve"] != true || answer["extension"] != "untouched" || answer["x"] != nil || sdkObj(answer["content"])["x"] != "new" {
				t.Fatal("MCP wrapper changed", answer)
			}
			_, keep := sdkObj(answer["content"])["keep"]
			if keep != (operation == "merge") {
				t.Fatal("incorrect answer merge/replacement", answer)
			}
			if sdkObj(compositionObject(compositionTestEffectiveValue(t, accepted, "content")))["x"] != "new" {
				t.Fatal("effective content not answer fields")
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
	delete(item, "body")
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
	delete(item, "body")
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
