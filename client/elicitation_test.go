package client

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func elicitationFixture(stage, mode, payload string) (map[string]any, map[string][]byte) {
	raw := []byte(payload)
	item := map[string]any{"id": "item", "kind": "data", "mediaType": "application/json", "selection": "body", "body": map[string]any{"ref": stage, "size": len(raw), "sha256": fmt.Sprintf("%x", sha256.Sum256(raw))}}
	meta := map[string]any{"server": "requester", "mode": mode, stage: item}
	event := map[string]any{"type": "user.elicitation." + stage, "id": "request-id", "source": "urn:adapter", "session": map[string]any{"id": "session"}, "elicitation": meta}
	if stage == "result" {
		event["id"] = "result-id"
		event["parentEventId"] = "request-id"
		meta["action"] = "accept"
	}
	return event, map[string][]byte{stage: raw}
}

const elicitationForm = `{"message":"choose","requestedSchema":{"type":"object","properties":{"x":{"type":"string","enum":["a"]}},"required":["x"]},"_meta":{"preserved":true},"extension":42}`

func TestElicitationSnapshotAndAnswers(t *testing.T) {
	event, bodies := elicitationFixture("request", "form", elicitationForm)
	snapshot, err := prepareElicitation(event, nil, bodies)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating the original input bytes or event must not mutate the snapshot.
	bodies["request"][0] = '!'
	event["id"] = "changed"
	event["elicitation"].(map[string]any)["server"] = "changed"
	result, resultBodies := elicitationFixture("result", "form", `{"action":"accept","content":{"x":"a"},"_meta":{"result":true}}`)
	if _, err = prepareElicitation(result, snapshot, resultBodies); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{
		map[string]any{"action": "accept", "content": map[string]any{"x": "b"}},
		map[string]any{"action": "accept"},
		map[string]any{"action": "decline"}, // envelope action mismatch
		map[string]any{"action": "accept", "content": map[string]any{"x": nil}},
	} {
		if validateElicitationAnswer(result, snapshot, value) == nil {
			t.Fatalf("invalid answer accepted: %#v", value)
		}
	}
	request, _ := elicitationFixture("request", "form", elicitationForm)
	for _, action := range []string{"decline", "cancel"} {
		if err := validateElicitationAnswer(request, snapshot, map[string]any{"action": action}); err != nil {
			t.Fatal(err)
		}
		if validateElicitationAnswer(request, snapshot, map[string]any{"action": action, "content": map[string]any{}}) == nil {
			t.Fatal("non-accept content accepted")
		}
	}
	if validateElicitationAnswer(result, &ElicitationRequest{}, map[string]any{"action": "accept"}) == nil {
		t.Fatal("zero snapshot accepted")
	}
}

func TestElicitationCorrelation(t *testing.T) {
	request, bodies := elicitationFixture("request", "form", elicitationForm)
	snapshot, err := prepareElicitation(request, nil, bodies)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]any){
		"parent":         func(e map[string]any) { e["parentEventId"] = "other" },
		"missing parent": func(e map[string]any) { delete(e, "parentEventId") },
		"source":         func(e map[string]any) { e["source"] = "urn:other" },
		"session":        func(e map[string]any) { e["session"] = map[string]any{"id": "other"} },
		"server":         func(e map[string]any) { e["elicitation"].(map[string]any)["server"] = "other" },
		"mode":           func(e map[string]any) { e["elicitation"].(map[string]any)["mode"] = "url" },
		"action":         func(e map[string]any) { e["elicitation"].(map[string]any)["action"] = "cancel" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			result, bodies := elicitationFixture("result", "form", `{"action":"accept","content":{"x":"a"}}`)
			mutate(result)
			if _, err := prepareElicitation(result, snapshot, bodies); err == nil {
				t.Fatal("mismatched correlation accepted")
			}
		})
	}
}

func TestElicitationSelectionAndPinnedRequestValidation(t *testing.T) {
	for _, selection := range []string{"metadata", "omit", "absent"} {
		event, _ := elicitationFixture("request", "form", elicitationForm)
		meta := event["elicitation"].(map[string]any)
		item := meta["request"].(map[string]any)
		delete(item, "body")
		item["selection"] = selection
		if selection == "absent" {
			delete(meta, "request")
		}
		snapshot, err := prepareElicitation(event, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot == nil || snapshot.request != "" {
			t.Fatal("metadata falsely established executable request")
		}
		if validateElicitationAnswer(event, snapshot, map[string]any{"action": "cancel"}) == nil {
			t.Fatal("metadata-only snapshot authorized answer")
		}
	}
	for _, payload := range []string{
		`{"message":"choose","requestedSchema":{"type":"object","properties":{"x":{"type":"object"}}}}`,
		`{"jsonrpc":"2.0","method":"elicitation/create","params":{}}`,
		elicitationForm + ` {}`,
		`{"mode":"url","message":"open","url":"https://example.test","elicitationId":"opaque"}`,
	} {
		event, bodies := elicitationFixture("request", "form", payload)
		if _, err := prepareElicitation(event, nil, bodies); err == nil {
			t.Fatal("invalid request or mode accepted")
		}
	}
	event, _ := elicitationFixture("request", "form", elicitationForm)
	if _, err := prepareElicitation(event, nil, nil); err == nil {
		t.Fatal("missing bytes accepted")
	}
	item := event["elicitation"].(map[string]any)["request"].(map[string]any)
	delete(item, "body")
	item["gap"] = map[string]any{"reason": "unavailable"}
	if _, err := prepareElicitation(event, nil, nil); err == nil {
		t.Fatal("selected gap accepted")
	}
}

func TestElicitationURLConsentAndOriginalContract(t *testing.T) {
	event, bodies := elicitationFixture("request", "url", `{"mode":"url","message":"open","url":"https://example.test","elicitationId":"opaque"}`)
	snapshot, err := prepareElicitation(event, nil, bodies)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"accept", "decline", "cancel"} {
		if err := validateElicitationAnswer(event, snapshot, map[string]any{"action": action}); err != nil {
			t.Fatal(err)
		}
		if validateElicitationAnswer(event, snapshot, map[string]any{"action": action, "content": map[string]any{}}) == nil {
			t.Fatal("URL content accepted")
		}
	}
	form, formBodies := elicitationFixture("request", "form", elicitationForm)
	original, err := prepareElicitation(form, nil, formBodies)
	if err != nil {
		t.Fatal(err)
	}
	rewritten, rewrittenBodies := elicitationFixture("request", "form", `{"message":"changed","requestedSchema":{"type":"object","properties":{"x":{"type":"string"}}}}`)
	preserved, err := prepareElicitation(rewritten, original, rewrittenBodies)
	if err != nil || preserved != original {
		t.Fatal("original contract replaced", err)
	}
	if validateElicitationAnswer(rewritten, preserved, map[string]any{"action": "accept", "content": map[string]any{"x": "b"}}) == nil {
		t.Fatal("rewritten form widened original contract")
	}
}

func TestElicitationMetadataBeforeBodyResolution(t *testing.T) {
	request, bodies := elicitationFixture("request", "form", elicitationForm)
	snapshot, err := prepareElicitation(request, nil, bodies)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := elicitationFixture("result", "form", `{"action":"accept","content":{"x":"a"}}`)
	if err := validateElicitationMetadata(result, snapshot); err != nil {
		t.Fatal(err)
	}
	result["parentEventId"] = "wrong-parent"
	if validateElicitationMetadata(result, snapshot) == nil {
		t.Fatal("correlation not rejected without resolving bodies")
	}
	if validateElicitationMetadata(request, nil) != nil {
		t.Fatal("initial request metadata rejected")
	}
}

func TestElicitationOptionalContentAndAbsentSession(t *testing.T) {
	request, bodies := elicitationFixture("request", "form", `{"message":"optional","requestedSchema":{"type":"object","properties":{"x":{"type":"boolean","default":true}}}}`)
	delete(request, "session")
	snapshot, err := prepareElicitation(request, nil, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateElicitationAnswer(request, snapshot, map[string]any{"action": "accept"}); err != nil {
		t.Fatal(err)
	}
	result, resultBodies := elicitationFixture("result", "form", `{"action":"accept"}`)
	delete(result, "session")
	if _, err := prepareElicitation(result, snapshot, resultBodies); err != nil {
		t.Fatal(err)
	}
}
