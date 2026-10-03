package interop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestLifecycleObserveValidationAndAuthorization(t *testing.T) {
	v, e := newLifecycleValidator(schemaPath(t))
	if e != nil {
		t.Fatal(e)
	}
	s := &lifecycleReceiver{validator: v, eventScopes: []string{"body"}, changed: make(chan struct{}), uploads: map[string]string{}, entries: []any{}}
	event := obj(clone(obj(request("observe-test")["params"])["event"]))
	text := "immutable bytes"
	ref := Object{"ref": "urn:test:body", "size": float64(len(text)), "sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(text)))}
	event["items"] = []any{Object{"id": "item", "kind": "text", "mediaType": "text/plain", "selection": "body", "body": ref}}
	notification := Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": event}}
	if _, e = s.dispatch(context.Background(), notification); e == nil {
		t.Fatal("missing upload accepted")
	}
	s.uploads[contentKey("body", "urn:test:body")] = text
	r, e := s.dispatch(context.Background(), notification)
	if e != nil {
		t.Fatal(e)
	}
	if e = v.validate("intercept-response", r); e != nil {
		t.Fatalf("malicious response must be canonical: %v", e)
	}
	s.eventScopes = []string{"metadata"}
	if _, e = s.dispatch(context.Background(), notification); e == nil {
		t.Fatal("cross-subscription reference accepted")
	}
	s.eventScopes = []string{"body"}
	ref["size"] = float64(999)
	if _, e = s.dispatch(context.Background(), notification); e == nil {
		t.Fatal("wrong metadata accepted")
	}
	ref["size"] = float64(len(text))
	obj(array(event["items"])[0])["unexpected"] = true
	if _, e = s.dispatch(context.Background(), notification); e == nil {
		t.Fatal("invalid content item accepted")
	}
}

func TestLifecycleStdioCorrelation(t *testing.T) {
	p := &lifecyclePipe{pending: map[string][]chan lifecycleResult{}, discarded: map[string]int{}, changed: make(chan struct{})}
	first := make(chan lifecycleResult, 2)
	second := make(chan lifecycleResult, 2)
	p.pending[`"first"`] = []chan lifecycleResult{first}
	p.pending[`"second"`] = []chan lifecycleResult{second}
	var frames bytes.Buffer
	for _, id := range []string{"unsolicited-observer", "wrong", "second", "first"} {
		if e := json.NewEncoder(&frames).Encode(lifecycleReply(id)); e != nil {
			t.Fatal(e)
		}
	}
	p.read(&frames)
	if got := (<-first).response["id"]; got != "first" {
		t.Fatalf("first correlation: %v", got)
	}
	if got := (<-second).response["id"]; got != "second" {
		t.Fatalf("second correlation: %v", got)
	}
	if p.discarded[`"wrong"`] != 1 || p.discarded[`"unsolicited-observer"`] != 0 {
		t.Fatalf("incorrect discarded frames: %v", p.discarded)
	}
	if e := p.waitDiscarded(context.Background(), `"wrong"`, 1); e != nil {
		t.Fatal(e)
	}
}

// This local integration regression checks real controls and selected receipts.
// Exhaustive scenario multiplicity/payload/ordering proofs remain central.
func TestLifecycleStagingCancellationAndUpload(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "fixture.json")
	ready := filepath.Join(dir, "ready.json")
	report := filepath.Join(dir, "report.json")
	req := request("hardening")
	prefix := obj(obj(req["params"])["state"])
	prefix["flow"] = "stop"
	prefix["instructions"] = []any{"accepted-prefix"}
	prefix["injections"] = []any{Object{"type": "inject", "target": "context", "operation": "append", "deliverAt": "next_turn", "value": "retained-context"}}
	validator, err := newLifecycleValidator(schemaPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = validator.validate("intercept-request", req); err != nil {
		t.Fatal(err)
	}
	first := response("hardening", Object{"type": "modify", "target": "input", "operation": "merge", "value": Object{"task": float64(2)}})
	second := response("hardening", Object{"type": "modify", "target": "input", "operation": "merge", "value": Object{"task": float64(3)}})
	steps := []Object{{"op": "send", "key": "a", "slot": "one"}, {"op": "wait", "key": "a"}, {"op": "release", "key": "a"}, {"op": "receive", "slot": "one"}, {"op": "send", "key": "a", "slot": "two"}, {"op": "wait", "key": "a", "count": 2}, {"op": "receive", "slot": "two"}, {"op": "accept", "key": "a"}, {"op": "cancel", "key": "a"}, {"op": "failOpen", "key": "a"}, {"op": "accept", "key": "a"}, {"op": "observe", "key": "a", "subscription": "metadata"}}
	sc := lifecycleScenario{ID: "hardening", Requests: map[string]Object{"a": req}, Responses: map[string]Object{"a": second}, ResponseSequences: map[string][]Object{"a": {first, second}}, Steps: steps}
	if e := writeAtomic(fixture, Object{"version": 1, "scenarios": []lifecycleScenario{sc}}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg := LifecycleConfig{Config: Config{Transport: "http", ReadinessFile: ready, ScenarioFile: fixture, SchemaDir: schemaPath(t), ReportFile: report}}
	done := make(chan error, 1)
	go func() { done <- LifecycleServer(ctx, cfg) }()
	defer func() {
		cancel()
		if e := <-done; e != nil {
			t.Error(e)
		}
	}()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	var address Object
	for {
		if Load(ready, &address) == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	cfg.Endpoint = str(address["endpoint"])
	cfg.ControlEndpoint = str(address["controlEndpoint"])
	if e := LifecycleClient(ctx, cfg); e != nil {
		t.Fatal(e)
	}
	var got Object
	if e := Load(report, &got); e != nil {
		t.Fatal(e)
	}
	results := array(got["results"])
	if len(results) != 1 {
		t.Fatalf("results count %d", len(results))
	}
	actual := obj(obj(results[0])["actual"])
	if len(array(actual["published"])) != 1 || len(array(actual["cancelled"])) != 1 || len(array(actual["ignored"])) != 1 {
		t.Fatalf("wrong lifecycle counts: %v", actual)
	}
	state := obj(obj(actual["states"])["hardening"])
	if state["flow"] != "stop" || state["executed"] != false || !reflect.DeepEqual(state["continuationInstructions"], prefix["instructions"]) || !reflect.DeepEqual(state["injections"], prefix["injections"]) {
		t.Fatal("interruption lost prior accepted state", state)
	}
	if obj(state["input"])["task"] != float64(2) {
		t.Fatalf("later duplicate replaced staged response: %v", state)
	}
	obs := array(actual["observations"])
	if len(obs) != 1 || obj(obj(obs[0])["input"])["task"] != float64(2) {
		t.Fatalf("cancel rolled back accepted input: %v", obs)
	}
	acquired, observations := 0, 0
	for _, entry := range array(obj(got["receipts"])["entries"]) {
		r := obj(entry)
		switch r["kind"] {
		case "acquired":
			acquired++
		case "view":
			t.Fatal("semantic view oracle must not exist")
		case "observed":
			observations++
			if _, exists := obj(obj(r["message"])["params"])["disposition"]; exists {
				t.Fatalf("obsolete disposition: %v", r)
			}
			event := obj(r["event"])
			if obj(obj(event["tool"])["input"])["task"] != float64(2) {
				t.Fatalf("receiver rollback: %v", event)
			}
			if _, ok := event["decision"]; ok {
				t.Fatal("normative decision field invented")
			}
		}
	}
	if acquired != 1 || observations != 1 {
		t.Fatalf("receipt counts %d %d", acquired, observations)
	}
	_, status, e := lifecycleCall(ctx, cfg.ControlEndpoint+"/emit", Object{"response": first})
	if e != nil || status != 400 {
		t.Fatalf("HTTP emit accepted: %d %v", status, e)
	}
}
