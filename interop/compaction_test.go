package interop

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func compactModify(target, value string) Object {
	return Object{"type": "modify", "target": target, "operation": "replace", "value": value}
}
func TestCompactionCallbacks(t *testing.T) {
	before := []CompactionHook{{Supplier: "edit", FailurePolicy: "fail-closed", Run: func(s Object) ([]Object, error) {
		s["instructions"] = "leak"
		return []Object{compactModify("instructions", "new")}, nil
	}}}
	after := []CompactionHook{{Supplier: "redact", FailurePolicy: "fail-closed", Run: func(s Object) ([]Object, error) {
		return []Object{compactModify("summary", str(obj(s["bodies"])[str(obj(s["summary"])["ref"])])+":redacted")}, nil
	}}, {Supplier: "watch", FailurePolicy: "fail-closed", Run: func(s Object) ([]Object, error) {
		if obj(s["bodies"])[str(obj(s["summary"])["ref"])] != "generated:new:redacted" {
			return nil, fmt.Errorf("stale result")
		}
		return []Object{}, nil
	}}}
	generated := []string{}
	r, err := RunCompaction("old", "summary-1", before, after, func(input string) (string, error) {
		generated = append(generated, input)
		return "generated:" + input, nil
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(generated, []string{"new"}) || r["applied"] != true || len(array(r["failures"])) != 0 {
		t.Fatalf("bad settlement: %v", r)
	}
	old := obj(obj(array(r["seen"])[1])["summary"])
	current := obj(r["summary"])
	if old["id"] != current["id"] || old["ref"] == current["ref"] || len(obj(r["bodies"])) != 2 {
		t.Fatal("immutable identity")
	}
}
func TestCompactionAtomicCandidate(t *testing.T) {
	before := []CompactionHook{{"cache", "fail-closed", func(Object) ([]Object, error) { return []Object{{"type": "return", "value": "cached"}}, nil }}, {"bad", "fail-open", func(Object) ([]Object, error) {
		return []Object{compactModify("instructions", "leak"), {"type": "message", "text": "leak"}, compactModify("summary", "wrong")}, nil
	}}}
	after := []CompactionHook{{"redact", "fail-closed", func(Object) ([]Object, error) { return []Object{compactModify("summary", "safe")}, nil }}}
	r, err := RunCompaction("old", "summary-1", before, after, func(string) (string, error) { return "", fmt.Errorf("generator must not run") }, false)
	if err != nil {
		t.Fatal(err)
	}
	if r["instructions"] != "old" || len(array(r["messages"])) != 0 || obj(r["bodies"])[str(obj(r["summary"])["ref"])] != "safe" || r["applied"] != true || obj(r["provenance"])["supplier"] != "cache" {
		t.Fatalf("bad settlement: %v", r)
	}
}
func TestCompactionAfterFailure(t *testing.T) {
	r, err := RunCompaction("old", "summary-1", nil, []CompactionHook{{"bad", "fail-closed", func(Object) ([]Object, error) {
		return []Object{compactModify("summary", "leak"), compactModify("instructions", "wrong")}, nil
	}}}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if r["applied"] != false || len(obj(r["bodies"])) != 1 {
		t.Fatal("partial commit")
	}
	caps, _ := CompactionCapabilities("after", true)
	if len(obj(caps["modify"])) != 0 || len(array(caps["effects"])) != 0 {
		t.Fatal("observation control")
	}
}

func TestCompactionBlockedObserversDetached(t *testing.T) {
	entered := make(chan Object, 1)
	release := make(chan struct{})
	finished := make(chan struct{})
	panicked := make(chan struct{})
	settled := make(chan Object, 1)
	hooks := []CompactionHook{
		{"slow", "fail-closed", func(snapshot Object) ([]Object, error) {
			entered <- obj(clone(snapshot))
			<-release
			snapshot["instructions"] = "mutation"
			snapshot["bodies"] = Object{}
			close(finished)
			return []Object{compactModify("summary", "forbidden")}, nil
		}},
		{"panic", "fail-closed", func(Object) ([]Object, error) { defer close(panicked); panic("observer failure") }},
	}
	defer close(release)
	go func() {
		r, err := RunCompaction("base", "summary-1", nil, hooks, nil, true)
		if err != nil {
			settled <- Object{"error": err.Error()}
			return
		}
		downstream := []any{}
		if r["applied"] == true {
			downstream = append(downstream, obj(r["bodies"])[str(obj(r["summary"])["ref"])])
		}
		settled <- Object{"result": r, "downstream": downstream}
	}()
	var snapshot Object
	select {
	case snapshot = <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("observer did not start")
	}
	var output Object
	select {
	case output = <-settled:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked observer gated settlement")
	}
	select {
	case <-finished:
		t.Fatal("barrier released early")
	default:
	}
	select {
	case <-panicked:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked observer serialized other notifications")
	}
	if !reflect.DeepEqual(output["downstream"], []any{"summary:base"}) || snapshot["applied"] != true {
		t.Fatal(output)
	}
	result := obj(output["result"])
	if len(array(result["failures"])) != 0 || len(array(obj(snapshot["capabilities"])["effects"])) != 0 {
		t.Fatal("observation has authority")
	}
	// Release with a rendezvous while keeping the deferred cleanup single-close.
	release <- struct{}{}
	<-finished
	if obj(result["bodies"])[str(obj(result["summary"])["ref"])] != "summary:base" || result["instructions"] != "base" {
		t.Fatal("observer mutated settlement")
	}
}
