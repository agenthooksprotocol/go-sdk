package interop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestAcceptedPrefixSurvivesLaterResponses(t *testing.T) {
	req := obj(clone(request("serial")))
	oldInjection := Object{"type": "inject", "target": "context", "operation": "append", "deliverAt": "next_turn", "value": "old"}
	prior := Object{"permission": "none", "candidate": nil, "flow": "stop", "instructions": []any{"old instruction"}, "injections": []any{oldInjection}}
	obj(req["params"])["state"] = prior
	original := clone(req)
	got, e := Apply(req, lifecycleReply("serial"))
	if e != nil || got["flow"] != "stop" || got["executed"] != false || !reflect.DeepEqual(got["continuationInstructions"], prior["instructions"]) || !reflect.DeepEqual(got["injections"], prior["injections"]) {
		t.Fatal("empty response lost accepted state", got, e)
	}
	res := response("serial", Object{"type": "inject", "target": "context", "operation": "append", "deliverAt": "now", "value": "new"}, Object{"type": "message", "text": "new diagnostic"})
	got, e = Apply(req, res)
	if e != nil || got["flow"] != "stop" || got["executed"] != false || len(array(got["injections"])) != 2 {
		t.Fatal("later effects revived stopped operation", got, e)
	}
	// The staged append and replacement are discarded together on failure.
	bad := response("serial", Object{"type": "inject", "target": "context", "operation": "append", "deliverAt": "now", "value": "discard"}, Object{"type": "modify", "target": "input", "operation": "merge", "value": Object{"task": float64(0)}})
	if state, e := Apply(req, bad); e == nil || state != nil {
		t.Fatal("partial publication", state, e)
	}
	if !reflect.DeepEqual(req, original) {
		t.Fatal("accepted prefix mutated")
	}
	obj(array(got["injections"])[0])["value"] = "mutated result"
	if obj(array(prior["injections"])[0])["value"] != "old" {
		t.Fatal("accepted injection aliased staged output")
	}
}

func TestSerialContinuationConsumesOneAllowance(t *testing.T) {
	req := obj(clone(request("continue")))
	event := obj(obj(req["params"])["event"])
	event["type"] = "turn.finish.before"
	event["outcome"] = "completed"
	event["items"] = []any{}
	event["turn"] = Object{"id": "turn-1"}
	event["continuationCount"] = float64(0)
	delete(event, "tool")
	delete(event, "call")
	delete(event, "path")
	caps := Object{"effects": []any{"flow", "message"}}
	obj(req["params"])["capabilities"] = caps
	caps["flow"] = Object{"operations": []any{"stop", "continue"}, "remainingContinuations": float64(2), "continuationCount": float64(0)}
	validator, err := newLifecycleValidator(schemaPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = validator.core.schemas["intercept-request"].Validate(req); err != nil {
		t.Fatal(err)
	}
	if err = validator.validate("intercept-request", req); err != nil {
		t.Fatal(err)
	}
	first, e := Apply(req, response("continue", Object{"type": "flow", "operation": "continue", "instruction": "first"}))
	if e != nil || first["continuationRemaining"] != float64(1) {
		t.Fatal(first, e)
	}
	obj(req["params"])["state"] = Object{"permission": "none", "candidate": nil, "flow": first["flow"], "instructions": first["continuationInstructions"], "injections": []any{}}
	obj(caps["flow"])["remainingContinuations"] = first["continuationRemaining"]
	for _, res := range []Object{lifecycleReply("continue"), response("continue", Object{"type": "flow", "operation": "continue", "instruction": "second"})} {
		if err := validator.validate("intercept-request", req); err != nil {
			t.Fatal(err)
		}
		next, e := Apply(req, res)
		if e != nil || next["flow"] != "continue" || next["continuationRemaining"] != float64(1) {
			t.Fatal("serial continuation debited twice", next, e)
		}
	}
	obj(caps["flow"])["remainingContinuations"] = float64(0)
	next, e := Apply(req, response("continue", Object{"type": "flow", "operation": "continue", "instruction": "reserved"}))
	if e != nil || next["continuationRemaining"] != float64(0) || !reflect.DeepEqual(next["continuationInstructions"], []any{"first", "reserved"}) {
		t.Fatal("existing reservation lost", next, e)
	}
	stopped, e := Apply(req, response("continue", Object{"type": "flow", "operation": "stop", "reason": "stop"}))
	if e != nil || stopped["flow"] != "stop" || stopped["continuationRemaining"] != float64(0) {
		t.Fatal(stopped, e)
	}
}

func TestNativeDenialAlsoBlocksSuppliedResult(t *testing.T) {
	req := obj(clone(request("native-deny")))
	obj(req["params"])["state"] = Object{"permission": "none", "candidate": nil, "nativePermission": "deny"}
	got, e := Apply(req, response("native-deny", Object{"type": "allow"}, Object{"type": "return", "value": "private result"}))
	if e != nil || got["decision"] != "deny" || got["executed"] != false {
		t.Fatal(got, e)
	}
	if _, ok := got["result"]; ok {
		t.Fatal("supplied result bypassed native policy")
	}
}

func TestLifecycleUploadDoesNotInheritEventCredentials(t *testing.T) {
	// The real event receiver requires a bearer token, while an independently
	// authorized anonymous receiver captures the upload request's actual headers.
	uploadReceiver := &lifecycleReceiver{uploads: map[string]string{}, changed: make(chan struct{})}
	captured := make(chan http.Header, 1)
	descriptors := make(chan Object, 1)
	uploadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- r.Header.Clone()
		recorder := httptest.NewRecorder()
		uploadReceiver.upload(recorder, r, map[string]UploadBinding{"body": {Endpoint: "http://127.0.0.1/anonymous"}})
		var descriptor Object
		if err := json.Unmarshal(recorder.Body.Bytes(), &descriptor); err != nil {
			t.Error(err)
		}
		descriptors <- descriptor
		for key, values := range recorder.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	}))
	defer uploadServer.Close()
	dir := t.TempDir()
	fixture := filepath.Join(dir, "scenario.json")
	req := request("isolation")
	payload := []byte{0, 255, 128, 'x'}
	steps := []Object{{"op": "send", "key": "a", "slot": "a"}, {"op": "wait", "key": "a"}, {"op": "release", "key": "a"}, {"op": "receive", "slot": "a"}, {"op": "accept", "key": "a"}, {"op": "upload", "subscription": "body", "ref": "anonymous-bytes", "bodyBase64": base64.StdEncoding.EncodeToString(payload)}}
	sc := lifecycleScenario{ID: "isolation", Requests: map[string]Object{"a": req}, Responses: map[string]Object{"a": lifecycleReply("isolation")}, Steps: steps}
	if e := writeAtomic(fixture, Object{"scenarios": []lifecycleScenario{sc}}); e != nil {
		t.Fatal(e)
	}
	c := LifecycleConfig{Config: Config{Transport: "http", Auth: Auth{Mode: "bearer", Token: "event-only-secret"}, ReadinessFile: filepath.Join(dir, "ready.json"), ScenarioFile: fixture, ReportFile: filepath.Join(dir, "report.json"), SchemaDir: schemaPath(t)}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- LifecycleServer(ctx, c) }()
	defer func() {
		cancel()
		if e := <-done; e != nil {
			t.Error(e)
		}
	}()
	ready := waitReady(t, c.ReadinessFile)
	c.Endpoint = str(ready["endpoint"])
	c.ControlEndpoint = str(ready["controlEndpoint"])
	c.Upload = UploadBinding{Endpoint: uploadServer.URL + "/anonymous"} // auth OMITTED
	if e := LifecycleClient(ctx, c); e != nil {
		t.Fatal(e)
	}
	select {
	case headers := <-captured:
		if len(headers.Values("Authorization")) != 0 {
			t.Fatal("event Authorization leaked to upload endpoint")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	descriptor := <-descriptors
	if str(descriptor["ref"]) == "" || descriptor["ref"] == "anonymous-bytes" {
		t.Fatal("receiver did not allocate the reference", descriptor)
	}
	uploadReceiver.mu.Lock()
	body := uploadReceiver.uploads[contentKey("body", str(descriptor["ref"]))]
	uploadReceiver.mu.Unlock()
	if body != string(payload) {
		t.Fatal("receiver did not capture exact anonymous bytes")
	}
	var report Object
	if e := Load(c.ReportFile, &report); e != nil {
		t.Fatal(e)
	}
	found := false
	for _, raw := range array(obj(report["receipts"])["entries"]) {
		entry := obj(raw)
		if entry["kind"] == "received" {
			found = true
			if !reflect.DeepEqual(entry["message"], clone(req)) {
				t.Fatal("authenticated event message not retained")
			}
		}
	}
	if !found {
		t.Fatal("no authenticated event exchange")
	}
}
