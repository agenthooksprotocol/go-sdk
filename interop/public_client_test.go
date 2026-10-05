package interop

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPublicClientComposesBeforeHostSchemaRefusal(t *testing.T) {
	req := request("public-client")
	req["id"] = "fixture-rpc-id"
	calls := 0
	actual, rejected, err := publicIntercept(context.Background(), req, func(_ context.Context, method string, body []byte) ([]byte, error) {
		calls++
		var delivered Object
		if err := json.Unmarshal(body, &delivered); err != nil {
			return nil, err
		}
		if method != "hooks/intercept" || delivered["id"] == req["id"] {
			t.Fatal("public client did not own the RPC envelope")
		}
		sent := obj(obj(delivered["params"])["event"])
		if sent["source"] != "urn:ahp:interop" || sent["id"] != "public-client" || obj(sent["session"])["id"] != "test" {
			t.Fatalf("host input lost: %#v", sent)
		}
		return jsonBytes(response(str(delivered["id"]), Object{"type": "message", "text": "accepted"}, Object{"type": "modify", "target": "input", "operation": "replace", "value": Object{"task": float64(0)}})), nil
	})
	if err != nil || rejected || calls != 1 {
		t.Fatalf("public dispatch: actual=%#v rejected=%v calls=%d err=%v", actual, rejected, calls, err)
	}
	if actual["executed"] != false || actual["hostInputRejected"] != true || !reflect.DeepEqual(actual["input"], Object{"task": float64(0)}) || !reflect.DeepEqual(actual["messages"], []any{"accepted"}) {
		t.Fatalf("lost accepted effects: %#v", actual)
	}
}

func TestPublicClientRejectsAdversarialResponse(t *testing.T) {
	_, rejected, err := publicIntercept(context.Background(), request("bad"), func(_ context.Context, _ string, body []byte) ([]byte, error) {
		var delivered Object
		if err := json.Unmarshal(body, &delivered); err != nil {
			return nil, err
		}
		return jsonBytes(response(str(delivered["id"]), Object{"type": "unknown"})), nil
	})
	if err == nil || !rejected {
		t.Fatalf("adversarial response not rejected: %v %v", rejected, err)
	}
}

func TestPublicClientOmittedState(t *testing.T) {
	req := request("omitted-state")
	delete(obj(req["params"]), "state")
	actual, rejected, err := publicIntercept(context.Background(), req, func(_ context.Context, _ string, body []byte) ([]byte, error) {
		var sent Object
		if err := json.Unmarshal(body, &sent); err != nil {
			return nil, err
		}
		return jsonBytes(response(str(sent["id"]), []any{}...)), nil
	})
	if err != nil || rejected || actual["executed"] != true {
		t.Fatalf("omitted state rejected: %#v %v %v", actual, rejected, err)
	}
}

func TestPublicReportHostRefusalAndSettledRaw(t *testing.T) {
	validator, err := NewValidator(schemaPath(t))
	if err != nil {
		t.Fatal(err)
	}
	host := request("host-refusal-report")
	settled := request("settled-raw")
	obj(obj(settled["params"])["state"])["permission"] = "deny"
	fixtures := []Scenario{
		{ID: "host-refusal-report", Request: wire(host), Response: wire(response("host-refusal-report", Object{"type": "message", "text": "retained"}, Object{"type": "modify", "target": "input", "operation": "replace", "value": Object{"task": float64(0)}})), ExpectError: true, Tags: []string{"application-invalid"}, HostExpected: Object{"decision": "allow", "executed": false, "input": Object{"task": float64(0)}, "messages": []any{"retained"}}},
		{ID: "settled-raw", Request: wire(settled), Response: wire(response("settled-raw", Object{"type": "allow"})), Expected: Object{"decision": "deny", "executed": false}},
	}
	state := &serverState{validator: validator, scenarios: fixtures, barriers: map[string]chan struct{}{}}
	handler, err := state.publicHandler(nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/intercept", handler)
	mux.HandleFunc("/capabilities", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(Capabilities()) })
	receiver := httptest.NewServer(mux)
	defer receiver.Close()
	dir := t.TempDir()
	config := Config{Transport: "http", Endpoint: receiver.URL, ScenarioFile: filepath.Join(dir, "scenarios.json"), ReportFile: filepath.Join(dir, "report.json"), SchemaDir: schemaPath(t)}
	if err := writeAtomic(config.ScenarioFile, Object{"scenarios": fixtures}); err != nil {
		t.Fatal(err)
	}
	if err := Client(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Results []Result `json:"results"`
	}
	if err := Load(config.ReportFile, &report); err != nil {
		t.Fatal(err)
	}
	result := report.Results[0]
	if result.Status != "passed" || result.SDKAccepted == nil || !*result.SDKAccepted || result.HostAccepted == nil || *result.HostAccepted || result.RejectionLayer != "host-input-schema" || !reflect.DeepEqual(result.Actual, fixtures[0].HostExpected) {
		t.Fatalf("wrong host refusal report: %#v", result)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.requests) != 2 {
		t.Fatalf("unexpected deliveries: %d", len(state.requests))
	}
	receipt := obj(state.requests[1])
	if receipt["method"] != "hooks/intercept" || !reflect.DeepEqual(receipt["message"], settled) {
		t.Fatalf("settled fixture was not raw: %#v", receipt)
	}
}
