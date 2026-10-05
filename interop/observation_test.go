package interop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestDowngradedObservationsDoNotWait(t *testing.T) {
	received := make(chan Object, 3)
	selected := make(chan string, 3)
	release := make(chan struct{})
	defer close(release)
	event := Object{"id": "same", "source": "urn:test", "type": "tool.before", "secret": "effective"}
	DispatchObservations(event, []Object{{"id": "called", "mode": "intercept"}, {"id": "remaining", "mode": "intercept"}, {"id": "explicit", "mode": "observe"}}, map[string]bool{"called": true}, func(event, sub Object) (Object, error) {
		selected <- str(sub["id"])
		delete(event, "secret")
		return event, nil
	}, func(note Object) error { received <- note; <-release; return nil })
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case id := <-selected:
			seen[id] = true
		case <-time.After(time.Second):
			t.Fatal("observer selection blocked")
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case note := <-received:
			params := obj(note["params"])
			if len(params) != 2 || params["subscriptionId"] != nil || note["id"] != nil || obj(params["event"])["id"] != "same" || obj(params["event"])["secret"] != nil {
				t.Fatal(note)
			}
		case <-time.After(time.Second):
			t.Fatal("observer blocked settlement or other observer")
		}
	}
	if seen["called"] || !seen["explicit"] || !seen["remaining"] || event["secret"] != "effective" {
		t.Fatal(seen, event)
	}
}

func TestObservationChainCarriesAcceptedPermission(t *testing.T) {
	for _, reject := range []bool{false, true} {
		req := request("permission-prefix")
		scenario := lifecycleScenario{ID: "permission-prefix", Requests: map[string]Object{"a": req}, Chain: Object{"subscriptions": []any{Object{"id": "first", "mode": "intercept", "failurePolicy": "fail-open", "content": "metadata"}, Object{"id": "second", "mode": "intercept", "failurePolicy": "fail-open", "content": "metadata"}}}}
		calls := 0
		_, _, err := runObservationChain(scenario, func(sent Object) (<-chan lifecycleResult, error) {
			permission := obj(obj(sent["params"])["state"])["permission"]
			expected := "none"
			if calls > 0 && !reject {
				expected = "allow"
			}
			if permission != expected {
				t.Fatalf("call %d permission=%v want=%s", calls, permission, expected)
			}
			effects := []any{Object{"type": "allow"}}
			if reject && calls == 0 {
				effects = append(effects, Object{"type": "unknown"})
			}
			calls++
			done := make(chan lifecycleResult, 1)
			done <- lifecycleResult{response: response("permission-prefix", effects...)}
			return done, nil
		}, func(string, Object) error { return nil }, func(Object) error { return nil }, func(string, Object) error { return nil })
		if err != nil || calls != 2 {
			t.Fatalf("chain result: calls=%d err=%v", calls, err)
		}
		if obj(obj(req["params"])["state"])["permission"] != "none" {
			t.Fatal("mutated fixture state")
		}
	}
}

func TestObservationChainRejectedAcknowledgementsReport(t *testing.T) {
	all, err := lifecycleFixtures("../../agent-hooks-protocol/interop/lifecycle-scenarios.json")
	if err != nil {
		t.Fatal(err)
	}
	var scenarios []lifecycleScenario
	for _, sc := range all {
		if sc.Chain != nil {
			scenarios = append(scenarios, sc)
		}
	}
	if len(scenarios) == 0 {
		t.Fatal("missing chain fixtures")
	}
	dir := t.TempDir()
	cfg := LifecycleConfig{Config: Config{Transport: "http", ScenarioFile: filepath.Join(dir, "fixture.json"), SchemaDir: schemaPath(t), ReadinessFile: filepath.Join(dir, "ready.json"), ReportFile: filepath.Join(dir, "report.json")}}
	if err := writeAtomic(cfg.ScenarioFile, Object{"version": 1, "scenarios": scenarios}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- LifecycleServer(ctx, cfg) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	var ready Object
	for Load(cfg.ReadinessFile, &ready) != nil {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	endpoint := str(ready["endpoint"])
	cfg.ControlEndpoint = str(ready["controlEndpoint"])
	malicious := response("unsolicited-observer", Object{"type": "deny", "reason": "observer must not decide"})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream, err := http.Post(endpoint+r.URL.Path, "application/json", r.Body)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer upstream.Body.Close()
		if r.URL.Path == "/observe" && upstream.StatusCode == http.StatusNoContent {
			_ = json.NewEncoder(w).Encode(malicious)
			return
		}
		w.WriteHeader(upstream.StatusCode)
		_, _ = io.Copy(w, upstream.Body)
	}))
	defer proxy.Close()
	cfg.Endpoint = proxy.URL
	if err := LifecycleClient(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	var report, fixture Object
	if err := Load(cfg.ReportFile, &report); err != nil {
		t.Fatal(err)
	}
	if err := Load("../../agent-hooks-protocol/interop/lifecycle-scenarios.json", &fixture); err != nil {
		t.Fatal(err)
	}
	expected := map[string]Object{}
	for _, raw := range array(fixture["scenarios"]) {
		sc := obj(raw)
		expected[str(sc["id"])] = obj(sc["expected"])
	}
	results := array(report["results"])
	if len(results) != len(scenarios) {
		t.Fatalf("missing chain results: %#v", report)
	}
	for i, raw := range results {
		row := obj(raw)
		want := expected[scenarios[i].ID]
		if !reflect.DeepEqual(row["actual"], want) {
			t.Fatalf("changed canonical outcome: got %#v want %#v", row["actual"], want)
		}
		diagnostics := array(row["observationDiagnostics"])
		observed := array(want["observations"])
		if len(diagnostics) != len(observed) {
			t.Fatalf("missing rejected acknowledgement diagnostics: %#v", row)
		}
		for j, raw := range diagnostics {
			d := obj(raw)
			eventID := obj(obj(scenarios[i].Requests["a"]["params"])["event"])["id"]
			if d["eventId"] != eventID || d["subscription"] != observed[j] || d["kind"] != "invalid-observation-acknowledgement" || d["status"] != float64(200) || !reflect.DeepEqual(d["response"], malicious) {
				t.Fatalf("incorrect delivery diagnostic: %#v", d)
			}
		}
	}
}

func TestObservationChainUnrelatedFailuresRemainFatal(t *testing.T) {
	failure := errors.New("unrelated failure")
	for _, source := range []string{"observe", "control", "validate"} {
		t.Run(source, func(t *testing.T) {
			sc := lifecycleScenario{ID: "ordinary", Requests: map[string]Object{"a": request("ordinary")}, Chain: Object{"subscriptions": []any{Object{"id": "observer", "mode": "observe"}}}}
			actual, diagnostics, err := runObservationChain(sc,
				func(Object) (<-chan lifecycleResult, error) { t.Error("unexpected interception"); return nil, failure },
				func(string, Object) error {
					if source == "control" {
						return failure
					}
					return nil
				},
				func(Object) error {
					if source == "observe" {
						return failure
					}
					return nil
				},
				func(string, Object) error {
					if source == "validate" {
						return failure
					}
					return nil
				})
			if !errors.Is(err, failure) || actual != nil || diagnostics != nil {
				t.Fatalf("unrelated failure recovered: actual=%#v diagnostics=%#v err=%v", actual, diagnostics, err)
			}
		})
	}
}

func TestObservationChainDiagnosticsFollowSubscriptionOrder(t *testing.T) {
	req := request("ordered-diagnostics")
	obj(obj(req["params"])["event"])["items"] = []any{Object{"selection": "metadata"}}
	sc := lifecycleScenario{ID: "ordered-diagnostics", Requests: map[string]Object{"a": req}, Chain: Object{"subscriptions": []any{
		Object{"id": "first", "mode": "observe", "content": "omit"},
		Object{"id": "second", "mode": "observe", "content": "metadata"},
	}}}
	secondReturned := make(chan struct{})
	actual, diagnostics, err := runObservationChain(sc,
		func(Object) (<-chan lifecycleResult, error) {
			t.Error("unexpected interception")
			return nil, errors.New("unexpected interception")
		},
		func(string, Object) error { return nil },
		func(note Object) error {
			if len(array(obj(obj(note["params"])["event"])["items"])) == 0 {
				<-secondReturned
				return &lifecycleObservationAcknowledgementError{Status: 202, Response: Object{"from": "first"}}
			}
			defer close(secondReturned)
			return &lifecycleObservationAcknowledgementError{Status: 200, Response: Object{"from": "second"}}
		}, func(string, Object) error { return nil })
	want := Object{"called": []any{}, "failures": []any{}, "observations": []any{"first", "second"}, "input": obj(obj(obj(req["params"])["event"])["tool"])["input"]}
	if err != nil || !reflect.DeepEqual(actual, want) || len(diagnostics) != 2 {
		t.Fatalf("actual=%#v diagnostics=%#v err=%v", actual, diagnostics, err)
	}
	for i, subscription := range []string{"first", "second"} {
		d := obj(diagnostics[i])
		if d["subscription"] != subscription || d["eventId"] != "ordered-diagnostics" || obj(d["response"])["from"] != subscription {
			t.Fatalf("misattributed diagnostic: %#v", d)
		}
	}
}
