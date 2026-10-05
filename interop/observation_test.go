package interop

import (
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
		_, err := runObservationChain(scenario, func(sent Object) (<-chan lifecycleResult, error) {
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
