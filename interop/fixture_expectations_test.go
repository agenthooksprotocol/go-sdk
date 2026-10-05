package interop

import (
	"reflect"
	"testing"
)

// Reviewed test-only metadata overlays older sibling fixtures without changing
// their wire requests/responses or relaxing exact acceptance/rejection checks.
func withHostRefusalExpectations(t *testing.T, scenarios []Scenario) []Scenario {
	t.Helper()
	var overlay struct {
		Scenarios map[string]struct {
			Tags         []string `json:"tags"`
			HostExpected Object   `json:"hostExpected"`
		} `json:"scenarios"`
	}
	if err := Load("testdata/host-refusal-outcomes.json", &overlay); err != nil {
		t.Fatal(err)
	}
	out := append([]Scenario(nil), scenarios...)
	for i := range out {
		expected, ok := overlay.Scenarios[out[i].ID]
		if !ok {
			continue
		}
		if !out[i].ExpectError || !containsTag(out[i].Tags, "application-invalid") {
			t.Fatalf("host overlay no longer matches %s", out[i].ID)
		}
		if out[i].HostExpected != nil && !reflect.DeepEqual(out[i].HostExpected, expected.HostExpected) {
			t.Fatalf("host expectation diverged for %s", out[i].ID)
		}
		out[i].HostExpected = obj(clone(expected.HostExpected))
	}
	return out
}

func assertHostRefusal(t *testing.T, scenario Scenario, actual Object, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("accepted effects became protocol rejection: %v", err)
	}
	expected := obj(clone(scenario.HostExpected))
	expected["hostInputRejected"] = true
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("host refusal differs: got %#v want %#v", actual, expected)
	}
}

// Mirrors the reviewed observation_chain.py expected_requests oracle: each
// request retains its independently authored content view and accepted permission.
func expectedChainRequests(scenario Object) []Object {
	requests := []Object{}
	permission := str(obj(obj(obj(obj(scenario["requests"])["a"])["params"])["state"])["permission"])
	sequence := array(obj(scenario["responseSequences"])["a"])
	called := array(obj(scenario["expected"])["called"])
	failures := array(obj(scenario["expected"])["failures"])
	for i, raw := range array(obj(scenario["chainProof"])["requests"]) {
		request := obj(clone(raw))
		obj(obj(request["params"])["state"])["permission"] = permission
		requests = append(requests, request)
		if i >= len(sequence) || (i < len(called) && has(failures, str(called[i]))) {
			continue
		}
		for _, rawEffect := range array(obj(obj(sequence[i])["result"])["effects"]) {
			switch obj(rawEffect)["type"] {
			case "deny":
				permission = "deny"
			case "ask":
				if permission != "deny" {
					permission = "ask"
				}
			case "allow":
				if permission == "none" {
					permission = "allow"
				}
			}
		}
	}
	return requests
}
