package client_test

import (
	"encoding/json"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/capability"
	"github.com/agenthooksprotocol/go-sdk/client"
	"github.com/agenthooksprotocol/go-sdk/event"
)

// A consumer can depend on this synchronous API without input or context.
var _ interface{ Subscribes(event.Type) bool } = (*client.Hooks)(nil)
var _ func(*client.Hooks, event.Type) bool = (*client.Hooks).Subscribes
var _ interface{ Intercepts(event.Type) bool } = (*client.Hooks)(nil)
var _ func(*client.Hooks, event.Type) bool = (*client.Hooks).Intercepts

func TestPublicSubscribesIncludesObserveOnly(t *testing.T) {
	var registration ahp.Registration
	if err := json.Unmarshal([]byte(`{"protocolVersion":"draft","hooks":[{"id":"com.example.observer","transport":{"type":"http","url":"http://127.0.0.1:1/hooks"},"subscriptions":[{"events":["tool.*"],"mode":"observe","content":{"default":"body"},"filters":{"toolKinds":["filtered"]}}]}]}`), &registration); err != nil {
		t.Fatal(err)
	}
	hooks, err := client.New(registration, client.Options{Harness: ahp.Harness{Name: "test", Version: "1"}, Source: "urn:test:consumer", Events: capability.Host{ToolAfter: capability.ToolAfter{Observe: true}}})
	if err != nil {
		t.Fatal(err)
	}
	defer hooks.Close()
	if !hooks.Subscribes(event.ToolAfter) {
		t.Fatal("observe-only filtered match must retain preparation")
	}
	for _, eventType := range []event.Type{event.ToolBefore, event.Type("unknown.event"), ""} {
		if hooks.Subscribes(eventType) {
			t.Fatalf("unconfigured event %q has interest", eventType)
		}
	}
}

func TestPublicInterceptsExcludesObserveOnly(t *testing.T) {
	var registration ahp.Registration
	if err := json.Unmarshal([]byte(`{"protocolVersion":"draft","hooks":[{"id":"com.example.mixed","transport":{"type":"http","url":"http://127.0.0.1:1/hooks"},"subscriptions":[{"events":["tool.*"],"mode":"observe","content":{"default":"body"}},{"events":["tool.before"],"mode":"intercept","timeoutMs":1000,"failurePolicy":"fail-closed","content":{"default":"body"}}]}]}`), &registration); err != nil {
		t.Fatal(err)
	}
	hooks, err := client.New(registration, client.Options{Harness: ahp.Harness{Name: "test", Version: "1"}, Source: "urn:test:consumer", Events: capability.Host{ToolBefore: capability.ToolBefore{Deny: true, Observe: true}, ToolAfter: capability.ToolAfter{Observe: true}}})
	if err != nil {
		t.Fatal(err)
	}
	defer hooks.Close()
	if !hooks.Intercepts(event.ToolBefore) {
		t.Fatal("intercept subscription must report interception")
	}
	if !hooks.Subscribes(event.ToolAfter) || hooks.Intercepts(event.ToolAfter) {
		t.Fatal("observe-only subscription must not report interception")
	}
	for _, eventType := range []event.Type{event.Type("unknown.event"), ""} {
		if hooks.Intercepts(eventType) {
			t.Fatalf("unconfigured event %q has interception", eventType)
		}
	}
}
