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

func TestPublicSubscribesIncludesObserveOnly(t *testing.T) {
	var registration ahp.Registration
	if err := json.Unmarshal([]byte(`{"protocolVersion":"draft","hooks":[{"id":"com.example.observer","transport":{"type":"http","url":"http://127.0.0.1:1/hooks"},"subscriptions":[{"events":["tool.*"],"mode":"observe","content":{"default":"body"},"filters":{"toolKinds":["filtered"]}}]}]}`), &registration); err != nil {
		t.Fatal(err)
	}
	hooks, err := client.New(registration, client.Options{Source: "urn:test:consumer", Events: capability.Host{ToolAfter: capability.Observe{}}})
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
