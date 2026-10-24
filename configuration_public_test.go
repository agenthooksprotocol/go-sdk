package ahp_test

import (
	"encoding/json"
	"testing"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/event"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
	"github.com/agenthooksprotocol/go-sdk/registration"
	"github.com/agenthooksprotocol/go-sdk/server"
	"github.com/agenthooksprotocol/go-sdk/subscription"
	"github.com/agenthooksprotocol/go-sdk/transport"
)

func TestSharedConfigurationPublicSurface(t *testing.T) {
	intercept := subscription.NewIntercept(event.ToolBefore, 750*time.Millisecond, subscription.FailOpen, content.Metadata())
	observe := subscription.NewObserve(content.Metadata(), event.ToolAfter)
	configuration := ahp.NewConfiguration(intercept).Subscribe(observe)
	if _, err := server.NewHandler(server.Handlers{Configuration: configuration}, server.Options{}); err != nil {
		t.Fatal(err)
	}
	// The same subscription declaration works in explicit client registration.
	explicit := registration.New(registration.NewBackend("com.example.policy", transport.NewHttp("https://example.test/hooks"), intercept, registration.WithBackendSubscriptions(intercept, observe)))
	encoded, err := json.Marshal(explicit)
	if err != nil || !ahp.ParseRegistration(encoded).OK {
		t.Fatalf("explicit configuration invalid: %s %v", encoded, err)
	}
	// Omission is separate from an explicit empty collection.
	discovered := registration.New(registration.NewDiscoveredBackend("com.example.policy", transport.NewHttp("https://example.test/hooks")))
	encoded, err = json.Marshal(discovered)
	if err != nil || !ahp.ParseRegistration(encoded).OK {
		t.Fatalf("discovered registration invalid: %s %v", encoded, err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	backend := wire["hooks"].([]any)[0].(map[string]any)
	if _, exists := backend["subscriptions"]; exists {
		t.Fatal("discovery constructor supplied explicit subscriptions")
	}
	empty := registration.New(registration.NewDiscoveredBackend("com.example.policy", transport.NewHttp("https://example.test/hooks"), registration.WithBackendSubscriptions()))
	encoded, err = json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.Validate("registration", encoded) == nil {
		t.Fatal("explicit empty subscriptions became discovery")
	}
}
