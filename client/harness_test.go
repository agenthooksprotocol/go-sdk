package client

import (
	"context"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/event"
)

func TestHarnessRequiredAtConstruction(t *testing.T) {
	for _, identity := range []ahp.Harness{{}, {Name: "test"}, {Version: "1"}} {
		c, err := New(eventOptionsRegistration(t, "tool.before", "intercept", nil), Options{Source: "urn:test:harness", Harness: identity, Events: testHost()})
		if c != nil {
			c.Close()
			t.Fatal("invalid identity acquired client")
		}
		if err == nil || !strings.Contains(err.Error(), "harness") {
			t.Fatalf("invalid identity: %v", err)
		}
	}
}

func TestHarnessSnapshotAndDispatch(t *testing.T) {
	c, transports := testClient(t, "fail-closed")
	identity := ahp.Harness{Name: "test", Version: "1"}
	configured, err := New(eventOptionsRegistration(t, "tool.before", "intercept", nil), Options{Source: "urn:test:harness", Harness: identity, Events: testHost()})
	if err != nil {
		t.Fatal(err)
	}
	defer configured.Close()
	c.opts.Harness = configured.opts.Harness
	identity.Name = "mutated"
	input := testInput()
	input["harness"] = map[string]any{"name": "test", "version": "1"}
	result, err := c.Dispatch(context.Background(), event.ToolBefore, input)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	transports[0].mu.Lock()
	emitted := sdkObj(sdkObj(transports[0].calls[0]["params"])["event"])
	harness := sdkObj(emitted["harness"])
	transports[0].mu.Unlock()
	if harness["name"] != "test" || harness["version"] != "1" {
		t.Fatalf("identity not snapshotted: %v", harness)
	}
	input["harness"] = map[string]any{"name": "other", "version": "1"}
	if _, err := c.Dispatch(context.Background(), event.ToolBefore, input); err == nil {
		t.Fatal("conflicting identity accepted")
	}
	delete(input, "harness")
	result, err = c.Dispatch(context.Background(), event.ToolBefore, input)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
}

func TestWireEventRequiresHarness(t *testing.T) {
	input := testInput()
	input["source"] = "urn:test:wire"
	input["type"] = "tool.before"
	if ahp.ParseEvent(sdkJSON(input)).OK {
		t.Fatal("wire event missing harness accepted")
	}
	input["harness"] = map[string]any{"name": "test", "version": "1"}
	if !ahp.ParseEvent(sdkJSON(input)).OK {
		t.Fatal("valid harness rejected")
	}
}
