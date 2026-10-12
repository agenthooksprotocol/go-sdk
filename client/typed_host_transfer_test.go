package client

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/capability"
	"github.com/agenthooksprotocol/go-sdk/event"
)

// Keep typed Host construction separate from wire capabilities admission. Raw
// registration admission and subscription ceilings remain in New.
func TestTypedHostConstructionHasNoCapabilitiesJSONAdmission(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "client.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "New" {
			continue
		}
		found = true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.BasicLit:
				if value.Kind == token.STRING && value.Value == `"capabilities-response"` {
					t.Error("typed Host construction admits a capabilities-response JSON document")
				}
			case *ast.SelectorExpr:
				if value.Sel.Name == "ParseCapabilitiesResponse" {
					t.Error("typed Host construction reparses capabilities")
				}
			}
			return true
		})
	}
	if !found {
		t.Fatal("New constructor not found")
	}
}

func TestManifestMetadataValidationDoesNotInspectTypedEvents(t *testing.T) {
	manifest, err := manifestForOptions(eventOptionsRegistration(t, "tool.before", "intercept", nil), Options{})
	if err != nil {
		t.Fatal(err)
	}
	// An unmarshalable sentinel proves that event grants never enter even an
	// indirect JSON serialization or validation path in the metadata check.
	manifest["events"] = make(chan struct{})
	if err := validateManifestMetadata(manifest); err != nil {
		t.Fatalf("metadata admission inspected typed events: %v", err)
	}
	manifest["transports"] = []any{"networksettings"}
	if err := validateManifestMetadata(manifest); err == nil {
		t.Fatal("metadata admission skipped invalid non-event fields")
	}
}

func TestTypedHostTransferPreservesContinuationMaximum(t *testing.T) {
	host := capability.Host{TurnFinishBefore: capability.TurnFinishBefore{Flow: capability.ContinueAndStop(2, 1).WithMaxContinuations(3), Observe: true}}
	h, err := New(eventOptionsRegistration(t, "turn.finish.before", "intercept", nil), Options{Source: "urn:test:flow-max", Events: host})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	caps := sdkObj(sdkObj(sdkArray(h.manifest["events"])[0])["capabilities"])
	flow := sdkObj(caps["flow"])
	want := map[string]any{"operations": []any{"continue", "stop"}, "remainingContinuations": json.Number("2"), "continuationCount": json.Number("1"), "maxContinuations": json.Number("3")}
	if !reflect.DeepEqual(flow, want) {
		t.Fatalf("typed flow transfer changed: %v", flow)
	}
	output := host.Wire()
	*output["turn.finish.before"].Capabilities.Flow.MaxContinuations = 99
	if !reflect.DeepEqual(flow, want) {
		t.Fatal("renderer output mutated stored grants")
	}
}

func TestTypedHostElicitationOnlyIsValidInterception(t *testing.T) {
	host := capability.Host{ToolBefore: capability.ToolBefore{ElicitationForm: true}}
	h, err := New(eventOptionsRegistration(t, "tool.before", "intercept", nil), Options{Source: "urn:test:facility", Events: host})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	entry := sdkObj(sdkArray(h.manifest["events"])[0])
	caps := sdkObj(entry["capabilities"])
	if !reflect.DeepEqual(entry["modes"], []any{"intercept"}) || !reflect.DeepEqual(caps["effects"], []any{}) || !reflect.DeepEqual(caps["elicitation"], map[string]any{"form": map[string]any{}}) {
		t.Fatalf("facility manufactured effect authority: %v", entry)
	}
	if !h.Subscribes(event.ToolBefore) {
		t.Fatal("elicitation-only subscriber omitted")
	}
}
