package ahp_test

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"math"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/capability"
)

func TestTypedCapabilityHelpers(t *testing.T) {
	var nilObserve *capability.SessionEnd
	var nilEvent *capability.ToolBefore
	var nilFlow *capability.ContinueFlow
	for _, host := range []capability.Host{
		{}, {ToolBefore: capability.ToolBefore{}}, {ToolBefore: nilEvent},
		{SessionEnd: nilObserve}, {TurnFinishBefore: capability.TurnFinishBefore{Flow: nilFlow}},
		{ToolBefore: capability.ToolBefore{ModifyInput: capability.Modify{}, Flow: capability.StopFlow{}, InjectContext: capability.Injection{}}},
		{TurnFinishBefore: capability.TurnFinishBefore{Flow: capability.ContinueFlow{}}},
		{TurnFinishBefore: capability.TurnFinishBefore{Flow: capability.StopContinueFlow{}}},
	} {
		if len(host.Wire()) != 0 {
			t.Fatal("zero declaration invented authority", host.Wire())
		}
	}
	for _, host := range []capability.Host{
		{ToolBefore: capability.ToolBefore{Observe: true}}, {ToolBefore: capability.ToolBefore{Observe: true}},
	} {
		wire := host.Wire()["tool.before"]
		if len(wire.Modes) != 1 || wire.Modes[0] != "observe" || wire.Capabilities != nil {
			t.Fatal("explicit observation acquired interception", wire)
		}
	}
	for _, declaration := range []capability.ToolBefore{{ElicitationForm: true}, {ElicitationURL: true}} {
		wire := (capability.Host{ToolBefore: declaration}).Wire()["tool.before"]
		if len(wire.Modes) != 1 || wire.Modes[0] != "intercept" || wire.Capabilities == nil || len(wire.Capabilities.Effects) != 0 || len(wire.Capabilities.Elicitation) != 1 {
			t.Fatal("elicitation-only grant changed", wire)
		}
	}
	form := (capability.Host{UserElicitationRequest: capability.UserElicitationRequest{ElicitationForm: true}}).Wire()["user.elicitation.request"]
	raw, err := json.Marshal(form)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"modes":["intercept"],"capabilities":{"effects":[],"elicitation":{"form":{}}}}` {
		t.Fatalf("form-only grant changed: %s", raw)
	}
}

func TestHandwrittenTypedCapabilityConstruction(t *testing.T) {
	injection := capability.InjectNow().WithNextTurn().WithNow()
	host := capability.Host{
		ToolBefore:       capability.ToolBefore{Deny: true, ModifyInput: capability.ReplaceAndMerge(), Flow: capability.Stop(), InjectContext: injection, ElicitationForm: true, Observe: true},
		ToolAfter:        capability.ToolAfter{ModifyOutput: capability.Merge()},
		TurnFinishBefore: capability.TurnFinishBefore{Flow: capability.ContinueAndStop(3, 2)},
	}
	first, second := host.Wire(), host.Wire()
	tool := first["tool.before"]
	if len(tool.Modes) != 2 || tool.Modes[0] != "intercept" || tool.Modes[1] != "observe" {
		t.Fatal("explicit modes lost", tool.Modes)
	}
	if !tool.Capabilities.Modify["input"].Replace || !tool.Capabilities.Modify["input"].Merge || len(tool.Capabilities.Effects) != 4 {
		t.Fatal("safe grants lost or duplicated", tool.Capabilities)
	}
	if len(tool.Capabilities.Inject.Context.DeliverAt) != 2 || !tool.Capabilities.Inject.Context.Append {
		t.Fatal("injection composition lost")
	}
	if second["tool.after"].Capabilities.Modify["output"].Replace {
		t.Fatal("merge granted replace")
	}
	// Rendered snapshots, including nested collections and counter pointers, are detached.
	tool.Modes[0] = "changed"
	tool.Capabilities.Effects[0] = "changed"
	tool.Capabilities.Modify["input"] = capability.WireModification{}
	delete(tool.Capabilities.Elicitation, "form")
	tool.Capabilities.Flow.Operations[0] = "changed"
	tool.Capabilities.Inject.Context.DeliverAt[0] = "changed"
	flow := first["turn.finish.before"].Capabilities.Flow
	flow.Operations[0] = "changed"
	*flow.RemainingContinuations = 99
	*flow.ContinuationCount = 99
	want, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(host.Wire())
	if err != nil || string(again) != string(want) {
		t.Fatal("renderer shared mutable state", err)
	}
}

func TestTypedCapabilityFlowSchemaRange(t *testing.T) {
	for _, pair := range [][2]uint64{{0, 0}, {1, 2}, {9007199254740992, 9007199254740992}, {math.MaxUint64, math.MaxUint64}} {
		for _, grant := range []capability.Flow{capability.Continue(pair[0], pair[1]), capability.ContinueAndStop(pair[0], pair[1])} {
			flow := (capability.Host{TurnFinishBefore: capability.TurnFinishBefore{Flow: grant}}).Wire()["turn.finish.before"].Capabilities.Flow
			if flow == nil || *flow.RemainingContinuations != pair[0] || *flow.ContinuationCount != pair[1] {
				t.Fatalf("schema counters changed: %v", pair)
			}
		}
	}
}

func TestTypedCapabilityPublicStaticContract(t *testing.T) {
	const path = "github.com/agenthooksprotocol/go-sdk/capability"
	output, err := exec.Command("go", "list", "-export", "-f", "{{.Export}}", path).CombinedOutput()
	if err != nil {
		t.Fatalf("load public capability API: %v: %s", err, output)
	}
	exportPath := strings.TrimSpace(string(output))
	publicImporter := importer.ForCompiler(token.NewFileSet(), "gc", func(importPath string) (io.ReadCloser, error) {
		if importPath != path {
			return nil, fmt.Errorf("unexpected import %q", importPath)
		}
		return os.Open(exportPath)
	})
	cases := []struct {
		name, declaration string
		valid             bool
	}{
		{"event-specific host", `var _ = capability.Host{ToolBefore: capability.ToolBefore{Allow: true, ModifyInput: capability.ReplaceAndMerge(), Flow: capability.Stop()}, SessionStart: capability.SessionStart{Observe: true}, SessionEnd: capability.SessionEnd{Observe: true}}`, true},
		{"safe continuation", `var _ = capability.Host{TurnFinishBefore: capability.TurnFinishBefore{Flow: capability.ContinueAndStop(0, 18446744073709551615)}}`, true},
		{"safe injection", `var _ = capability.ToolBefore{InjectContext: capability.InjectNow().WithNextTurn()}`, true},
		{"cross-event", `var _ = capability.Host{ToolBefore: capability.ToolAfter{}}`, false},
		{"observation-only", `var _ = capability.Host{SessionEnd: capability.ToolBefore{}}`, false},
		{"shared observation removed", `var _ = capability.Host{SessionEnd: capability.Observe{}}`, false},
		{"wire is output only", `var _ = capability.Host{ToolBefore: capability.WireDeclaration{}}`, false},
		{"unsupported control", `var _ = capability.ToolAfter{Deny: true}`, false},
		{"unsupported target", `var _ = capability.ToolBefore{ModifyOutput: capability.Replace()}`, false},
		{"stop-only flow", `var _ = capability.ToolBefore{Flow: capability.Continue(0, 0)}`, false},
		{"stop-only combined flow", `var _ = capability.ToolBefore{Flow: capability.ContinueAndStop(0, 0)}`, false},
		{"negative counter", `var _ = capability.Continue(-1, 0)`, false},
		{"signed counter", `var count int64; var _ = capability.Continue(count, 0)`, false},
		{"unknown modifier", `var _ = capability.Replace("unknown")`, false},
		{"private modifier", `var _ = capability.Modify{replace: true}`, false},
		{"private flow", `var _ = capability.StopFlow{granted: true}`, false},
		{"private injection", `var _ = capability.Injection{deliveries: []string{"unknown"}}`, false},
	}
	for _, name := range []string{"New", "WithEffects", "WithModify", "WithInputModification", "WithOutputModification", "WithElicitation", "WithElicitationForm", "WithElicitationURL", "WithFlow", "WithInject", "Intercept", "ModifyInput", "FlowContinue", "FlowStop", "InjectContextAppend"} {
		cases = append(cases, struct {
			name, declaration string
			valid             bool
		}{"absent " + name, "var _ = capability." + name, false})
	}
	for _, name := range []string{"Grant", "Event", "Mode", "ModifyOperation"} {
		cases = append(cases, struct {
			name, declaration string
			valid             bool
		}{"absent " + name, "var _ capability." + name, false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "consumer.go", "package consumer\nimport capability \""+path+"\"\n"+tc.declaration, 0)
			if err != nil {
				t.Fatal(err)
			}
			config := types.Config{Importer: publicImporter}
			_, err = config.Check("consumer", fset, []*ast.File{file}, nil)
			if (err == nil) != tc.valid {
				t.Fatalf("public declaration valid=%t: %v", tc.valid, err)
			}
		})
	}
}
