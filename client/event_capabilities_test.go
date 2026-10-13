package client

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/capability"
)

func eventOptionsRegistration(t *testing.T, name, mode string, policy map[string]any) ahp.Registration {
	t.Helper()
	hooks := []any{}
	if name != "" {
		sub := map[string]any{"events": []string{name}, "mode": mode, "timeoutMs": 1000, "failurePolicy": "fail-open", "content": map[string]any{"default": "metadata"}}
		if mode == "observe" {
			delete(sub, "timeoutMs")
			delete(sub, "failurePolicy")
		}
		for k, v := range policy {
			sub[k] = v
		}
		hooks = append(hooks, map[string]any{"id": "dev.example.events", "transport": map[string]any{"type": "http", "url": "http://127.0.0.1:1/hooks"}, "subscriptions": []any{sub}})
	}
	parsed := ahp.ParseRegistration(sdkJSON(map[string]any{"protocolVersion": "draft", "hooks": hooks}))
	if !parsed.OK {
		t.Fatal(parsed.Diagnostics)
	}
	return parsed.Value
}

func eventOptionsCaps(effects ...string) *ahp.Capabilities {
	caps := &ahp.Capabilities{Effects: []ahp.CapabilitiesEffectsItem{}}
	for _, effect := range effects {
		var value ahp.CapabilitiesEffectsItem
		if err := json.Unmarshal(sdkJSON(effect), &value); err != nil {
			panic(err)
		}
		caps.Effects = append(caps.Effects, value)
	}
	return caps
}

func TestEventOptionsRejectInvalidAuthority(t *testing.T) {
	cases := map[string]capability.Host{
		"absent":            {},
		"zero event":        {ToolBefore: capability.ToolBefore{}},
		"zero modification": {ToolBefore: capability.ToolBefore{ModifyInput: capability.Modify{}}},
		"wrong mode":        {ToolBefore: capability.ToolBefore{Observe: true}},
		"unrelated event":   {SessionEnd: capability.SessionEnd{Observe: true}},
	}
	for name, events := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := New(eventOptionsRegistration(t, "tool.before", "intercept", nil), Options{Source: "urn:test:events", Events: events})
			if c != nil {
				c.Close()
				t.Fatal("invalid configuration acquired a client")
			}
			if err == nil {
				t.Fatal("expected admission error")
			}
		})
	}
}

func TestEventOptionsExplicitModesAndPolicy(t *testing.T) {
	for _, mode := range []string{"intercept", "observe"} {
		t.Run(mode, func(t *testing.T) {
			events := capability.Host{ToolBefore: capability.ToolBefore{Observe: true}}
			if mode == "intercept" {
				events.ToolBefore = capability.ToolBefore{Deny: true}
			}
			c, err := New(eventOptionsRegistration(t, "tool.before", mode, nil), Options{Source: "urn:test:events", Events: events})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if !sdkHas(sdkObj(sdkArray(c.manifest["events"])[0])["modes"], mode) {
				t.Fatal("explicit mode lost")
			}
		})
	}
	for _, policy := range []map[string]any{{"scope": "project"}, {"scope": "managed", "disableable": false}, {"disableable": false}} {
		c, err := New(eventOptionsRegistration(t, "tool.before", "intercept", policy), Options{Source: "urn:test:events", Events: capability.Host{ToolBefore: capability.ToolBefore{Deny: true}}})
		if err == nil {
			c.Close()
			t.Fatal("ordinary options admitted stronger policy")
		}
	}
}

func TestEventOptionsSnapshotAndNarrowing(t *testing.T) {
	declaration := &capability.ToolBefore{Deny: true, Allow: true}
	events := capability.Host{ToolBefore: declaration}
	c, err := New(eventOptionsRegistration(t, "tool.before", "intercept", nil), Options{Source: "urn:test:events", Events: events})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	before := string(sdkJSON(c.manifest))
	declaration.Deny = false
	declaration.ModifyInput = capability.Replace()
	events.ToolBefore = nil
	if string(sdkJSON(c.manifest)) != before {
		t.Fatal("manifest aliases caller data")
	}
	base := sdkObj(sdkObj(sdkArray(c.manifest["events"])[0])["capabilities"])
	if _, _, _, err := resolveOptions(base, []InterceptOption{WithCapabilities(*eventOptionsCaps("deny"))}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := resolveOptions(base, []InterceptOption{WithCapabilities(*eventOptionsCaps("modify"))}); err == nil {
		t.Fatal("per-occurrence options added authority")
	}
	if _, err := c.intercept(context.Background(), "tool.after", map[string]any{}); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("unadvertised boundary: %v", err)
	}
}

func TestEventOptionsMetadataCannotGrantEvents(t *testing.T) {
	reg := eventOptionsRegistration(t, "tool.before", "intercept", nil)
	c, err := New(reg, Options{Source: "urn:test:events", Metadata: testManifestMetadata()})
	if c != nil {
		c.Close()
		t.Fatal("metadata acquired interception authority")
	}
	if err == nil {
		t.Fatal("metadata supplied an event grant")
	}
}

func TestEventOptionsMinimalMetadata(t *testing.T) {
	reg := eventOptionsRegistration(t, "session.start", "intercept", nil)
	c, err := New(reg, Options{Source: "urn:test:events", Events: capability.Host{ToolBefore: capability.ToolBefore{Observe: true}, SessionStart: capability.SessionStart{Message: true}}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	entries := sdkArray(c.manifest["events"])
	if sdkObj(entries[0])["event"] != "session.start" || sdkObj(entries[1])["event"] != "tool.before" {
		t.Fatal("events not sorted")
	}
	for _, key := range []string{"gaps", "authentication", "toolPaths", "contentCategories", "correlationIdentityFields"} {
		if !reflect.DeepEqual(c.manifest[key], []any{}) {
			t.Fatalf("invented %s metadata", key)
		}
	}
	if !reflect.DeepEqual(c.manifest["transports"], []any{"http"}) || !reflect.DeepEqual(c.manifest["limits"], map[string]any{}) {
		t.Fatal("invented transport or limits")
	}
	tr := &testTransport{}
	c.backends[0].transport = tr
	r, err := c.intercept(context.Background(), "session.start", map[string]any{"session": map[string]any{"id": "session-1"}, "harness": map[string]any{"name": "test", "version": "1"}, "trigger": "startup", "permissionMode": "default", "items": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	var delivered map[string]any
	if err := json.Unmarshal(sdkJSON(r.Event), &delivered); err != nil {
		t.Fatal(err)
	}
	if string(sdkJSON(delivered["manifest"])) != string(sdkJSON(c.manifest)) {
		t.Fatal("session.start manifest differs from admitted metadata")
	}
	if len(tr.calls) != 1 {
		t.Fatalf("expected session.start delivery, got %d", len(tr.calls))
	}
}

// These programs exercise the public API from a separate package. Invalid states
// formerly rejected at admission must now be impossible to construct at all.
func TestTypedCapabilityPublicAPI(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(cwd)
	dir := t.TempDir()
	module := fmt.Sprintf("module capabilityconsumer\n\ngo 1.27.0\n\nrequire github.com/agenthooksprotocol/go-sdk v0.0.0\nreplace github.com/agenthooksprotocol/go-sdk => %s\n", filepath.ToSlash(root))
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(module), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, source string
		valid        bool
	}{
		{"all canonical public event names", `func allEvents(h *client.Hooks) { for _, name := range []event.Type{event.ConfigChangeAfter, event.ConfigChangeBefore, event.ContextCompactAfter, event.ContextCompactBefore, event.FileChanged, event.HookFailure, event.ModelError, event.ModelRequestBefore, event.ModelResponseAfter, event.ModelSwitchAfter, event.ModelSwitchBefore, event.SessionEnd, event.SessionStart, event.TaskChangeAfter, event.TaskChangeBefore, event.ToolAfter, event.ToolBatchAfter, event.ToolBefore, event.ToolPermissionRequest, event.ToolPermissionResolved, event.ToolProgress, event.TurnEnd, event.TurnFinishBefore, event.TurnProgress, event.TurnStart, event.UserAttention, event.UserElicitationRequest, event.UserElicitationResult, event.UserMessageInbound, event.UserMessageOutbound, event.WorkspaceChangeAfter, event.WorkspaceChangeBefore} { _ = h.Subscribes(name); _, _ = h.Dispatch(nil, name, nil); _ = client.CapabilityAdmissionError{Event: name}; _ = event.ResponseForRequest(name, nil); _ = event.StageResponseForRequest(name, nil, nil) } }`, true},
		{"typed contextual parsers", `var _ = event.ResponseForRequest(event.ToolBefore, nil); var _ = event.StageResponseForRequest(event.ToolBefore, nil, nil)`, true},
		{"runtime string response parser", `func parse(name string) { _ = event.ResponseForRequest(name, nil) }`, false},
		{"runtime string stage parser", `func stage(name string) { _ = event.StageResponseForRequest(name, nil, nil) }`, false},
		{"typed dispatch event", `func dispatch(h *client.Hooks) { _, _ = h.Dispatch(nil, event.ToolBefore, nil) }`, true},
		{"runtime string dispatch event", `func dispatch(h *client.Hooks, name string) { _, _ = h.Dispatch(nil, name, nil) }`, false},
		{"typed capability diagnostic event", `var _ = client.CapabilityAdmissionError{Event: event.ToolBefore}`, true},
		{"runtime string capability diagnostic event", `func diagnostic(name string) client.CapabilityAdmissionError { return client.CapabilityAdmissionError{Event: name} }`, false},
		{"typed subscription interest", `func interest(h *client.Hooks) bool { return h.Subscribes(event.ToolBefore) }`, true},
		{"runtime string subscription interest", `func interest(h *client.Hooks, name string) bool { return h.Subscribes(name) }`, false},
		{"public example", `var _ = capability.Host{SessionStart: capability.SessionStart{Observe: true}, ToolBefore: capability.ToolBefore{Allow: true, Deny: true, ReturnResult: true, ModifyInput: capability.ReplaceAndMerge(), Observe: true}}`, true},
		{"unknown event", `var _ = capability.Host{ToolUnknown: capability.ToolUnknown{Observe: true}}`, false},
		{"arbitrary modes", `var _ = capability.ToolBefore{Modes: []string{"execute"}}`, false},
		{"wrong event", `var _ = capability.Host{ToolBefore: capability.SessionStart{Message: true}}`, false},
		{"unsupported effect", `var _ = capability.ToolBefore{ModifySummary: capability.Replace()}`, false},
		{"observation only", `var _ = capability.Host{SessionEnd: capability.ToolBefore{Deny: true}}`, false},
		{"wire input", `var _ = capability.Host{ToolBefore: capability.WireDeclaration{}}`, false},
		{"closed declaration", `type external struct{}; var _ = capability.Host{ToolBefore: external{}}`, false},
		{"negative continuation", `var _ = capability.Continue(-1, 0)`, false},
		{"stop only", `var _ = capability.ToolBefore{Flow: capability.Continue(1, 0)}`, false},
		{"arbitrary modification", `var _ = capability.Modify{Operations: []string{"unknown"}}`, false},
		{"legacy Event", `var _ capability.Event`, false},
		{"legacy Mode", `var _ capability.Mode`, false},
		{"legacy builder", `var _ = capability.Intercept()`, false},
		{"legacy New", `var _ = capability.New(nil)`, false},
		{"legacy Grant", `var _ capability.Grant`, false},
		{"raw manifest option", `var _ = client.Options{Manifest: nil}`, false},
		{"metadata event grant", `var _ = client.ManifestMetadata{Events: capability.Host{}}`, false},
		{"legacy With", `var _ = capability.WithInputModification(true, true)`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := "package consumer\nimport (\"github.com/agenthooksprotocol/go-sdk/capability\"; \"github.com/agenthooksprotocol/go-sdk/client\"; \"github.com/agenthooksprotocol/go-sdk/event\")\nvar _ event.Type\nvar _ capability.Host\nvar _ client.Options\n" + tc.source + "\n"
			if err := os.WriteFile(filepath.Join(dir, "consumer.go"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("go", "test", "-mod=mod", ".")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOWORK=off")
			out, err := cmd.CombinedOutput()
			if tc.valid && err != nil {
				t.Fatalf("valid public API failed: %v\n%s", err, out)
			}
			if !tc.valid && err == nil {
				t.Fatal("invalid public API compiled")
			}
			if strings.HasPrefix(tc.name, "runtime string ") && err != nil && (!strings.Contains(string(out), "cannot use name") || !strings.Contains(string(out), "event.Type")) {
				t.Fatalf("expected runtime string type rejection, got: %v\n%s", err, out)
			}
			if !tc.valid && !strings.Contains(string(out), "./consumer.go:") {
				t.Fatalf("compiler did not reject source: %v\n%s", err, out)
			}
		})
	}
}
