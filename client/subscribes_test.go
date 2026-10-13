package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
	"github.com/agenthooksprotocol/go-sdk/capability"
	"github.com/agenthooksprotocol/go-sdk/event"
)

func TestSubscribesStaticInterest(t *testing.T) {
	for _, tc := range []struct {
		name, selector, mode string
		query                event.Type
		filtered, want       bool
	}{
		{name: "unrelated selector", selector: "tool.after", mode: "observe", query: event.ToolBefore},
		{name: "exact", selector: "tool.before", mode: "intercept", query: event.ToolBefore, want: true},
		{name: "global wildcard", selector: "*", mode: "intercept", query: event.ToolBefore, want: true},
		{name: "prefix wildcard", selector: "tool.*", mode: "intercept", query: event.ToolBefore, want: true},
		{name: "prefix is not bare namespace", selector: "tool.*", mode: "intercept", query: event.Type("tool")},
		{name: "unrelated namespace", selector: "tool.*", mode: "intercept", query: event.SessionStart},
		{name: "observe only", selector: "tool.after", mode: "observe", query: event.ToolAfter, want: true},
		{name: "filtered exact", selector: "tool.before", mode: "intercept", query: event.ToolBefore, filtered: true, want: true},
		{name: "filtered observer", selector: "tool.before", mode: "observe", query: event.ToolBefore, filtered: true, want: true},
		{name: "intercept fallback observation", selector: "tool.*", mode: "intercept", query: event.ToolAfter, want: true},
		{name: "wildcard unknown", selector: "*", mode: "observe", query: event.Type("unknown.event")},
		{name: "wildcard unconfigured", selector: "*", mode: "observe", query: event.SessionEnd},
		{name: "wildcard empty", selector: "*", mode: "observe", query: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hooks := []any{}
			if tc.selector != "" {
				sub := map[string]any{"events": []any{tc.selector}, "mode": tc.mode, "content": map[string]any{"default": "body"}}
				if tc.mode == "intercept" {
					sub["timeoutMs"] = 1000
					sub["failurePolicy"] = "fail-closed"
				}
				if tc.filtered {
					sub["filters"] = map[string]any{"toolKinds": []any{"never-matches-without-input"}, "paths": []any{"execute"}}
				}
				hooks = append(hooks, map[string]any{"id": "com.example.interest", "transport": map[string]any{"type": "http", "url": "http://127.0.0.1/hooks"}, "subscriptions": []any{sub}})
			}
			reg := ahp.ParseRegistration(sdkJSON(map[string]any{"protocolVersion": "draft", "hooks": hooks}))
			if !reg.OK {
				t.Fatal(reg.Diagnostics)
			}
			h, err := New(reg.Value, Options{Source: "urn:test:interest", AuthProvider: interestAuth{t}, EventClient: &http.Client{Transport: interestHTTP{t}}, UploadClient: &http.Client{Transport: interestHTTP{t}}, Events: capability.Host{ToolBefore: capability.ToolBefore{Deny: true, Observe: true}, ToolAfter: capability.ToolAfter{Observe: true}, SessionStart: capability.SessionStart{Observe: true}}, Content: ContentOptions{
				AuthorizeContent: func(context.Context, ContentAuthorization) (bool, error) {
					t.Fatal("content authorization in lookup")
					return false, nil
				},
				Resolver: func(context.Context, string) (io.ReadCloser, error) {
					t.Fatal("content preparation in lookup")
					return nil, nil
				},
				ProjectOpaque: func(context.Context, ContentAuthorization, string, any) (any, error) {
					t.Fatal("projection in lookup")
					return nil, nil
				},
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			transports := []*testTransport{}
			for i := range h.backends {
				h.backends[i].transport.Close()
				tr := &testTransport{reply: func(map[string]any) []any { t.Fatal("backend contact in lookup"); return nil }}
				h.backends[i].transport = tr
				transports = append(transports, tr)
			}
			snapshot, _ := json.Marshal([]any{h.manifest, subscriptionsForTest(h)})
			for i := 0; i < 3; i++ {
				if got := h.Subscribes(tc.query); got != tc.want {
					t.Fatalf("Subscribes(%q)=%v, want %v", tc.query, got, tc.want)
				}
			}
			after, _ := json.Marshal([]any{h.manifest, subscriptionsForTest(h)})
			if string(snapshot) != string(after) {
				t.Fatal("lookup mutated configuration")
			}
			for _, tr := range transports {
				if len(tr.calls) != 0 {
					t.Fatal("lookup delivered an observation or interception")
				}
			}
		})
	}
}

func subscriptionsForTest(h *Hooks) []any {
	out := []any{}
	for _, b := range h.backends {
		out = append(out, b.subscriptions)
	}
	return out
}

type interestHTTP struct{ t *testing.T }

func (s interestHTTP) RoundTrip(*http.Request) (*http.Response, error) {
	s.t.Fatal("HTTP contact in lookup")
	return nil, nil
}

type interestAuth struct{ t *testing.T }

func (s interestAuth) Credential(context.Context, auth.Request) (auth.Credential, error) {
	s.t.Fatal("authentication in lookup")
	return auth.Credential{}, nil
}
func (s interestAuth) Challenge(context.Context, auth.Request, auth.Challenge) (*auth.Credential, error) {
	s.t.Fatal("authentication challenge in lookup")
	return nil, nil
}

func TestSubscribesWithoutSubscribers(t *testing.T) {
	// Canonical registration requires at least one backend and subscription.
	// Exercise the empty lookup directly without weakening admission.
	for _, h := range []*Hooks{nil, {}, {manifest: map[string]any{"events": []any{map[string]any{"event": "tool.before", "modes": []any{"intercept", "observe"}}}}}} {
		if h.Subscribes(event.ToolBefore) {
			t.Fatal("no subscriptions must mean no interest")
		}
	}
}

func TestSubscribesAllCanonicalEvents(t *testing.T) {
	events := []event.Type{event.ConfigChangeAfter, event.ConfigChangeBefore, event.ContextCompactAfter, event.ContextCompactBefore, event.FileChanged, event.HookFailure, event.ModelError, event.ModelRequestBefore, event.ModelResponseAfter, event.ModelSwitchAfter, event.ModelSwitchBefore, event.SessionEnd, event.SessionStart, event.TaskChangeAfter, event.TaskChangeBefore, event.ToolAfter, event.ToolBatchAfter, event.ToolBefore, event.ToolPermissionRequest, event.ToolPermissionResolved, event.ToolProgress, event.TurnEnd, event.TurnFinishBefore, event.TurnProgress, event.TurnStart, event.UserAttention, event.UserElicitationRequest, event.UserElicitationResult, event.UserMessageInbound, event.UserMessageOutbound, event.WorkspaceChangeAfter, event.WorkspaceChangeBefore}
	if len(events) != 32 {
		t.Fatalf("expected 32 canonical event constants, got %d", len(events))
	}
	for _, eventType := range events {
		t.Run(string(eventType), func(t *testing.T) {
			h := &Hooks{manifest: map[string]any{"events": []any{map[string]any{"event": string(eventType), "modes": []any{"observe"}}}}, backends: []registeredBackend{{subscriptions: []map[string]any{{"events": []any{"*"}, "mode": "observe"}}}}}
			if !h.Subscribes(eventType) {
				t.Fatal("configured canonical event lacks static interest")
			}
		})
	}
}
