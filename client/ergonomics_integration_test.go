package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/capability"
	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/diagnostic"
	"github.com/agenthooksprotocol/go-sdk/effect"
	"github.com/agenthooksprotocol/go-sdk/event"
	"github.com/agenthooksprotocol/go-sdk/permission"
	"github.com/agenthooksprotocol/go-sdk/state"
)

func TestGeneratedCapabilityCompositionAndBoundaryAdmission(t *testing.T) {
	grant := capability.Replace()
	first := capability.Host{ToolBefore: capability.ToolBefore{Deny: true, ModifyInput: grant, Observe: true}}.Wire()["tool.before"]
	before := string(sdkJSON(first))
	reused := capability.Host{ToolBefore: capability.ToolBefore{ModifyInput: grant}}.Wire()["tool.before"]
	if !reflect.DeepEqual(reused.Capabilities.Modify, first.Capabilities.Modify) {
		t.Fatal("reused modification grant changed authority")
	}
	second := capability.Host{ToolBefore: capability.ToolBefore{ModifyInput: capability.ReplaceAndMerge()}}.Wire()["tool.before"]
	if string(sdkJSON(first)) != before || !reflect.DeepEqual(first.Modes, []string{"intercept", "observe"}) {
		t.Fatal("reused grant mutated declaration or modes")
	}
	base, _ := sdkMap(first.Capabilities)
	var wider ahp.Capabilities
	if err := json.Unmarshal(sdkJSON(second.Capabilities), &wider); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := resolveOptions(base, []InterceptOption{WithCapabilities(wider)}); err == nil {
		t.Fatal("per-call merge widened replace-only grant")
	}
	for _, host := range []capability.Host{{}, {ToolBefore: capability.ToolBefore{}}, {ToolBefore: capability.ToolBefore{ModifyInput: capability.Modify{}}}} {
		if len(host.Wire()) != 0 {
			t.Fatal("zero declaration granted authority")
		}
	}
	zeroModify := capability.Host{ToolBefore: capability.ToolBefore{Deny: true, ModifyInput: capability.Modify{}}}.Wire()["tool.before"]
	if zeroModify.Capabilities.Modify != nil || !reflect.DeepEqual(zeroModify.Capabilities.Effects, []string{"deny"}) {
		t.Fatal("zero modification widened a nonzero event")
	}
	observed := capability.Host{ToolBefore: capability.Observe{}}.Wire()["tool.before"]
	if !reflect.DeepEqual(observed.Modes, []string{"observe"}) || observed.Capabilities != nil {
		t.Fatal("explicit observation added interception")
	}
	var code diagnostic.Code = diagnostic.RemoteRpc
	if code != diagnostic.RemoteRpc {
		t.Fatal("diagnostic vocabulary diverged")
	}
}

func TestGeneratedInitialCandidateAndEffectSemantics(t *testing.T) {
	initial := state.Initial(permission.Allow)
	raw, err := sdkMap(initial)
	if err != nil {
		t.Fatal(err)
	}
	if raw["permission"] != "allow" || raw["candidate"] != nil {
		t.Fatalf("initial=%v", raw)
	}
	candidate, err := state.Candidate[any](nil)
	if err != nil {
		t.Fatal(err)
	}
	withNull, _ := sdkMap(state.Initial(permission.Allow, state.WithCandidate(candidate)))
	c := sdkObj(withNull["candidate"])
	if c == nil {
		t.Fatal("candidate whose value is null became absent")
	}
	if value, ok := c["value"]; !ok || value != nil {
		t.Fatal("null candidate value lost")
	}
	patch, err := effect.ModifyInputReplace(map[string]int{"count": 2})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := sdkMap(patch)
	if payload["type"] != "modify" || payload["target"] != "input" || payload["operation"] != "replace" {
		t.Fatalf("effect=%v", payload)
	}
	if _, err := effect.ModifyInputReplace(make(chan int)); err == nil {
		t.Fatal("unencodable payload silently accepted")
	}
}

func TestNamedSourcesReachAuthorizedReceiverReferences(t *testing.T) {
	for _, mode := range []string{"intercept", "observe"} {
		for _, selection := range []string{"body", "metadata", "omit"} {
			t.Run(mode+"/"+selection, func(t *testing.T) {
				var uploads, deliveries atomic.Int32
				peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/upload" {
						raw, _ := io.ReadAll(r.Body)
						if string(raw) != "owned bytes" {
							t.Errorf("upload=%q", raw)
						}
						uploads.Add(1)
						contentTestConfirm(w, "receiver-allocated", raw)
						return
					}
					var request map[string]any
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					projected := sdkObj(sdkObj(request["params"])["event"])
					if sdkObj(projected["call"])["id"] != "flat-call" || sdkObj(projected["tool"])["name"] != "tool" {
						t.Error("flattened projection lost required facts")
					}
					item := contentTestBody(t, projected)
					if selection == "body" {
						if uploads.Load() != 1 || sdkObj(item["body"])["ref"] != "receiver-allocated" {
							t.Error("event published before receiver reference was verified")
						}
					} else if item["body"] != nil {
						t.Error("unselected body disclosed")
					}
					deliveries.Add(1)
					if request["method"] == "hooks/observe" {
						w.WriteHeader(204)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request["id"], "result": map[string]any{"protocolVersion": "draft", "effects": []any{}}})
				}))
				defer peer.Close()
				sub := contentTestSubscription(peer.URL + "/upload")
				sub["events"] = []any{"tool.before"}
				sub["mode"] = mode
				sub["content"] = map[string]any{"default": selection}
				if mode == "intercept" {
					sub["timeoutMs"] = 1000
					sub["failurePolicy"] = "fail-closed"
				}
				reg := ahp.ParseRegistration(sdkJSON(map[string]any{"protocolVersion": "draft", "hooks": []any{map[string]any{"id": "com.example.source", "transport": map[string]any{"type": "http", "url": peer.URL + "/hooks"}, "subscriptions": []any{sub}}}}))
				if !reg.OK {
					t.Fatal(reg.Diagnostics)
				}
				hooks, err := New(reg.Value, Options{Source: "urn:test:source", Events: capability.Host{ToolBefore: capability.ToolBefore{Deny: true, Observe: true}}, Content: ContentOptions{AllowLoopbackHTTP: true, AuthorizeContent: contentTestAllow, ProjectOpaque: func(_ context.Context, _ ContentAuthorization, _ string, value any) (any, error) { return value, nil }}})
				if err != nil {
					t.Fatal(err)
				}
				defer hooks.Close()
				reader := &sourceTestReader{Reader: strings.NewReader("owned bytes")}
				source := content.NewSource(reader)
				input := event.ToolBeforeInput[map[string]int]{CallID: "flat-call", Name: "tool", Input: map[string]int{"count": 1}, Path: "execute", Origin: "native", ItemsInput: &[]*event.ContentPartInput{{Attachment: &event.AttachmentBodyInput{AttachmentBodyPart: ahp.AttachmentBodyPart{ID: "original-item", MediaType: "application/octet-stream"}, Body: source}}}}
				encoded, err := json.Marshal(input)
				if err != nil || strings.Contains(string(encoded), "Source") {
					t.Fatalf("stream serialized: %s %v", encoded, err)
				}
				result, err := hooks.ToolBefore(context.Background(), input)
				if err != nil || result == nil || len(result.Diagnostics) != 0 {
					t.Fatalf("result=%+v err=%v", result, err)
				}
				if result.Permission != permission.None || !result.InputAvailable || result.Input["count"] != 1 || deliveries.Load() != 1 {
					t.Fatalf("settlement=%+v", result)
				}
				if err := result.Close(); err != nil {
					t.Fatal(err)
				}
				if reader.closes.Load() != 1 {
					t.Fatal("owned source not closed")
				}
				if selection == "body" {
					if reader.reads.Load() == 0 || uploads.Load() != 1 {
						t.Fatal("selected source not uploaded")
					}
				} else if reader.reads.Load() != 0 || uploads.Load() != 0 {
					t.Fatal("metadata/omit consumed body")
				}
			})
		}
	}
}
