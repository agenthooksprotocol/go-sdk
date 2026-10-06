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
	operations := []capability.ModifyOperation{capability.Replace}
	grant := capability.ModifyInput(operations...)
	operations[0] = capability.Merge
	first, err := capability.Intercept(capability.Deny(), grant)
	if err != nil {
		t.Fatal(err)
	}
	before := string(sdkJSON(first.Capabilities))
	second, err := capability.Intercept(grant, capability.ModifyInput(capability.Merge))
	if err != nil {
		t.Fatal(err)
	}
	if string(sdkJSON(first.Capabilities)) != before || !reflect.DeepEqual(first.Modes, []Mode{Intercept, Observe}) {
		t.Fatal("reused grant mutated declaration or modes")
	}
	base, _ := sdkMap(first.Capabilities)
	if _, _, _, err := resolveOptions(base, []InterceptOption{WithCapabilities(*second.Capabilities)}); err == nil {
		t.Fatal("per-call merge widened replace-only grant")
	}
	if _, err := capability.Intercept(); err == nil {
		t.Fatal("empty declaration accepted")
	}
	if _, err := capability.Intercept(capability.ModifyInput()); err == nil {
		t.Fatal("empty operation set accepted")
	}
	if _, err := capability.Intercept(capability.ModifyInput("unknown")); err == nil {
		t.Fatal("unknown operation accepted")
	}
	wrong, err := capability.Intercept(capability.ModifySummary(capability.Replace))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(eventOptionsRegistration(t, "tool.before", "intercept", nil), Options{Source: "urn:test:generated", Events: map[event.Type]capability.Event{event.ToolBefore: wrong}})
	if c != nil {
		c.Close()
		t.Fatal("incompatible generated declaration acquired client")
	}
	if err == nil {
		t.Fatal("boundary incompatibility accepted")
	}
	if !reflect.DeepEqual(capability.Observe().Modes, []Mode{Observe}) {
		t.Fatal("observe constructor added interception")
	}
	// Numeric limits are always checked by canonical runtime admission even
	// when a generated parser only checks the structural capability shape.
	if invalid, buildErr := capability.Intercept(capability.FlowContinue(-1, 0)); buildErr == nil {
		c, admissionErr := New(eventOptionsRegistration(t, event.TurnFinishBefore, "intercept", nil), Options{Source: "urn:test:generated", Events: map[event.Type]capability.Event{event.TurnFinishBefore: invalid}})
		if c != nil {
			c.Close()
			t.Fatal("negative continuation count admitted")
		}
		if admissionErr == nil {
			t.Fatal("invalid limits reached delivery")
		}
	}
	var code diagnostic.Code = DeliveryRemoteRPC
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
				declaration, err := capability.Intercept(capability.Deny())
				if err != nil {
					t.Fatal(err)
				}
				hooks, err := New(reg.Value, Options{Source: "urn:test:source", Events: map[event.Type]capability.Event{event.ToolBefore: declaration}, Content: ContentOptions{AllowLoopbackHTTP: true, AuthorizeContent: contentTestAllow, ProjectOpaque: func(_ context.Context, _ ContentAuthorization, _ string, value any) (any, error) { return value, nil }}})
				if err != nil {
					t.Fatal(err)
				}
				defer hooks.Close()
				var descriptor ahp.ContentItem
				if err := json.Unmarshal([]byte(`{"id":"original-item","kind":"message","mediaType":"text/plain","selection":"metadata"}`), &descriptor); err != nil {
					t.Fatal(err)
				}
				reader := &sourceTestReader{Reader: strings.NewReader("owned bytes")}
				source := content.NewSource(reader)
				input := event.ToolBeforeInput[map[string]int]{CallID: "flat-call", Name: "tool", Input: map[string]int{"count": 1}, Path: "execute", Origin: "native", Items: ahp.Some([]*ahp.ContentItem{&descriptor}), ItemsSources: []*content.Source{source}}
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
