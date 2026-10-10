package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
	"github.com/agenthooksprotocol/go-sdk/capability"
	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/event"
)

type budgetIntegrationTransport struct {
	check func(context.Context)
	calls atomic.Int32
}

func (tr *budgetIntegrationTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tr.check(r.Context())
	tr.calls.Add(1)
	return http.DefaultTransport.RoundTrip(r)
}

func TestNamedSourceOuterBudgetThroughAuthRetryAndOwnedObservation(t *testing.T) {
	// Every phase limit exceeds the outer budget. None may replace that deadline,
	// including credential acquisition, actual challenge recovery, or observations.
	deadline := time.Now().Add(10 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	checkDeadline := func(ctx context.Context) {
		t.Helper()
		got, ok := ctx.Deadline()
		if !ok || !got.Equal(deadline) {
			t.Errorf("phase deadline=%v present=%v; want unchanged root %v", got, ok, deadline)
		}
		if err := ctx.Err(); err != nil {
			t.Errorf("unexpected expired phase: %v", err)
		}
	}

	var mu sync.Mutex
	var sequence []string
	var firstBody []byte
	var firstID any
	uploads, intercepts, observations := 0, 0, 0
	var interceptRef, observationRef string
	confirmed := map[string]bool{}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/upload" {
			if r.Header.Get("Authorization") != "Bearer upload-token" {
				t.Error("event credential leaked into upload")
			}
			if string(raw) != "owned budget bytes" {
				t.Errorf("upload bytes=%q", raw)
			}
			uploads++
			sequence = append(sequence, fmt.Sprintf("upload-%d", uploads))
			ref := fmt.Sprintf("receiver-%d", uploads)
			confirmed[ref] = true
			contentTestConfirm(w, ref, raw)
			return
		}
		if r.URL.Path != "/hooks" {
			t.Errorf("unexpected endpoint %q", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		var request map[string]any
		if err := json.Unmarshal(raw, &request); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		projected := sdkObj(sdkObj(request["params"])["event"])
		if sdkObj(projected["call"])["id"] != "budget-call" || sdkObj(projected["tool"])["name"] != "budget-tool" {
			t.Error("named input lost flattened facts")
		}
		item := contentTestBody(t, projected)
		if request["method"] == "hooks/observe" {
			observations++
			sequence = append(sequence, "observe")
			observationRef = compositionString(sdkObj(item["body"])["ref"])
			if uploads != 2 || !confirmed[observationRef] || observationRef == interceptRef {
				t.Error("observer published without its verified receiver upload")
			}
			if r.Header.Get("Authorization") != "Bearer event-observer" {
				t.Error("observer did not use event binding")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if request["method"] != "hooks/intercept" {
			t.Errorf("unexpected method=%v", request["method"])
		}
		intercepts++
		sequence = append(sequence, fmt.Sprintf("intercept-%d", intercepts))
		ref := compositionString(sdkObj(item["body"])["ref"])
		if interceptRef == "" {
			interceptRef = ref
		}
		if uploads != 2 || !confirmed[ref] || ref != interceptRef {
			t.Error("intercept/retry did not retain verified first upload")
		}
		if intercepts == 1 {
			firstBody = bytes.Clone(raw)
			firstID = request["id"]
			if firstID == nil || projected["id"] != firstID {
				t.Error("missing initial request/event identity")
			}
			if r.Header.Get("Authorization") != "Bearer event-stale" {
				t.Error("first intercept credential mismatch")
			}
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			w.Header().Set("X-Budget-Challenge", "actual-401")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if intercepts != 2 || !bytes.Equal(firstBody, raw) || request["id"] != firstID {
			t.Error("challenge retry changed request bytes/identity or exceeded retry limit")
		}
		if r.Header.Get("Authorization") != "Bearer event-fresh" {
			t.Error("challenge replacement credential not used")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request["id"], "result": map[string]any{"protocolVersion": "draft", "effects": []any{}}})
	}))
	defer peer.Close()

	const backendID = "com.example.budget"
	var uploadCredentials, eventCredentials, challenges, authorizations atomic.Int32
	attempt := &struct{ label string }{"first-event-credential"}
	checkScope := func(request auth.Request, purpose auth.Operation, ref, destination string) {
		t.Helper()
		var binding map[string]any
		if err := json.Unmarshal(request.Binding, &binding); err != nil {
			t.Error(err)
		}
		if request.Purpose != purpose || request.BackendID != backendID || request.Destination != destination || binding["type"] != "bearer" || binding["tokenRef"] != ref {
			t.Errorf("wrong auth scope: %+v binding=%v", request, binding)
		}
	}
	provider := clientAuthProvider{
		credential: func(ctx context.Context, request auth.Request) (auth.Credential, error) {
			checkDeadline(ctx)
			if request.Purpose == auth.Upload {
				checkScope(request, auth.Upload, "upload-binding", peer.URL+"/upload")
				uploadCredentials.Add(1)
				return auth.Credential{Type: "bearer", Token: "upload-token"}, nil
			}
			checkScope(request, auth.Event, "event-binding", peer.URL+"/hooks")
			n := eventCredentials.Add(1)
			if n == 1 {
				return auth.Credential{Type: "bearer", Token: "event-stale", Attempt: attempt}, nil
			}
			if n != 2 {
				t.Errorf("unexpected event credential acquisition %d", n)
			}
			return auth.Credential{Type: "bearer", Token: "event-observer"}, nil
		},
		challenge: func(ctx context.Context, request auth.Request, rejection auth.Challenge) (*auth.Credential, error) {
			checkDeadline(ctx)
			checkScope(request, auth.Event, "event-binding", peer.URL+"/hooks")
			challenges.Add(1)
			if rejection.StatusCode != 401 || rejection.Attempt != attempt || rejection.Header.Get("WWW-Authenticate") != `Bearer error="invalid_token"` || rejection.Header.Get("X-Budget-Challenge") != "actual-401" {
				t.Errorf("challenge lost actual rejection or attempt identity: %+v", rejection)
			}
			return &auth.Credential{Type: "bearer", Token: "event-fresh"}, nil
		},
	}
	subscription := func(mode string) map[string]any {
		sub := contentTestSubscription(peer.URL + "/upload")
		sub["id"] = "budget-" + mode
		sub["events"] = []any{"tool.before"}
		sub["mode"] = mode
		sdkObj(sub["upload"])["timeoutMs"] = 60000
		sdkObj(sub["upload"])["auth"] = map[string]any{"type": "bearer", "tokenRef": "upload-binding"}
		if mode == "intercept" {
			sub["timeoutMs"] = 60000
			sub["failurePolicy"] = "fail-closed"
		}
		return sub
	}
	registration := ahp.ParseRegistration(sdkJSON(map[string]any{"protocolVersion": "draft", "hooks": []any{map[string]any{
		"id": backendID, "transport": map[string]any{"type": "http", "url": peer.URL + "/hooks"},
		"authentication": map[string]any{"type": "bearer", "tokenRef": "event-binding"},
		"subscriptions":  []any{subscription("intercept"), subscription("observe")},
	}}}))
	if !registration.OK {
		t.Fatal(registration.Diagnostics)
	}
	declaration, err := capability.Intercept(capability.Deny())
	if err != nil {
		t.Fatal(err)
	}
	transport := &budgetIntegrationTransport{check: checkDeadline}
	hooks, err := New(registration.Value, Options{
		Source: "urn:test:budget", Events: map[event.Type]capability.Event{event.ToolBefore: declaration}, AuthProvider: provider,
		EventClient: &http.Client{Transport: transport}, UploadClient: &http.Client{Transport: transport}, ObservationTimeout: time.Minute,
		Content: ContentOptions{AllowLoopbackHTTP: true,
			AuthorizeContent: func(ctx context.Context, scope ContentAuthorization) (bool, error) {
				checkDeadline(ctx)
				authorizations.Add(1)
				return true, nil
			},
			ProjectOpaque: func(ctx context.Context, _ ContentAuthorization, _ string, value any) (any, error) {
				checkDeadline(ctx)
				return value, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hooks.Close()
	var descriptor ahp.ContentItem
	if err := json.Unmarshal([]byte(`{"id":"budget-item","kind":"attachment","mediaType":"application/octet-stream","selection":"metadata"}`), &descriptor); err != nil {
		t.Fatal(err)
	}
	reader := &sourceTestReader{Reader: strings.NewReader("owned budget bytes")}
	source := content.NewSource(reader)
	input := event.ToolBeforeInput[map[string]int]{CallID: "budget-call", Name: "budget-tool", Input: map[string]int{"count": 1}, Path: "execute", Origin: "native", Items: ahp.Some([]*ahp.ContentItem{&descriptor}), ItemsSources: []*content.Source{source}}
	result, err := hooks.ToolBefore(ctx, input)
	if err != nil || result == nil {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if result.Interrupted || !result.InputAvailable || result.Input["count"] != 1 || len(result.Diagnostics) != 0 {
		t.Fatalf("unexpected settlement: %+v", result)
	}
	select {
	case <-result.Observations.Done():
	default:
		t.Fatal("observer still running after owned operation returned")
	}
	if reader.reads.Load() != 2 || reader.closes.Load() != 1 {
		t.Fatalf("source was reread or not closed: reads=%d closes=%d", reader.reads.Load(), reader.closes.Load())
	}
	if uploadCredentials.Load() != 2 || eventCredentials.Load() != 2 || challenges.Load() != 1 || authorizations.Load() != 4 || transport.calls.Load() != 5 {
		t.Fatalf("auth/transport counts: uploads=%d events=%d challenges=%d authorizations=%d exchanges=%d", uploadCredentials.Load(), eventCredentials.Load(), challenges.Load(), authorizations.Load(), transport.calls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"upload-1", "upload-2", "intercept-1", "intercept-2", "observe"}
	if uploads != 2 || intercepts != 2 || observations != 1 || !reflect.DeepEqual(sequence, want) {
		t.Fatalf("delivery order=%v; want %v", sequence, want)
	}
}
