package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
	"github.com/agenthooksprotocol/go-sdk/capability"
	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/event"
	"github.com/agenthooksprotocol/go-sdk/server"
)

func discoveryRegistration(t *testing.T, url string, explicit any) ahp.Registration {
	t.Helper()
	backend := map[string]any{"id": "com.example.configuration", "transport": map[string]any{"type": "http", "url": url, "headers": map[string]any{"Authorization": "Bearer config-secret"}}}
	if explicit != nil {
		backend["subscriptions"] = explicit
	}
	parsed := ahp.ParseRegistration(sdkJSON(map[string]any{"protocolVersion": "draft", "hooks": []any{backend}}))
	if !parsed.OK {
		t.Fatal(parsed.Diagnostics)
	}
	return parsed.Value
}
func discoveryOptions() Options {
	return Options{Content: ContentOptions{ProjectOpaque: func(_ context.Context, _ ContentAuthorization, _ string, v any) (any, error) { return v, nil }}, Source: "urn:test:configuration", Harness: ahp.Harness{Name: "test", Version: "1"}, Events: capability.Host{ToolBefore: capability.ToolBefore{Deny: true, Observe: true}, ToolAfter: capability.ToolAfter{Observe: true}}}
}
func discoveredSubscriptions(events ...string) []any {
	return []any{map[string]any{"events": events, "mode": "intercept", "timeoutMs": 750, "failurePolicy": "fail-open", "content": map[string]any{"default": "metadata"}}}
}

func TestConfigurationDiscoveryHTTP(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer config-secret" {
			t.Error("configured authorization missing")
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		if req["method"] != "hooks/configuration" {
			t.Errorf("unexpected method: %v", req["method"])
		}
		params := sdkObj(req["params"])
		if len(params) != 1 || params["protocolVersion"] != "draft" {
			t.Error("discovery included event or session data")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"protocolVersion": "draft", "configuration": map[string]any{"subscriptions": discoveredSubscriptions("tool.*", "session.start")}}})
	}))
	defer s.Close()
	h, err := New(discoveryRegistration(t, s.URL, nil), discoveryOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if calls.Load() != 1 || !h.Subscribes(event.ToolBefore) || h.Subscribes(event.ToolAfter) || len(h.backends) != 1 {
		t.Fatalf("unexpected routes: %+v", h.backends)
	}
	sub := h.backends[0].subscriptions[0]
	if len(sdkArray(sub["events"])) != 1 || sub["failurePolicy"] != "fail-open" || sdkObj(sub["content"])["default"] != "metadata" {
		t.Fatalf("settings changed: %+v", sub)
	}
}

func TestExplicitConfigurationBypassesDiscovery(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("explicit config contacted discovery")
		w.WriteHeader(500)
	}))
	defer s.Close()
	h, err := New(discoveryRegistration(t, s.URL, discoveredSubscriptions("tool.before")), discoveryOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if !h.Subscribes(event.ToolBefore) {
		t.Fatal("explicit route missing")
	}
}

func TestConfigurationDiscoveryFailuresSkip(t *testing.T) {
	for _, kind := range []string{"unavailable", "malformed", "empty", "unmatched", "correlation", "version", "invalid-setting", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "timeout" {
					select {
					case <-r.Context().Done():
					case <-time.After(100 * time.Millisecond):
					}
					return
				}
				if kind == "unavailable" {
					w.WriteHeader(500)
					return
				}
				if kind == "malformed" {
					_, _ = w.Write([]byte(`{"bad":true}`))
					return
				}
				var req map[string]any
				_ = json.NewDecoder(r.Body).Decode(&req)
				subs := discoveredSubscriptions("tool.before")
				id, version := req["id"], "draft"
				switch kind {
				case "empty":
					subs = []any{}
				case "unmatched":
					subs = discoveredSubscriptions("session.start")
				case "correlation":
					id = "wrong"
				case "version":
					version = "old"
				case "invalid-setting":
					sdkObj(subs[0])["timeoutMs"] = -1
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"protocolVersion": version, "configuration": map[string]any{"subscriptions": subs}}})
			}))
			defer s.Close()
			opts := discoveryOptions()
			opts.ConfigurationTimeout = 25 * time.Millisecond
			var diagnosed bool
			opts.TransportDiagnostic = func(id string, err error) { diagnosed = errors.Is(err, ErrConfigurationSkipped) }
			h, err := New(discoveryRegistration(t, s.URL, nil), opts)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			if len(h.backends) != 0 || !diagnosed {
				t.Fatal("backend not skipped with diagnostic")
			}
		})
	}
}

func TestConfigurationDiscoveryCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts := discoveryOptions()
	opts.InitializationContext = ctx
	h, err := New(discoveryRegistration(t, "http://127.0.0.1:1/hooks", nil), opts)
	if h != nil {
		h.Close()
		t.Fatal("cancelled initialization returned client")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation swallowed: %v", err)
	}
}

func TestConfigurationStdioHelper(t *testing.T) {
	if os.Getenv("AHP_CONFIGURATION_HELPER") != "1" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req map[string]any
		if json.Unmarshal(scanner.Bytes(), &req) != nil {
			os.Exit(2)
		}
		if req["method"] == "hooks/intercept" {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"protocolVersion": "draft", "effects": []any{}}})
			continue
		}
		if req["method"] != "hooks/configuration" {
			os.Exit(3)
		}
		subs := discoveredSubscriptions("tool.before")
		sdkObj(subs[0])["timeoutMs"] = 5000
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"protocolVersion": "draft", "configuration": map[string]any{"subscriptions": subs}}})
	}
	os.Exit(0)
}

func TestConfigurationDiscoveryStdio(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, lifecycle := range []string{"persistent", "per_event"} {
		t.Run(lifecycle, func(t *testing.T) {
			parsed := ahp.ParseRegistration(sdkJSON(map[string]any{"protocolVersion": "draft", "hooks": []any{map[string]any{"id": "com.example.stdio", "transport": map[string]any{"type": "stdio", "command": exe, "args": []string{"-test.run=^TestConfigurationStdioHelper$"}, "lifecycle": lifecycle, "env": map[string]string{"AHP_CONFIGURATION_HELPER": "1"}}}}}))
			if !parsed.OK {
				t.Fatal(parsed.Diagnostics)
			}
			h, err := New(parsed.Value, discoveryOptions())
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			if len(h.backends) != 1 || !h.Subscribes(event.ToolBefore) {
				t.Fatal("stdio discovery did not register backend")
			}
			result, err := h.intercept(context.Background(), "tool.before", testInput())
			if err != nil || len(result.AcceptedResponses) != 1 {
				t.Fatalf("stdio post-discovery delivery failed: %v %v", err, result.Diagnostics)
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConfigurationHTTPServerAndClient(t *testing.T) {
	var configuration ahp.Configuration
	if err := json.Unmarshal(sdkJSON(map[string]any{"subscriptions": discoveredSubscriptions("tool.before")}), &configuration); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	handler, err := server.NewHandler(server.Handlers{Configuration: &configuration, Intercept: server.InterceptHandlers{ToolBefore: func(context.Context, server.InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities]) (server.ToolBeforeReply, error) {
		calls.Add(1)
		return server.ToolBeforeReply{}, nil
	}}}, server.Options{})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(handler)
	defer endpoint.Close()
	h, err := New(discoveryRegistration(t, endpoint.URL, nil), discoveryOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	result, err := h.intercept(context.Background(), "tool.before", testInput())
	if err != nil || calls.Load() != 1 || len(result.AcceptedResponses) != 1 {
		t.Fatalf("post-discovery HTTP delivery: %v %v", err, result.Diagnostics)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.intercept(context.Background(), "tool.before", testInput()); err == nil {
		t.Fatal("closed client admitted event")
	}
}

func discoveredUploadSubscription(endpoint string, binding map[string]any) map[string]any {
	upload := map[string]any{"endpoint": endpoint, "timeoutMs": 1000, "maxBytes": 1024}
	if binding != nil {
		upload["auth"] = binding
	}
	return map[string]any{"events": []any{"model.request.before"}, "mode": "intercept", "timeoutMs": 1000, "failurePolicy": "fail-closed", "content": map[string]any{"default": "body"}, "upload": upload}
}
func discoveredUploadOptions() Options {
	opts := discoveryOptions()
	opts.Events = capability.Host{ModelRequestBefore: capability.ModelRequestBefore{ModifyRequest: capability.ReplaceAndMerge(), Message: true, Deny: true, Observe: true}}
	opts.Metadata = testManifestMetadata()
	opts.Content.AuthorizeContent = contentTestAllow
	opts.Content.AllowLoopbackHTTP = true
	return opts
}
func dispatchDiscoveredUpload(t *testing.T, h *Hooks) {
	t.Helper()
	result, err := h.Dispatch(context.Background(), event.ModelRequestBefore, uploadPlanInput(t), WithContentSource(uploadPlanPath, content.NewAttachment([]byte("body"))))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if len(result.Diagnostics) != 0 {
		t.Fatalf("delivery diagnostics: %v", result.Diagnostics)
	}
}

// discoveryUploadEndpoint confirms uploads after checking the Authorization header.
func discoveryUploadEndpoint(t *testing.T, authorization string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("Authorization"); got != authorization {
			t.Errorf("upload Authorization = %q, want %q", got, authorization)
		}
		raw, _ := io.ReadAll(r.Body)
		contentTestConfirm(w, "upload-receipt", raw)
	}))
	t.Cleanup(s.Close)
	return s, &calls
}

// discoveryBackend advertises subs and counts event deliveries, which must carry
// the confirmed upload receipt.
func discoveryBackend(t *testing.T, subs []any) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var deliveries atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(raw, &req)
		result := map[string]any{"protocolVersion": "draft", "configuration": map[string]any{"subscriptions": subs}}
		if req["method"] != "hooks/configuration" {
			deliveries.Add(1)
			if !bytes.Contains(raw, []byte("upload-receipt")) {
				t.Error("delivery missing upload receipt")
			}
			result = map[string]any{"protocolVersion": "draft", "effects": []any{}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": result})
	}))
	t.Cleanup(s.Close)
	return s, &deliveries
}

type discoverySecretProvider struct{ calls atomic.Int32 }

func (p *discoverySecretProvider) Credential(context.Context, auth.Request) (auth.Credential, error) {
	p.calls.Add(1)
	return auth.Credential{}, errors.New("secret resolved")
}
func (p *discoverySecretProvider) Challenge(context.Context, auth.Request, auth.Challenge) (*auth.Credential, error) {
	p.calls.Add(1)
	return nil, errors.New("secret resolved")
}

func TestDiscoveredUploadAdmittedWithConfiguredHeader(t *testing.T) {
	uploads, received := discoveryUploadEndpoint(t, "Bearer config-secret")
	backend, deliveries := discoveryBackend(t, []any{discoveredUploadSubscription(uploads.URL+"/advertised", nil)})
	h, err := New(discoveryRegistration(t, backend.URL, nil), discoveredUploadOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	dispatchDiscoveredUpload(t, h)
	if received.Load() != 1 || deliveries.Load() != 1 {
		t.Fatalf("uploads=%d deliveries=%d", received.Load(), deliveries.Load())
	}
}

func TestDiscoveredUploadOAuthWithoutClientSecretAdmitted(t *testing.T) {
	binding := map[string]any{"type": "oauth", "resource": "https://uploads.example.test", "issuer": "https://issuer.example.test", "clientId": "client", "flow": "client_credentials"}
	backend, _ := discoveryBackend(t, []any{discoveredUploadSubscription("https://uploads.example.test/body", binding)})
	provider := &discoverySecretProvider{}
	opts := discoveredUploadOptions()
	opts.AuthProvider = provider
	h, err := New(discoveryRegistration(t, backend.URL, nil), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if !h.Subscribes(event.ModelRequestBefore) || provider.calls.Load() != 0 {
		t.Fatalf("subscribed=%v credential calls=%d", h.Subscribes(event.ModelRequestBefore), provider.calls.Load())
	}
}

func TestDiscoveredUploadLocalSecretReferenceSkipsBackend(t *testing.T) {
	for name, binding := range map[string]map[string]any{
		"tokenEnv":        {"type": "bearer", "tokenEnv": "AHP_DISCOVERED_UPLOAD_SECRET"},
		"tokenRef":        {"type": "bearer", "tokenRef": "AHP_DISCOVERED_UPLOAD_SECRET"},
		"clientSecretRef": {"type": "oauth", "resource": "https://uploads.example.test", "issuer": "https://issuer.example.test", "clientId": "client", "flow": "client_credentials", "clientSecretRef": "AHP_DISCOVERED_UPLOAD_SECRET"},
	} {
		for _, placement := range []string{"only-subscription", "unmatched-subscription"} {
			t.Run(name+"/"+placement, func(t *testing.T) {
				t.Setenv("AHP_DISCOVERED_UPLOAD_SECRET", "local-secret")
				uploads, received := discoveryUploadEndpoint(t, "")
				sub := discoveredUploadSubscription(uploads.URL, binding)
				subs := []any{sub}
				if placement == "unmatched-subscription" {
					sub["events"] = []any{"session.start"}
					subs = []any{discoveredUploadSubscription(uploads.URL, nil), sub}
				}
				backend, deliveries := discoveryBackend(t, subs)
				provider := &discoverySecretProvider{}
				opts := discoveredUploadOptions()
				opts.AuthProvider = provider
				var reason error
				opts.TransportDiagnostic = func(_ string, err error) { reason = err }
				h, err := New(discoveryRegistration(t, backend.URL, nil), opts)
				if err != nil {
					t.Fatal(err)
				}
				defer h.Close()
				if !errors.Is(reason, ErrConfigurationLocalSecretReference) || !errors.Is(reason, ErrConfigurationSkipped) {
					t.Fatalf("skip reason: %v", reason)
				}
				if strings.Contains(reason.Error(), "AHP_DISCOVERED_UPLOAD_SECRET") {
					t.Fatal("diagnostic exposes reference name")
				}
				if len(h.backends) != 0 || h.Subscribes(event.ModelRequestBefore) {
					t.Fatal("backend admitted")
				}
				dispatchDiscoveredUpload(t, h)
				if provider.calls.Load() != 0 || received.Load() != 0 || deliveries.Load() != 0 {
					t.Fatalf("credential calls=%d uploads=%d deliveries=%d", provider.calls.Load(), received.Load(), deliveries.Load())
				}
			})
		}
	}
}

func TestExplicitUploadLocalSecretReferenceRetained(t *testing.T) {
	t.Setenv("AHP_EXPLICIT_UPLOAD_SECRET", "local-secret")
	uploads, received := discoveryUploadEndpoint(t, "Bearer local-secret")
	backend, deliveries := discoveryBackend(t, nil)
	sub := discoveredUploadSubscription(uploads.URL, map[string]any{"type": "bearer", "tokenEnv": "AHP_EXPLICIT_UPLOAD_SECRET"})
	parsed := ahp.ParseRegistration(sdkJSON(map[string]any{"protocolVersion": "draft", "hooks": []any{map[string]any{"id": "com.example.explicit", "transport": map[string]any{"type": "http", "url": backend.URL}, "subscriptions": []any{sub}}}}))
	if !parsed.OK {
		t.Fatal(parsed.Diagnostics)
	}
	h, err := New(parsed.Value, discoveredUploadOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	dispatchDiscoveredUpload(t, h)
	if received.Load() != 1 || deliveries.Load() != 1 {
		t.Fatalf("uploads=%d deliveries=%d", received.Load(), deliveries.Load())
	}
}
