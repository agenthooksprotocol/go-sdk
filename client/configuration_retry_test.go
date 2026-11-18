package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
	"github.com/agenthooksprotocol/go-sdk/event"
)

const retryBackendID = "com.example.retry"

// retryProvider is a host provider with an explicit prepare: until prepared,
// a challenge fails with code; afterwards it supplies a credential.
type retryProvider struct {
	mu       sync.Mutex
	code     auth.Code
	prepares atomic.Uint64
}

func (p *retryProvider) Credential(context.Context, auth.Request) (auth.Credential, error) {
	return auth.Credential{}, &auth.Error{Code: auth.CodeInvalidConfiguration}
}
func (p *retryProvider) Challenge(context.Context, auth.Request, auth.Challenge) (*auth.Credential, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.code != "" {
		return nil, &auth.Error{Code: p.code}
	}
	return &auth.Credential{Type: "bearer", Token: "granted-token"}, nil
}
func (p *retryProvider) Preparations(r auth.Request) uint64 {
	if r.BackendID != retryBackendID || r.Purpose != auth.Event {
		return 0
	}
	return p.prepares.Load()
}
func (p *retryProvider) prepare() {
	p.mu.Lock()
	p.code = ""
	p.mu.Unlock()
	p.prepares.Add(1)
}

// retryServer answers discovery according to mode and counts deliveries.
type retryServer struct {
	*httptest.Server
	mode        atomic.Value
	discoveries atomic.Int32
	deliveries  atomic.Int32
	gate        atomic.Pointer[retryGate]
}

// retryGate holds discovery requests until release is closed.
type retryGate struct{ entered, release chan struct{} }

func (s *retryServer) holdDiscovery() *retryGate {
	g := &retryGate{make(chan struct{}, 16), make(chan struct{})}
	s.gate.Store(g)
	return g
}

func newRetryServer(t *testing.T, mode string) *retryServer {
	t.Helper()
	s := &retryServer{}
	s.mode.Store(mode)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if req["method"] != "hooks/configuration" {
			s.deliveries.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"protocolVersion": "draft", "effects": []any{}}})
			return
		}
		if r.Header.Get("Authorization") == "" {
			// A challenged replay is part of the same attempt.
			s.discoveries.Add(1)
		}
		if g := s.gate.Load(); g != nil {
			g.entered <- struct{}{}
			<-g.release
		}
		subs := []any{map[string]any{"events": []any{"tool.before"}, "mode": "intercept", "timeoutMs": 5000, "failurePolicy": "fail-open", "content": map[string]any{"default": "metadata"}}, map[string]any{"events": []any{"tool.after"}, "mode": "observe", "content": map[string]any{"default": "metadata"}}}
		result := map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"protocolVersion": "draft", "configuration": map[string]any{"subscriptions": subs}}}
		switch s.mode.Load().(string) {
		case "401":
			if r.Header.Get("Authorization") != "Bearer granted-token" {
				w.Header().Set("WWW-Authenticate", "Bearer")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"secret":"response-body-secret"}`))
				return
			}
		case "500":
			w.WriteHeader(http.StatusInternalServerError)
			return
		case "slow":
			time.Sleep(300 * time.Millisecond)
		case "rpc-error":
			result = map[string]any{"jsonrpc": "2.0", "id": req["id"], "error": map[string]any{"code": -32000, "message": "busy"}}
		case "method-not-found":
			result = map[string]any{"jsonrpc": "2.0", "id": req["id"], "error": map[string]any{"code": -32601, "message": "no such method"}}
		case "unmatched":
			subs[0] = map[string]any{"events": []any{"session.start"}, "mode": "intercept", "timeoutMs": 750, "failurePolicy": "fail-open", "content": map[string]any{"default": "metadata"}}
			subs = subs[:1]
			result["result"].(map[string]any)["configuration"] = map[string]any{"subscriptions": subs}
		case "local-secret":
			sdkObj(subs[0])["upload"] = map[string]any{"endpoint": "https://uploads.example.test", "timeoutMs": 1000, "maxBytes": 1024, "auth": map[string]any{"type": "bearer", "tokenEnv": "AHP_RETRY_SECRET"}}
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	t.Cleanup(s.Close)
	return s
}

func retryRegistration(t *testing.T, backends ...map[string]any) ahp.Registration {
	t.Helper()
	hooks := make([]any, len(backends))
	for i, backend := range backends {
		hooks[i] = backend
	}
	parsed := ahp.ParseRegistration(sdkJSON(map[string]any{"protocolVersion": "draft", "hooks": hooks}))
	if !parsed.OK {
		t.Fatal(parsed.Diagnostics)
	}
	return parsed.Value
}
func retryBackend(url string) map[string]any {
	return map[string]any{"id": retryBackendID, "transport": map[string]any{"type": "http", "url": url}}
}

// retryHarness records diagnostics and controls the client's clock.
type retryHarness struct {
	mu          sync.Mutex
	diagnostics []*ConfigurationSkipError
	offset      atomic.Int64
}

func (r *retryHarness) options(provider auth.Provider) Options {
	opts := discoveryOptions()
	opts.AuthProvider = provider
	opts.TransportDiagnostic = func(id string, err error) {
		var skip *ConfigurationSkipError
		if !errors.As(err, &skip) || skip.BackendID != id {
			return
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		copied := *skip
		r.diagnostics = append(r.diagnostics, &copied)
	}
	return opts
}
func (r *retryHarness) install(h *Hooks) {
	h.now = func() time.Time { return time.Now().Add(time.Duration(r.offset.Load())) }
}
func (r *retryHarness) advance(d time.Duration) { r.offset.Add(int64(d)) }
func (r *retryHarness) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.diagnostics)
}
func (r *retryHarness) last(t *testing.T) ConfigurationSkipError {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.diagnostics) == 0 {
		t.Fatal("no skip diagnostic")
	}
	return *r.diagnostics[len(r.diagnostics)-1]
}

// dispatchTool delivers one event, then waits for any re-attempt it started.
func dispatchTool(t *testing.T, h *Hooks) *Result {
	t.Helper()
	result, err := h.intercept(context.Background(), "tool.before", testInput())
	if err != nil {
		t.Fatal(err)
	}
	waitRetry(h)
	return result
}

// waitRetry waits for a background re-attempt, which holds the retry lock.
func waitRetry(h *Hooks) {
	h.retry.Lock()
	h.retry.Unlock()
}

func newRetryHooks(t *testing.T, r *retryHarness, reg ahp.Registration, opts Options) *Hooks {
	t.Helper()
	h, err := New(reg, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	r.install(h)
	return h
}

// Every skip cause maps to exactly one diagnostic code.
func TestConfigurationSkipDiagnosticCodes(t *testing.T) {
	for mode, want := range map[string]ConfigurationSkipCode{
		"500":              ConfigurationUnavailable,
		"rpc-error":        ConfigurationUnavailable,
		"method-not-found": ConfigurationInvalid,
		"unmatched":        ConfigurationNoApplicableSubscriptions,
		"local-secret":     ConfigurationLocalSecret,
	} {
		t.Run(mode, func(t *testing.T) {
			s := newRetryServer(t, mode)
			r := &retryHarness{}
			newRetryHooks(t, r, retryRegistration(t, retryBackend(s.URL)), r.options(nil))
			got := r.last(t)
			if got != (ConfigurationSkipError{BackendID: retryBackendID, Code: want}) {
				t.Fatalf("diagnostic = %+v; want code %s", got, want)
			}
		})
	}
}

func TestConfigurationUnauthorizedDiagnosticCarriesAuthCode(t *testing.T) {
	s := newRetryServer(t, "401")
	r := &retryHarness{}
	provider := &retryProvider{code: auth.CodeInteractionRequired}
	h := newRetryHooks(t, r, retryRegistration(t, retryBackend(s.URL)), r.options(provider))
	if len(h.routes()) != 0 || r.count() != 1 {
		t.Fatal("unauthorized backend not skipped exactly once")
	}
	diagnostic := r.last(t)
	encoded, _ := json.Marshal(diagnostic)
	if string(encoded) != `{"backendId":"com.example.retry","code":"configuration_unavailable","authError":"interaction_required","recovery":"login"}` {
		t.Fatalf("diagnostic = %s", encoded)
	}
	var classified *auth.Error
	if !errors.Is(&diagnostic, ErrConfigurationSkipped) || !errors.As(&diagnostic, &classified) || classified.Code != auth.CodeInteractionRequired {
		t.Fatal("diagnostic is not a typed configuration skip with its auth error")
	}
	if text := diagnostic.Error() + string(encoded); strings.Contains(text, "secret") || strings.Contains(text, "granted-token") || strings.Contains(text, s.URL) {
		t.Fatalf("diagnostic leaks credentials or content: %s", text)
	}

	t.Run("initialization cancellation propagates without diagnostic", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := &retryHarness{}
		opts := r.options(provider)
		opts.InitializationContext = ctx
		if h, err := New(retryRegistration(t, retryBackend(s.URL)), opts); h != nil || !errors.Is(err, context.Canceled) || r.count() != 0 {
			t.Fatalf("cancelled initialization: err=%v diagnostics=%d", err, r.count())
		}
	})
	t.Run("close during re-attempt emits no diagnostic", func(t *testing.T) {
		s := newRetryServer(t, "500")
		r := &retryHarness{}
		h := newRetryHooks(t, r, retryRegistration(t, retryBackend(s.URL)), r.options(nil))
		r.advance(time.Minute)
		g := s.holdDiscovery()
		t.Cleanup(func() { close(g.release) })
		if _, err := h.intercept(context.Background(), "tool.before", testInput()); err != nil {
			t.Fatal(err)
		}
		<-g.entered
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		if r.count() != 1 || len(h.routes()) != 0 {
			t.Fatalf("close diagnosed or installed: diagnostics=%d", r.count())
		}
	})
}

func TestConfigurationUnavailableRetriedAfterPrepare(t *testing.T) {
	for _, routed := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "auth.Route"}[routed], func(t *testing.T) {
			s := newRetryServer(t, "401")
			r := &retryHarness{}
			provider := &retryProvider{code: auth.CodeInteractionRequired}
			var host auth.Provider = provider
			if routed {
				host = auth.Route(auth.Routes{OAuth: provider})
			}
			h := newRetryHooks(t, r, retryRegistration(t, retryBackend(s.URL)), r.options(host))
			dispatchTool(t, h)
			if s.discoveries.Load() != 1 || s.deliveries.Load() != 0 || h.Subscribes(event.ToolBefore) {
				t.Fatal("skipped backend contacted before prepare")
			}
			provider.prepare()
			// The triggering event uses the previous routes; the re-attempt runs
			// beside it and installs the backend for the next event.
			if result := dispatchTool(t, h); len(result.AcceptedResponses) != 0 || s.discoveries.Load() != 2 || !h.Subscribes(event.ToolBefore) {
				t.Fatalf("prepare did not re-attempt at the next admission: discoveries=%d", s.discoveries.Load())
			}
			if result := dispatchTool(t, h); len(result.AcceptedResponses) != 1 || s.deliveries.Load() != 1 || s.discoveries.Load() != 2 {
				t.Fatalf("installed backend: deliveries=%d discoveries=%d", s.deliveries.Load(), s.discoveries.Load())
			}
		})
	}
}

func TestConfigurationUnavailableBackoff(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     string
		provider *retryProvider
		delay    time.Duration
		max      time.Duration
		steps    []time.Duration // backoff before each re-attempt
	}{
		{name: "no auth error", mode: "500", steps: []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute}},
		{name: "recovery retry", mode: "401", provider: &retryProvider{code: auth.CodeProviderFailed}, steps: []time.Duration{30 * time.Second, time.Minute}},
		{name: "host configured", mode: "500", delay: 10 * time.Second, max: 25 * time.Second, steps: []time.Duration{10 * time.Second, 20 * time.Second, 25 * time.Second, 25 * time.Second}},
		{name: "capped at one hour", mode: "500", delay: 40 * time.Minute, steps: []time.Duration{40 * time.Minute, time.Hour, time.Hour}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newRetryServer(t, tc.mode)
			r := &retryHarness{}
			var provider auth.Provider
			if tc.provider != nil {
				provider = tc.provider
			}
			opts := r.options(provider)
			opts.ConfigurationRetryDelay, opts.ConfigurationRetryMaxDelay = tc.delay, tc.max
			h := newRetryHooks(t, r, retryRegistration(t, retryBackend(s.URL)), opts)
			for i, step := range tc.steps {
				r.advance(step - time.Second)
				dispatchTool(t, h)
				if got := s.discoveries.Load(); got != int32(i+1) {
					t.Fatalf("step %d: admission before backoff contacted the backend (%d discoveries)", i, got)
				}
				if i == len(tc.steps)-1 {
					s.mode.Store("ok")
				}
				r.advance(time.Second)
				dispatchTool(t, h)
				if got := s.discoveries.Load(); got != int32(i+2) {
					t.Fatalf("step %d: backoff elapsed without re-attempt (%d discoveries)", i, got)
				}
				if i < len(tc.steps)-1 && (r.count() != i+2 || r.last(t).Code != ConfigurationUnavailable) {
					t.Fatalf("step %d: failed re-attempt not diagnosed", i)
				}
			}
			dispatchTool(t, h)
			if s.deliveries.Load() != 1 || !h.Subscribes(event.ToolBefore) {
				t.Fatal("successful re-attempt did not admit routes")
			}
		})
	}
	t.Run("prepare resets backoff", func(t *testing.T) {
		s := newRetryServer(t, "500")
		r := &retryHarness{}
		provider := &retryProvider{}
		h := newRetryHooks(t, r, retryRegistration(t, retryBackend(s.URL)), r.options(provider))
		for _, step := range []time.Duration{30 * time.Second, time.Minute} {
			r.advance(step)
			dispatchTool(t, h)
		}
		provider.prepare()
		dispatchTool(t, h)
		r.advance(30 * time.Second)
		dispatchTool(t, h)
		if s.discoveries.Load() != 5 {
			t.Fatalf("discoveries=%d; prepare did not reset backoff to its initial delay", s.discoveries.Load())
		}
	})
}

func TestConfigurationAuthFailureNotRetriedOnBackoff(t *testing.T) {
	for _, code := range []auth.Code{auth.CodeInteractionRequired, auth.CodeRefreshRejected, auth.CodeCredentialUnavailable, auth.CodeInvalidConfiguration, auth.CodeAccessDenied} {
		t.Run(string(code), func(t *testing.T) {
			s := newRetryServer(t, "401")
			r := &retryHarness{}
			provider := &retryProvider{code: code}
			h := newRetryHooks(t, r, retryRegistration(t, retryBackend(s.URL)), r.options(provider))
			if got := r.last(t); got.AuthError != code || got.Recovery == auth.RecoveryRetry {
				t.Fatalf("diagnostic = %+v", got)
			}
			for range 3 {
				r.advance(2 * time.Hour)
				dispatchTool(t, h)
			}
			if s.discoveries.Load() != 1 {
				t.Fatalf("recovery %s re-attempted on backoff", r.last(t).Recovery)
			}
			provider.prepare()
			dispatchTool(t, h)
			dispatchTool(t, h)
			if s.discoveries.Load() != 2 || s.deliveries.Load() != 1 {
				t.Fatal("prepare did not make the backend eligible")
			}
		})
	}
	t.Run("reinitialization re-attempts", func(t *testing.T) {
		s := newRetryServer(t, "401")
		r := &retryHarness{}
		provider := &retryProvider{code: auth.CodeInteractionRequired}
		newRetryHooks(t, r, retryRegistration(t, retryBackend(s.URL)), r.options(provider))
		newRetryHooks(t, r, retryRegistration(t, retryBackend(s.URL)), r.options(provider))
		if s.discoveries.Load() != 2 {
			t.Fatal("reinitialization did not rediscover")
		}
	})
}

func TestConfigurationInvalidNotRetried(t *testing.T) {
	for _, mode := range []string{"method-not-found", "unmatched", "local-secret"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("AHP_RETRY_SECRET", "local-secret")
			s := newRetryServer(t, mode)
			r := &retryHarness{}
			provider := &retryProvider{}
			h := newRetryHooks(t, r, retryRegistration(t, retryBackend(s.URL)), r.options(provider))
			s.mode.Store("ok")
			for range 3 {
				provider.prepare()
				r.advance(2 * time.Hour)
				dispatchTool(t, h)
			}
			if s.discoveries.Load() != 1 || s.deliveries.Load() != 0 || r.count() != 1 {
				t.Fatalf("discoveries=%d deliveries=%d diagnostics=%d", s.discoveries.Load(), s.deliveries.Load(), r.count())
			}
		})
	}
}

func TestConfigurationRetryAtomicRoutes(t *testing.T) {
	// The explicit backend precedes the discovered one. The first event is held
	// in flight while projecting content for it, after its admission, while a
	// later admission installs the retried routes.
	release, holding := make(chan struct{}), make(chan struct{})
	var released sync.Once
	unhold := func() { released.Do(func() { close(release) }) }
	var held atomic.Bool
	explicit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"protocolVersion": "draft", "effects": []any{}}})
	}))
	t.Cleanup(explicit.Close)
	s := newRetryServer(t, "500")
	r := &retryHarness{}
	sub := map[string]any{"events": []any{"tool.before"}, "mode": "intercept", "timeoutMs": 5000, "failurePolicy": "fail-open", "content": map[string]any{"default": "metadata"}}
	reg := retryRegistration(t, map[string]any{"id": "com.example.explicit", "transport": map[string]any{"type": "http", "url": explicit.URL}, "subscriptions": []any{sub}}, retryBackend(s.URL))
	opts := r.options(nil)
	opts.Content.ProjectOpaque = func(_ context.Context, scope ContentAuthorization, _ string, v any) (any, error) {
		if scope.BackendID == "com.example.explicit" && held.CompareAndSwap(false, true) {
			close(holding)
			<-release
		}
		return v, nil
	}
	h := newRetryHooks(t, r, reg, opts)
	t.Cleanup(unhold) // runs before Close, which waits for the held event

	first := make(chan *Result, 1)
	go func() {
		result, _ := h.intercept(context.Background(), "tool.before", testInput())
		first <- result
	}()
	<-holding
	// Backoff elapses; the next admission starts a re-attempt whose discovery
	// is held. Neither it nor a concurrent caller waits or sees a partial set.
	r.advance(time.Minute)
	s.mode.Store("ok")
	g := s.holdDiscovery()
	t.Cleanup(func() { s.gate.Store(nil) })
	for i := range 2 {
		observed := make(chan *Result, 1)
		go func() {
			result, _ := h.intercept(context.Background(), "tool.before", testInput())
			observed <- result
		}()
		select {
		case result := <-observed:
			if result == nil || len(result.AcceptedResponses) != 1 || h.Subscribes(event.ToolAfter) || len(h.routes()) != 1 {
				t.Fatalf("caller %d observed a partial or new route set", i)
			}
		case <-time.After(3 * time.Second):
			close(g.release)
			t.Fatalf("caller %d waited for the re-attempt", i)
		}
		if i == 0 {
			<-g.entered
		}
	}
	close(g.release)
	waitRetry(h)
	routes := h.routes()
	if len(routes) != 2 || routes[0].id != "com.example.explicit" || routes[1].id != retryBackendID || len(routes[1].subscriptions) != 2 || !h.Subscribes(event.ToolAfter) {
		t.Fatalf("routes not installed whole in registration order: %+v", routes)
	}
	if result := dispatchTool(t, h); len(result.AcceptedResponses) != 2 {
		t.Fatal("next admission did not deliver to the installed backend")
	}
	unhold()
	if result := <-first; result == nil || len(result.AcceptedResponses) != 1 || s.deliveries.Load() != 1 {
		t.Fatalf("event admitted before the retry succeeded was replayed: %d deliveries", s.deliveries.Load())
	}
}

// A retried backend that precedes explicit ones is inserted at its
// registration position, not appended.
func TestConfigurationRetryKeepsRegistrationOrder(t *testing.T) {
	explicit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"protocolVersion": "draft", "effects": []any{}}})
	}))
	t.Cleanup(explicit.Close)
	s := newRetryServer(t, "500")
	r := &retryHarness{}
	sub := map[string]any{"events": []any{"tool.before"}, "mode": "intercept", "timeoutMs": 5000, "failurePolicy": "fail-open", "content": map[string]any{"default": "metadata"}}
	explicitBackend := func(id string) map[string]any {
		return map[string]any{"id": id, "transport": map[string]any{"type": "http", "url": explicit.URL}, "subscriptions": []any{sub}}
	}
	h := newRetryHooks(t, r, retryRegistration(t, explicitBackend("com.example.a"), retryBackend(s.URL), explicitBackend("com.example.z")), r.options(nil))
	r.advance(time.Minute)
	s.mode.Store("ok")
	dispatchTool(t, h)
	var ids []string
	for _, b := range h.routes() {
		ids = append(ids, b.id)
	}
	if strings.Join(ids, ",") != "com.example.a,"+retryBackendID+",com.example.z" {
		t.Fatalf("routes out of registration order: %v", ids)
	}
}

// A re-attempt never consumes an event's deadline: an event whose admission
// starts a hung discovery still reaches a fail-closed backend in time.
func TestConfigurationRetryDoesNotConsumeEventDeadline(t *testing.T) {
	explicit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"protocolVersion": "draft", "effects": []any{}}})
	}))
	t.Cleanup(explicit.Close)
	s := newRetryServer(t, "500")
	r := &retryHarness{}
	sub := map[string]any{"events": []any{"tool.before"}, "mode": "intercept", "timeoutMs": 5000, "failurePolicy": "fail-closed", "content": map[string]any{"default": "metadata"}}
	h := newRetryHooks(t, r, retryRegistration(t, map[string]any{"id": "com.example.enforcer", "transport": map[string]any{"type": "http", "url": explicit.URL}, "subscriptions": []any{sub}}, retryBackend(s.URL)), r.options(nil))
	r.advance(time.Minute)
	g := s.holdDiscovery()
	t.Cleanup(func() { s.gate.Store(nil); close(g.release) })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	result, err := h.intercept(ctx, "tool.before", testInput())
	if err != nil || result.Interrupted || len(result.AcceptedResponses) != 1 || len(result.Diagnostics) != 0 {
		t.Fatalf("fail-closed backend not reached within the event deadline: %v %+v", err, result)
	}
	<-g.entered
}

// Short event deadlines never starve a slow backend: its re-attempt runs on
// the client's own budget and is admitted although every event gives up early.
func TestConfigurationShortEventDeadlinesDoNotStarveRetry(t *testing.T) {
	s := newRetryServer(t, "500")
	r := &retryHarness{}
	h := newRetryHooks(t, r, retryRegistration(t, retryBackend(s.URL)), r.options(nil))
	r.advance(time.Minute)
	s.mode.Store("slow")
	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		_, _ = h.intercept(ctx, "tool.before", testInput())
		cancel()
	}
	waitRetry(h)
	if s.discoveries.Load() != 2 || r.count() != 1 || !h.Subscribes(event.ToolBefore) {
		t.Fatalf("slow backend starved: discoveries=%d diagnostics=%d", s.discoveries.Load(), r.count())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if result, err := h.intercept(ctx, "tool.before", testInput()); err != nil || len(result.AcceptedResponses) != 1 {
		t.Fatalf("slow backend not delivered: %v", err)
	}
}

// A host prepare that arrives while discovery is in flight is not lost: the
// prepare count is read before each attempt and compared after it fails.
func TestConfigurationPrepareDuringAttemptNotLost(t *testing.T) {
	for _, phase := range []string{"initial", "re-attempt"} {
		t.Run(phase, func(t *testing.T) {
			s := newRetryServer(t, "401")
			r := &retryHarness{}
			provider := &retryProvider{code: auth.CodeInteractionRequired}
			reg := retryRegistration(t, retryBackend(s.URL))
			var h *Hooks
			hold := func(attempt func()) {
				g := s.holdDiscovery()
				done := make(chan struct{})
				go func() { attempt(); close(done) }()
				<-g.entered
				provider.prepares.Add(1) // prepare completes; the in-flight attempt still fails
				s.gate.Store(nil)
				close(g.release)
				<-done
			}
			if phase == "initial" {
				hold(func() { h = newRetryHooks(t, r, reg, r.options(provider)) })
			} else {
				h = newRetryHooks(t, r, reg, r.options(provider))
				provider.prepares.Add(1)
				hold(func() { dispatchTool(t, h) })
			}
			before := s.discoveries.Load()
			provider.prepare()
			provider.prepares.Add(^uint64(0)) // authorize without a further prepare signal
			dispatchTool(t, h)
			dispatchTool(t, h)
			if s.discoveries.Load() != before+1 || s.deliveries.Load() != 1 {
				t.Fatalf("prepare during the attempt was lost: discoveries %d->%d deliveries=%d", before, s.discoveries.Load(), s.deliveries.Load())
			}
		})
	}
}

// Concurrent admissions share one re-attempt: exactly one discovery runs.
func TestConfigurationConcurrentAdmissionsDiscoverOnce(t *testing.T) {
	s := newRetryServer(t, "500")
	r := &retryHarness{}
	h := newRetryHooks(t, r, retryRegistration(t, retryBackend(s.URL)), r.options(nil))
	r.advance(time.Minute)
	s.mode.Store("ok")
	g := s.holdDiscovery()
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.intercept(context.Background(), "tool.before", testInput())
		}()
	}
	<-g.entered
	s.gate.Store(nil)
	close(g.release)
	wg.Wait()
	dispatchTool(t, h)
	if s.discoveries.Load() != 2 {
		t.Fatalf("concurrent admissions ran %d discoveries; want 1 re-attempt", s.discoveries.Load()-1)
	}
}
