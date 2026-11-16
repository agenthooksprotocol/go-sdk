package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

func TestLifecycleDispatchDoesNotOwnConsent(t *testing.T) {
	_, p, r := setup(t, "authorization_code_pkce")
	_, err := p.Credential(budget(t), r)
	assertCode(t, err, auth.CodeInteractionRequired)
	p.mu.Lock()
	count := len(p.pending)
	p.mu.Unlock()
	if count != 0 {
		t.Fatal("credential dispatch allocated login state")
	}
	host := budget(t)
	prepared, err := p.Prepare(host, r)
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = p.Credential(short, r)
	assertCode(t, err, auth.CodeInteractionRequired)
	again, err := p.Prepare(host, r)
	if err != nil || again.Login != prepared.Login {
		t.Fatal("delivery replaced host-owned consent")
	}
	p.Cancel(prepared.Login)
	p.mu.Lock()
	count = len(p.pending)
	p.mu.Unlock()
	if count != 0 {
		t.Fatal("cancel retained pending state")
	}
}

func TestLifecycleAllowedStepUp(t *testing.T) {
	for _, flow := range []string{"authorization_code_pkce", "client_credentials"} {
		t.Run(flow, func(t *testing.T) {
			f, p, r := setup(t, flow)
			selectClient := p.options.SelectClient
			p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
				c, err := selectClient(ctx, r, issuers, resource)
				c.AllowedScopes = []string{"events", "admin"}
				return c, err
			}
			var credential auth.Credential
			if flow == "authorization_code_pkce" {
				credential = finishLogin(t, p, r)
			} else {
				var err error
				credential, err = p.Credential(budget(t), r)
				if err != nil {
					t.Fatal(err)
				}
			}
			challenge := auth.Challenge{StatusCode: 403, Header: http.Header{"Www-Authenticate": {`Bearer error="insufficient_scope", scope="admin"`}}, Attempt: credential.Attempt}
			_, err := p.Challenge(budget(t), r, challenge)
			if flow == "authorization_code_pkce" {
				assertCode(t, err, auth.CodeInteractionRequired)
				p.mu.Lock()
				count := len(p.pending)
				p.mu.Unlock()
				if count != 0 {
					t.Fatal("step-up dispatch allocated login state")
				}
				prepared, err := p.Prepare(budget(t), r)
				if err != nil || prepared.Login == nil {
					t.Fatalf("host step-up: %v", err)
				}
				u, _ := url.Parse(prepared.Login.AuthorizationURL())
				if !slices.Contains(strings.Fields(u.Query().Get("scope")), "admin") {
					t.Fatal("host consent omitted step-up requirement")
				}
			} else {
				// The real token server deliberately returns its old narrowed scope. The
				// rotation is persisted, but no insufficient credential is dispatched.
				assertCode(t, err, auth.CodeAccessDenied)
				if f.tokenCalls.Load() != 2 {
					t.Fatal("machine grant did not reissue without login")
				}
				f.grantsMu.Lock()
				last := f.grants[len(f.grants)-1]
				f.grantsMu.Unlock()
				if !slices.Contains(strings.Fields(last.Get("scope")), "admin") {
					t.Fatal("machine grant omitted approved scope")
				}
				saved, _ := f.store.Load(budget(t), credential.Attempt.(attempted).key)
				if saved == nil || saved.RefreshToken == "" {
					t.Fatal("step-up lost rotated refresh")
				}
			}
			challenge.Header.Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="forbidden"`)
			_, err = p.Challenge(budget(t), r, challenge)
			assertCode(t, err, auth.CodeAccessDenied)
		})
	}
}

func TestLifecycleBindingRequirementsMergeStaleWriters(t *testing.T) {
	_, p, r := setup(t, "client_credentials")
	c, m, err := p.resolve(budget(t), r, "")
	if err != nil {
		t.Fatal(err)
	}
	c.AllowedScopes = []string{"events", "admin", "write"}
	start := make(chan struct{})
	errs := make(chan error, 3)
	var wg sync.WaitGroup
	for _, requirement := range []string{"admin", "write", ""} {
		wg.Add(1)
		go func(required string) {
			defer wg.Done()
			<-start
			candidate := cloneConfig(c)
			if required != "" {
				candidate.RequiredScopes = []string{required}
			}
			_, err := p.persistBinding(budget(t), r, candidate, m)
			errs <- err
		}(requirement)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	stored, err := p.options.Store.Load(budget(t), p.bindingKey(r))
	if err != nil {
		t.Fatal(err)
	}
	if !sameScopes(stored.Binding.RequiredScopes, []string{"admin", "write"}) {
		t.Fatal("stale binding writer erased a requirement")
	}
	if stored.Binding.Config.ClientSecret != "" {
		t.Fatal("binding persisted runtime secret")
	}
	encoded, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	var restored Record
	if err = json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	restored.Binding.RequiredScopes[0] = "detached"
	again, _ := p.options.Store.Load(budget(t), p.bindingKey(r))
	if !sameScopes(again.Binding.RequiredScopes, []string{"admin", "write"}) {
		t.Fatal("binding snapshot aliased host store")
	}
}

func TestLifecycleExplicitExpiryAndUnknownRotation(t *testing.T) {
	_, p, _ := setup(t, "authorization_code_pkce")
	c := ClientConfig{Scopes: []string{"events"}, Resource: "unused"}
	p.options.ValidateToken = func(context.Context, ClientConfig, *oauth2.Token) error { return nil }
	for _, value := range []any{float64(0), int64(-1), "0", "-1"} {
		token := (&oauth2.Token{AccessToken: "access", RefreshToken: "rotated", TokenType: "Bearer"}).WithExtra(map[string]any{"expires_in": value})
		record, err := p.record(budget(t), c, token)
		if err == nil || record == nil || record.RefreshToken != "rotated" || !record.Rejected {
			t.Fatalf("explicit expired token: %v", err)
		}
	}
	record, err := p.record(budget(t), c, &oauth2.Token{AccessToken: "access", RefreshToken: "rotated", TokenType: "Bearer"})
	if err != nil || !usable(record) || record.RefreshToken != "rotated" {
		t.Fatalf("unknown expiry rotation lost: %v", err)
	}
}

// A panic in a real host callback must not strand pending-map ownership or the
// host grant coordinator. Production does not catch arbitrary host panics.
func TestLifecycleHostCallbackPanicReleasesCoordination(t *testing.T) {
	_, p, r := setup(t, "client_credentials")
	original := p.options.ValidateToken
	p.options.ValidateToken = func(context.Context, ClientConfig, *oauth2.Token) error { panic("host callback") }
	func() {
		defer func() {
			if recover() == nil {
				t.Error("host callback did not panic")
			}
		}()
		_, _ = p.Prepare(budget(t), r)
	}()
	p.options.ValidateToken = original
	next, err := p.Prepare(budget(t), r)
	if err != nil || next.Credential == nil {
		t.Fatalf("host panic stranded ownership: %v", err)
	}
}

func TestLifecycleRefreshUsesPreviousGrant(t *testing.T) {
	for _, mode := range []string{"refresh-omitted-scope", "refresh-broadened-scope"} {
		t.Run(mode, func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			selectClient := p.options.SelectClient
			p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
				c, err := selectClient(ctx, r, issuers, resource)
				c.Scopes = []string{"events", "admin"}
				return c, err
			}
			var binding map[string]any
			if err := json.Unmarshal(r.Binding, &binding); err != nil {
				t.Fatal(err)
			}
			binding["scopes"] = []string{"events", "admin"}
			r.Binding, _ = json.Marshal(binding)
			first := finishLogin(t, p, r)
			expire(t, f, first)
			f.mode.Store(mode)
			next, err := p.Prepare(budget(t), r)
			record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
			if record == nil || record.RefreshToken != "rotated-refresh" {
				t.Fatal("refresh response rotation not retained")
			}
			if mode == "refresh-omitted-scope" {
				if err != nil || next.Credential == nil || !sameScopes(record.Scopes, []string{"events"}) {
					t.Fatalf("refresh did not inherit prior narrowed grant: %v", err)
				}
			} else {
				assertCode(t, err, auth.CodeAccessDenied)
				if !record.Rejected || record.AccessToken != "" {
					t.Fatal("broadened refresh grant remained dispatchable")
				}
				recreated, err := New(p.options)
				if err != nil {
					t.Fatal(err)
				}
				request, err := http.NewRequestWithContext(budget(t), http.MethodPost, r.Destination, strings.NewReader(`{}`))
				if err != nil {
					t.Fatal(err)
				}
				response, err := auth.Do(f.server.Client(), request, r, auth.Route(auth.Routes{OAuth: recreated}), false)
				assertCode(t, err, auth.CodeAccessDenied)
				if response != nil {
					response.Body.Close()
					t.Fatal("quarantined grant produced a delivery response")
				}
				if f.eventCalls.Load() != 0 {
					t.Fatal("recreated provider dispatched unauthorized access")
				}
				retained, err := f.store.Load(budget(t), first.Attempt.(attempted).key)
				if err != nil || retained == nil || !retained.Rejected || retained.AccessToken != "" || retained.RefreshToken != "rotated-refresh" {
					t.Fatal("recreated provider lost refresh quarantine")
				}
				f.grantsMu.Lock()
				latest := f.grants[len(f.grants)-1]
				f.grantsMu.Unlock()
				if latest.Get("grant_type") != "refresh_token" || latest.Get("refresh_token") != "rotated-refresh" {
					t.Fatal("recreated provider did not retain rotated refresh for repair")
				}
			}
		})
	}
}

func TestLifecycleAcquisitionErrorsAreFlowSpecific(t *testing.T) {
	for _, mode := range []string{"reject", "invalid-client"} {
		t.Run("machine-"+mode, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			f.mode.Store(mode)
			_, err := p.Credential(budget(t), r)
			want := auth.CodeCredentialUnavailable
			if mode == "invalid-client" {
				want = auth.CodeInvalidConfiguration
			}
			assertCode(t, err, want)
			p.mu.Lock()
			count := len(p.pending)
			p.mu.Unlock()
			if count != 0 {
				t.Fatal("machine failure allocated interactive consent")
			}
		})
	}
	f, p, r := setup(t, "authorization_code_pkce")
	prepared, err := p.Prepare(budget(t), r)
	if err != nil {
		t.Fatal(err)
	}
	f.mode.Store("reject")
	u, _ := url.Parse(prepared.Login.AuthorizationURL())
	callback := "https://client.example/callback?" + url.Values{"state": {u.Query().Get("state")}, "code": {"used"}}.Encode()
	_, err = p.Complete(budget(t), prepared.Login, callback)
	assertCode(t, err, auth.CodeInteractionRequired)
}

func TestLifecyclePendingRequirementsAndLiteralLoopback(t *testing.T) {
	_, p, r := setup(t, "authorization_code_pkce")
	original := p.options.SelectClient
	required := false
	p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		c, err := original(ctx, r, issuers, resource)
		if required {
			c.RequiredScopes = []string{"events"}
		}
		return c, err
	}
	first, err := p.Prepare(budget(t), r)
	if err != nil {
		t.Fatal(err)
	}
	required = true
	second, err := p.Prepare(budget(t), r)
	if err != nil || first.Login == second.Login {
		t.Fatal("different operation requirements reused pending consent")
	}
	config := second.Login.config
	for _, redirect := range []string{"http://127.0.0.2:9000/callback", "http://[::1]:9000/callback"} {
		config.RedirectURI = redirect
		if !validConfig(config) {
			t.Errorf("literal loopback rejected: %s", redirect)
		}
	}
	for _, redirect := range []string{"http://localhost:9000/callback", "http://192.0.2.1/callback", "https://client.example/callback?"} {
		config.RedirectURI = redirect
		if validConfig(config) {
			t.Errorf("invalid redirect accepted: %s", redirect)
		}
	}
}

func TestLifecyclePreemptiveMissStillValidatesIdentity(t *testing.T) {
	_, p, r := setup(t, "client_credentials")
	r.Binding = nil
	for _, invalid := range []auth.Request{{Destination: r.Destination, Purpose: "unknown"}, {Destination: "https://user:password@example.test/", Purpose: auth.Event}, {Destination: r.Destination, Purpose: auth.Event, Binding: json.RawMessage(`{"type":"unknown"}`)}} {
		credential, err := p.PreemptiveCredential(budget(t), invalid)
		if err == nil || credential != nil {
			t.Fatal("invalid identity became anonymous cache miss")
		}
	}
}

func TestLifecycleNonOAuthRefreshFailureRetainsRetry(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	first := finishLogin(t, p, r)
	expire(t, f, first)
	f.mode.Store("non-oauth")
	_, err := p.Prepare(budget(t), r)
	assertCode(t, err, auth.CodeProviderFailed)
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if record == nil || record.RefreshToken != "refresh-token" || record.RefreshRejected {
		t.Fatal("operational failure discarded authorization")
	}
	f.mode.Store("ok")
	recovered, err := p.Prepare(budget(t), r)
	if err != nil || recovered.Credential == nil || recovered.Login != nil {
		t.Fatalf("operational refresh failure wedged grant: %v", err)
	}
	if f.refreshCalls.Load() != 2 {
		t.Fatal("operational failure did not permit host retry")
	}
}

func TestLifecycleCompletionUsesCurrentSecretAndPolicy(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	original := p.options.SelectClient
	secret := "first-secret"
	denied := false
	p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		if denied {
			return ClientConfig{}, &auth.Error{Code: auth.CodeUntrustedDestination}
		}
		c, err := original(ctx, r, issuers, resource)
		c.ClientSecret = secret
		return c, err
	}
	prepared, err := p.Prepare(budget(t), r)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(prepared.Login.AuthorizationURL())
	callback := "https://client.example/callback?" + url.Values{"state": {u.Query().Get("state")}, "code": {"code"}}.Encode()
	denied = true
	_, err = p.Complete(budget(t), prepared.Login, callback)
	assertCode(t, err, auth.CodeUntrustedDestination)
	if prepared.Login.used.Load() || f.tokenCalls.Load() != 0 {
		t.Fatal("failed policy check consumed consent or exchanged code")
	}
	denied = false
	secret = "rotated-secret"
	_, err = p.Complete(budget(t), prepared.Login, callback)
	if err != nil {
		t.Fatal(err)
	}
	f.grantsMu.Lock()
	used := f.grants[len(f.grants)-1].Get("client_secret")
	f.grantsMu.Unlock()
	if used != "rotated-secret" {
		t.Fatal("completion used stale captured secret")
	}
	_, err = p.Complete(budget(t), prepared.Login, callback)
	assertCode(t, err, auth.CodeInvalidConfiguration)
}

func TestLifecyclePendingBudgetReplacement(t *testing.T) {
	_, p, r := setup(t, "authorization_code_pkce")
	short, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	first, err := p.Prepare(short, r)
	if err != nil {
		t.Fatal(err)
	}
	long, cancelLong := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancelLong()
	second, err := p.Prepare(long, r)
	if err != nil || second.Login == first.Login || !first.Login.used.Load() {
		t.Fatal("long host operation inherited short consent budget")
	}
	if !second.Login.Deadline().After(first.Login.Deadline()) {
		t.Fatal("replacement did not preserve new budget")
	}
	reused, err := p.Prepare(long, r)
	if err != nil || reused.Login != second.Login {
		t.Fatal("polling same host operation replaced its consent")
	}
	u, _ := url.Parse(first.Login.AuthorizationURL())
	callback := "https://client.example/callback?" + url.Values{"state": {u.Query().Get("state")}, "code": {"code"}}.Encode()
	_, err = p.Complete(budget(t), first.Login, callback)
	assertCode(t, err, auth.CodeInvalidConfiguration)
	cancel() // the old operation must not cancel the replacement.
	u, _ = url.Parse(second.Login.AuthorizationURL())
	callback = "https://client.example/callback?" + url.Values{"state": {u.Query().Get("state")}, "code": {"code"}}.Encode()
	if _, err = p.Complete(long, second.Login, callback); err != nil {
		t.Fatalf("old cancellation invalidated replacement: %v", err)
	}
}

func TestLifecycleNoScopeChallengeUsesOnlyHostRequirement(t *testing.T) {
	_, p, r := setup(t, "authorization_code_pkce")
	original := p.options.SelectClient
	required := false
	p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		c, err := original(ctx, r, issuers, resource)
		c.AllowedScopes = []string{"events", "admin"}
		if required {
			c.RequiredScopes = []string{"admin"}
		}
		return c, err
	}
	first := finishLogin(t, p, r)
	challenge := auth.Challenge{StatusCode: 403, Header: http.Header{"Www-Authenticate": {`Bearer error="insufficient_scope"`}}, Attempt: first.Attempt}
	_, err := p.Challenge(budget(t), r, challenge)
	assertCode(t, err, auth.CodeAccessDenied)
	required = true
	_, err = p.Challenge(budget(t), r, challenge)
	assertCode(t, err, auth.CodeInteractionRequired)
	p.mu.Lock()
	count := len(p.pending)
	p.mu.Unlock()
	if count != 0 {
		t.Fatal("no-scope challenge allocated host consent")
	}
	prepared, err := p.Prepare(budget(t), r)
	if err != nil || prepared.Login == nil {
		t.Fatalf("host requirement did not prepare step-up: %v", err)
	}
	u, _ := url.Parse(prepared.Login.AuthorizationURL())
	if !slices.Contains(strings.Fields(u.Query().Get("scope")), "admin") {
		t.Fatal("no-scope challenge invented or lost host requirement")
	}
}

func TestLifecycleRefreshUnknownExpiryRotation(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	first := finishLogin(t, p, r)
	expire(t, f, first)
	f.mode.Store("refresh-unknown-expiry")
	prepared, err := p.Prepare(budget(t), r)
	if err != nil || prepared.Credential == nil {
		t.Fatalf("unknown expiry refresh failed: %v", err)
	}
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if record == nil || !record.ExpiresAt.IsZero() || record.RefreshToken != "rotated-refresh" {
		t.Fatal("unknown expiry dropped rotation")
	}
	again, err := p.Credential(budget(t), r)
	if err != nil || again.Token == "" || f.refreshCalls.Load() != 1 {
		t.Fatal("unknown expiry token was refreshed on next call")
	}
}

func TestLifecycleClientCredentialsTransientReissue(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	f.mode.Store("non-oauth")
	_, err := p.Credential(budget(t), r)
	assertCode(t, err, auth.CodeProviderFailed)
	p.mu.Lock()
	count := len(p.pending)
	p.mu.Unlock()
	if count != 0 {
		t.Fatal("machine outage allocated consent")
	}
	f.mode.Store("ok")
	next, err := p.Credential(budget(t), r)
	if err != nil || next.Token == "" || f.tokenCalls.Load() != 2 {
		t.Fatalf("machine outage not retryable: %v", err)
	}
}

func TestLifecyclePendingScopeContextReplacement(t *testing.T) {
	_, p, r := setup(t, "authorization_code_pkce")
	original := p.options.SelectClient
	stepUp := false
	p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		c, err := original(ctx, r, issuers, resource)
		c.AllowedScopes = []string{"events", "admin"}
		if stepUp {
			c.RequiredScopes = []string{"admin"}
		}
		return c, err
	}
	host := budget(t)
	first, err := p.Prepare(host, r)
	if err != nil {
		t.Fatal(err)
	}
	stepUp = true
	second, err := p.Prepare(host, r)
	if err != nil || first.Login == second.Login || !first.Login.used.Load() {
		t.Fatal("scope step-up reused incompatible consent")
	}
	u, _ := url.Parse(first.Login.AuthorizationURL())
	callback := "https://client.example/callback?" + url.Values{"state": {u.Query().Get("state")}, "code": {"code"}}.Encode()
	_, err = p.Complete(host, first.Login, callback)
	assertCode(t, err, auth.CodeInvalidConfiguration)
	u, _ = url.Parse(second.Login.AuthorizationURL())
	if !slices.Contains(strings.Fields(u.Query().Get("scope")), "admin") {
		t.Fatal("replacement omitted step-up scope")
	}
}

func TestLifecycleCompleteObservesPersistedStepUp(t *testing.T) {
	for _, newer := range []bool{false, true} {
		t.Run(map[bool]string{false: "code-exchange", true: "newer-generation"}[newer], func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			r.Binding = nil
			original := p.options.SelectClient
			p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
				c, err := original(ctx, r, issuers, resource)
				c.AllowedScopes = []string{"events", "admin"}
				return c, err
			}
			host := budget(t)
			prepared, err := p.Prepare(host, r)
			if err != nil {
				t.Fatal(err)
			}
			// No credential has been issued. A real permitted 403 records the binding
			// requirement but must not create, replace, or consume the host's pending
			// consent, whose original URL requests only events.
			_, err = p.Challenge(budget(t), r, auth.Challenge{StatusCode: 403, Header: http.Header{"Www-Authenticate": {`Bearer error="insufficient_scope", scope="admin"`}}})
			assertCode(t, err, auth.CodeInteractionRequired)
			if prepared.Login.used.Load() {
				t.Fatal("dispatch invalidated host consent")
			}
			key := prepared.Login.key
			if newer {
				// A different host process committed a newer otherwise-usable grant while
				// this callback was outstanding. Its scopes still lack the recorded step-up.
				ok, err := f.store.CompareAndSwap(host, key, "", &Record{Generation: "newer-grant", AccessToken: "newer-access", RefreshToken: "newer-refresh", Scopes: []string{"events"}})
				if err != nil || !ok {
					t.Fatalf("install newer grant: %v", err)
				}
			}
			u, _ := url.Parse(prepared.Login.AuthorizationURL())
			callback := "https://client.example/callback?" + url.Values{"state": {u.Query().Get("state")}, "code": {"code"}}.Encode()
			credential, err := p.Complete(host, prepared.Login, callback)
			if err == nil || credential.Token != "" {
				t.Fatal("completion returned credential lacking persisted step-up")
			}
			record, _ := f.store.Load(host, key)
			if newer {
				assertCode(t, err, auth.CodeInteractionRequired)
				if f.tokenCalls.Load() != 0 || record == nil || record.Generation != "newer-grant" {
					t.Fatal("newer insufficient grant was overwritten or code exchanged")
				}
			} else {
				assertCode(t, err, auth.CodeAccessDenied)
				if f.tokenCalls.Load() != 1 || record == nil || record.RefreshToken != "refresh-token" || !sameScopes(record.Scopes, []string{"events"}) {
					t.Fatal("successful exchange was not persisted before insufficiency")
				}
			}
		})
	}
}
