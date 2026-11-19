package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

// anyPending reports whether p holds or stored any pending login.
func anyPending(p *Provider) bool {
	switch s := p.logins.(type) {
	case *processLogins:
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.values) > 0
	case *memoryStore:
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, record := range s.values {
			if len(record.Pending) > 0 {
				return true
			}
		}
	}
	return false
}
func errorScopes(t *testing.T, err error) []string {
	t.Helper()
	var classified *auth.Error
	if !errors.As(err, &classified) {
		t.Fatalf("missing classified error: %v", err)
	}
	return classified.Scopes
}
func loginScopes(login *PendingLogin) []string {
	u, _ := url.Parse(login.AuthorizationURL())
	return strings.Fields(u.Query().Get("scope"))
}
func allowAdmin(p *Provider) {
	selectClient := p.options.SelectClient
	p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		c, err := selectClient(ctx, r, issuers, resource)
		c.AllowedScopes = []string{"events", "admin"}
		return c, err
	}
}

func TestLifecycleDeliveryNeverCreatesPendingLogin(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	_, err := p.Credential(budget(t), r)
	assertCode(t, err, auth.CodeInteractionRequired)
	unbound := r
	unbound.Binding = nil
	_, err = p.Challenge(budget(t), unbound, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer resource_metadata="` + f.server.URL + `/custom-resource"`}}})
	assertCode(t, err, auth.CodeInteractionRequired)
	cached, err := p.PreemptiveCredential(budget(t), unbound)
	assertCode(t, err, auth.CodeInteractionRequired)
	if cached != nil {
		t.Fatal("lookup served a credential without a grant")
	}
	if anyPending(p) {
		t.Fatal("delivery path created a pending login")
	}
	if prepared, err := p.Prepare(budget(t), r); err != nil || prepared.Login == nil || !anyPending(p) {
		t.Fatal("explicit prepare did not create a stored login")
	}
}

// The challenge requirement travels in the error, back into an explicit
// prepare, and never into the stored binding.
func TestLifecycleStepUpRoundTrip(t *testing.T) {
	for _, flow := range []string{"authorization_code_pkce", "client_credentials"} {
		t.Run(flow, func(t *testing.T) {
			f, p, r := setup(t, flow)
			allowAdmin(p)
			var credential auth.Credential
			if flow == "authorization_code_pkce" {
				credential = finishLogin(t, p, r)
			} else {
				var err error
				if credential, err = p.Credential(budget(t), r); err != nil {
					t.Fatal(err)
				}
			}
			challenge := auth.Challenge{StatusCode: 403, Header: http.Header{"Www-Authenticate": {`Bearer error="insufficient_scope", scope="admin"`}}, Attempt: credential.Attempt}
			_, err := p.Challenge(budget(t), r, challenge)
			if flow == "authorization_code_pkce" {
				assertCode(t, err, auth.CodeInteractionRequired)
				if !slices.Equal(errorScopes(t, err), []string{"admin"}) || anyPending(p) {
					t.Fatal("step-up error lost scopes or created a login")
				}
				prepared, err := p.Prepare(budget(t), r, errorScopes(t, err)...)
				if err != nil || prepared.Login == nil || !slices.Contains(loginScopes(prepared.Login), "admin") {
					t.Fatalf("host step-up consent omitted requirement: %v", err)
				}
				f.mode.Store("admin-scope")
				if _, err := p.Complete(budget(t), r, callback(prepared.Login, "step-up")); err != nil {
					t.Fatal(err)
				}
			} else {
				// The real token server returns its old narrowed scope. The new grant
				// is persisted, but no insufficient credential is dispatched.
				assertCode(t, err, auth.CodeAccessDenied)
				if !slices.Equal(errorScopes(t, err), []string{"admin"}) || f.tokenCalls.Load() != 2 {
					t.Fatal("machine grant did not reissue without login")
				}
				f.grantsMu.Lock()
				last := f.grants[len(f.grants)-1]
				f.grantsMu.Unlock()
				if !slices.Contains(strings.Fields(last.Get("scope")), "admin") {
					t.Fatal("machine grant omitted approved scope")
				}
			}
			challenge.Header.Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="forbidden"`)
			_, err = p.Challenge(budget(t), r, challenge)
			assertCode(t, err, auth.CodeAccessDenied)
		})
	}
}

// Requirements are operation-scoped: later operations use the stored grant,
// including scopes added by step-up consent, without the old requirement.
func TestLifecycleStepUpRequirementOperationScoped(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	allowAdmin(p)
	first := finishLogin(t, p, r)
	_, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 403, Header: http.Header{"Www-Authenticate": {`Bearer error="insufficient_scope", scope="admin"`}}, Attempt: first.Attempt})
	assertCode(t, err, auth.CodeInteractionRequired)
	binding, _ := f.store.Load(budget(t), p.bindingKey(r))
	if binding == nil || binding.Binding == nil || len(binding.Binding.Config.RequiredScopes) != 0 {
		t.Fatal("challenge requirement persisted on the binding")
	}
	// The challenge dropped the rejected token; a plain operation refreshes
	// the stored grant rather than inheriting the old requirement.
	if next, err := p.Credential(budget(t), r); err != nil || next.Token == "" {
		t.Fatalf("later operation inherited step-up requirement: %v", err)
	}
	f.mode.Store("admin-scope")
	finishLogin(t, p, r, "admin")
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if !sameScopes(record.Scopes, []string{"events", "admin"}) {
		t.Fatal("step-up consent not recorded")
	}
	f.mode.Store("ok")
	if _, err := p.Prepare(budget(t), r, "admin"); err != nil {
		t.Fatalf("stored step-up grant unusable: %v", err)
	}
}

// Token validity crosses the real token endpoint: a malformed expires_in is
// never dispatched, an initial response persists nothing, and a refresh keeps
// only a valid rotated refresh token.
func TestLifecycleTokenValidity(t *testing.T) {
	invalid := []string{`null`, `0`, `-1`, `3600.5`, `"0"`, `"-1"`, `"3600.5"`, `"1e3"`, `"abc"`, `true`, `{}`}
	for _, raw := range invalid {
		t.Run("refresh "+raw, func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			first := finishLogin(t, p, r)
			expire(t, f, first)
			f.tokenBody.Store(`{"access_token":"new-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":` + raw + `}`)
			_, err := p.Prepare(budget(t), r)
			assertCode(t, err, auth.CodeProviderFailed)
			record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
			if record == nil || record.RefreshToken != "rotated-refresh" || usable(record) {
				t.Fatal("rotated refresh lost or invalid token stored")
			}
		})
		t.Run("initial "+raw, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			f.tokenBody.Store(`{"access_token":"new-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":` + raw + `}`)
			_, err := p.Credential(budget(t), r)
			assertCode(t, err, auth.CodeProviderFailed)
			config, _, _, _ := p.cachedBinding(budget(t), r)
			if record, _ := f.store.Load(budget(t), p.key(r, config)); record != nil {
				t.Fatal("invalid initial response persisted")
			}
		})
	}
	// Responses x/oauth2 rejects before the SDK sees the token still keep the
	// rotated refresh token.
	for name, body := range map[string]string{
		"missing access token":      `{"refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600}`,
		"numeric access token":      `{"access_token":5,"refresh_token":"rotated-refresh","token_type":"Bearer"}`,
		"numeric token type":        `{"access_token":"new-access","refresh_token":"rotated-refresh","token_type":5}`,
		"201 malformed expiry":      `201 {"access_token":"new-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600.5}`,
		"overflowing expiry":        `{"access_token":"new-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":1e400}`,
		"form missing access token": `form refresh_token=rotated-refresh&token_type=Bearer`,
	} {
		t.Run("refresh "+name, func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			first := finishLogin(t, p, r)
			expire(t, f, first)
			f.tokenBody.Store(body)
			_, err := p.Prepare(budget(t), r)
			assertCode(t, err, auth.CodeProviderFailed)
			record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
			if record == nil || record.RefreshToken != "rotated-refresh" || usable(record) {
				t.Fatal("rotated refresh lost or invalid token stored")
			}
		})
	}
	t.Run("invalid rotated refresh keeps previous", func(t *testing.T) {
		f, p, r := setup(t, "authorization_code_pkce")
		first := finishLogin(t, p, r)
		expire(t, f, first)
		f.tokenBody.Store(`{"access_token":"new-access","refresh_token":"bad\nrefresh","token_type":"MAC"}`)
		_, err := p.Prepare(budget(t), r)
		assertCode(t, err, auth.CodeProviderFailed)
		if record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key); record == nil || record.RefreshToken != "refresh-token" {
			t.Fatal("invalid rotated refresh replaced the previous one")
		}
	})
	for _, raw := range []string{`3600`, `"3600"`, `99999999999999999999`, `"99999999999999999999"`} {
		t.Run("valid "+raw, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			f.tokenBody.Store(`{"access_token":"access-token","token_type":"Bearer","expires_in":` + raw + `}`)
			credential, err := p.Credential(budget(t), r)
			if err != nil || credential.Token != "access-token" {
				t.Fatalf("valid expiry rejected: %v", err)
			}
			record, _ := f.store.Load(budget(t), credential.Attempt.(attempted).key)
			if record.ExpiresAt.IsZero() {
				t.Fatal("expiry classification mismatch")
			}
		})
	}
}

// A panic in a real host callback must not strand the host grant coordinator.
// Production does not catch arbitrary host panics.
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
			required := false
			p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
				c, err := selectClient(ctx, r, issuers, resource)
				c.Scopes = []string{"events", "admin"}
				if required {
					c.RequiredScopes = []string{"admin"}
				}
				return c, err
			}
			var binding map[string]any
			if err := json.Unmarshal(r.Binding, &binding); err != nil {
				t.Fatal(err)
			}
			binding["scopes"] = []string{"events", "admin"}
			r.Binding, _ = json.Marshal(binding)
			// The real initial response narrows read+write to read ("events").
			first := finishLogin(t, p, r)
			expire(t, f, first)
			f.mode.Store(mode)
			next, err := p.Prepare(budget(t), r)
			record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
			if err != nil || next.Credential == nil || record == nil || record.RefreshToken != "rotated-refresh" || !sameScopes(record.Scopes, []string{"events"}) {
				t.Fatalf("refresh did not keep the narrowed grant and rotation: %v", err)
			}
			if mode == "refresh-omitted-scope" {
				return
			}
			// The ignored broadening is not usable for an admin-requiring operation.
			required = true
			_, err = p.Credential(budget(t), r)
			assertCode(t, err, auth.CodeAccessDenied)
			required = false
			recreated, err := New(p.options)
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequestWithContext(budget(t), http.MethodPost, r.Destination, strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			response, err := auth.Do(f.server.Client(), request, r, auth.Route(auth.Routes{OAuth: recreated}))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatal("narrowed grant not usable after provider recreation")
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
			if anyPending(p) {
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
	_, err = p.Complete(budget(t), r, callback(prepared.Login, "used"))
	assertCode(t, err, auth.CodeInteractionRequired)
}

func TestLifecycleLiteralLoopbackRedirect(t *testing.T) {
	config := ClientConfig{Issuer: "https://issuer.example", Resource: "https://api.example", ClientID: "client", Flow: "authorization_code_pkce", Scopes: []string{"events"}}
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
	if record == nil || record.RefreshToken != "refresh-token" {
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
	denied = true
	_, err = p.Complete(budget(t), r, callback(prepared.Login, "code"))
	assertCode(t, err, auth.CodeUntrustedDestination)
	denied = false
	if pendingRecord(t, p, r) == nil || f.tokenCalls.Load() != 0 {
		t.Fatal("failed policy check consumed consent or exchanged code")
	}
	secret = "rotated-secret"
	if _, err = p.Complete(budget(t), r, callback(prepared.Login, "code")); err != nil {
		t.Fatal(err)
	}
	f.grantsMu.Lock()
	used := f.grants[len(f.grants)-1].Get("client_secret")
	f.grantsMu.Unlock()
	if used != "rotated-secret" {
		t.Fatal("completion used stale captured secret")
	}
	stored, _ := json.Marshal(f.store.values)
	if strings.Contains(string(stored), "secret\"") || strings.Contains(string(stored), "rotated-secret") || strings.Contains(string(stored), "first-secret") {
		t.Fatal("runtime client secret persisted")
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
	if anyPending(p) {
		t.Fatal("no-scope challenge allocated host consent")
	}
	prepared, err := p.Prepare(budget(t), r)
	if err != nil || prepared.Login == nil || !slices.Contains(loginScopes(prepared.Login), "admin") {
		t.Fatalf("no-scope challenge invented or lost host requirement: %v", err)
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

func TestLifecycleRefreshInvalidGrant(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(map[bool]string{false: "drops-tokens", true: "stale-keeps-newer"}[stale], func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			first := finishLogin(t, p, r)
			expire(t, f, first)
			key := first.Attempt.(attempted).key
			if stale {
				// Another process, whose coordination lease lapsed, commits a newer
				// grant while this refresh is in flight.
				f.onRefresh = func() {
					current, _ := f.store.Load(context.Background(), key)
					newer := cloneRecord(current)
					newer.AccessToken, newer.RefreshToken, newer.ExpiresAt, newer.Generation = "newer-access", "newer-refresh", time.Now().Add(time.Hour), "newer"
					f.store.CompareAndSwap(context.Background(), key, current.Generation, newer)
				}
			}
			f.mode.Store("reject")
			_, err := p.Prepare(budget(t), r)
			assertCode(t, err, auth.CodeRefreshRejected)
			record, _ := f.store.Load(budget(t), key)
			if stale {
				if record == nil || record.Generation != "newer" || record.RefreshToken != "newer-refresh" {
					t.Fatal("stale invalid_grant wiped a newer record")
				}
				return
			}
			if record == nil || record.AccessToken != "" || record.RefreshToken != "" {
				t.Fatal("invalid_grant kept tokens")
			}
			if prepared, err := p.Prepare(budget(t), r); err != nil || prepared.Login == nil {
				t.Fatalf("rejected refresh cannot be repaired by consent: %v", err)
			}
		})
	}
}

func TestLifecycleTokenValidationFailureClearsInFlight(t *testing.T) {
	for _, exchange := range []string{"code", "refresh"} {
		t.Run(exchange, func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			var key string
			if exchange == "refresh" {
				first := finishLogin(t, p, r)
				key = first.Attempt.(attempted).key
				expire(t, f, first)
				f.mode.Store("wrong-type")
				_, err := p.Prepare(budget(t), r)
				assertCode(t, err, auth.CodeProviderFailed)
				record, _ := f.store.Load(budget(t), key)
				if record == nil || record.RefreshToken != "refresh-token" || usable(record) {
					t.Fatal("invalid refresh response left wrong state")
				}
			} else {
				prepared, err := p.Prepare(budget(t), r)
				if err != nil {
					t.Fatal(err)
				}
				f.mode.Store("wrong-type")
				_, err = p.Complete(budget(t), r, callback(prepared.Login, "code"))
				assertCode(t, err, auth.CodeProviderFailed)
				config, _, _, _ := p.cachedBinding(budget(t), r)
				key = p.key(r, config)
				record, _ := f.store.Load(budget(t), key)
				if record != nil || anyPending(p) {
					t.Fatal("invalid code exchange persisted tokens or left the login in flight")
				}
			}
			f.mode.Store("ok")
			if prepared, err := p.Prepare(budget(t), r); err != nil || (prepared.Credential == nil) == (exchange == "refresh") {
				t.Fatalf("grant wedged after invalid response: %v", err)
			}
		})
	}
}

func TestLifecycleClientCredentialsTransientReissue(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	f.mode.Store("non-oauth")
	_, err := p.Credential(budget(t), r)
	assertCode(t, err, auth.CodeProviderFailed)
	if anyPending(p) {
		t.Fatal("machine outage allocated consent")
	}
	f.mode.Store("ok")
	next, err := p.Credential(budget(t), r)
	if err != nil || next.Token == "" || f.tokenCalls.Load() != 2 {
		t.Fatalf("machine outage not retryable: %v", err)
	}
}

// Widening the ceiling keeps the grant key; the grant is re-intersected with
// the current ceiling at use.
func TestLifecycleScopeCeilingWideningKeepsGrant(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	first, err := p.Credential(budget(t), r)
	if err != nil {
		t.Fatal(err)
	}
	original := p.options.SelectClient
	p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		c, err := original(ctx, r, issuers, resource)
		c.AllowedScopes = []string{"events", "admin", "write"}
		return c, err
	}
	widened, err := p.Credential(budget(t), r)
	if err != nil || widened.Token != first.Token || f.tokenCalls.Load() != 1 {
		t.Fatalf("widened ceiling orphaned the grant: %v", err)
	}
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if satisfies(record, ClientConfig{AllowedScopes: []string{"admin"}, RequiredScopes: []string{"events"}}) {
		t.Fatal("stored grant not re-intersected with the current ceiling")
	}
}

func TestLifecycleExtraGrantedScopeIgnored(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	f.mode.Store("extra-scope")
	credential, err := p.Credential(budget(t), r)
	if err != nil {
		t.Fatalf("extra granted scopes rejected: %v", err)
	}
	record, _ := f.store.Load(budget(t), credential.Attempt.(attempted).key)
	if !sameScopes(record.Scopes, []string{"events"}) {
		t.Fatalf("scopes outside the ceiling recorded: %v", record.Scopes)
	}
}

// Narrowing the ceiling hides scopes at use only; a refresh under the narrow
// ceiling keeps the grant, so widening again restores the scope.
func TestLifecycleScopeCeilingNarrowingKeepsGrant(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	original := p.options.SelectClient
	ceiling := []string{"events", "admin"}
	p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		c, err := original(ctx, r, issuers, resource)
		c.AllowedScopes = ceiling
		return c, err
	}
	f.mode.Store("admin-scope")
	first := finishLogin(t, p, r, "admin")
	ceiling = []string{"events"}
	if _, err := p.Credential(budget(t), r); err != nil {
		t.Fatal(err)
	}
	expire(t, f, first)
	f.mode.Store("refresh-omitted-scope")
	if _, err := p.Credential(budget(t), r); err != nil || f.refreshCalls.Load() != 1 {
		t.Fatalf("refresh under narrow ceiling: %v", err)
	}
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if !sameScopes(record.Scopes, []string{"events", "admin"}) {
		t.Fatalf("narrow ceiling shrank the stored grant: %v", record.Scopes)
	}
	ceiling = []string{"events", "admin"}
	if prepared, err := p.Prepare(budget(t), r, "admin"); err != nil || prepared.Credential == nil {
		t.Fatalf("widened ceiling lost the scope: %v", err)
	}
}

func TestLifecyclePrepareRequiredOutsideCeilingDenied(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	_, err := p.Prepare(budget(t), r, "admin")
	assertCode(t, err, auth.CodeAccessDenied)
	if anyPending(p) || f.tokenCalls.Load() != 0 {
		t.Fatal("required scope outside the ceiling started acquisition")
	}
}

// Step-up consent requests and keeps the previous grant even when the new
// caller's ceiling no longer covers it.
func TestLifecycleStepUpKeepsPreviousGrant(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	first := finishLogin(t, p, r)
	original := p.options.SelectClient
	p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		c, err := original(ctx, r, issuers, resource)
		c.AllowedScopes = []string{"admin"}
		return c, err
	}
	prepared, err := p.Prepare(budget(t), r, "admin")
	if err != nil || prepared.Login == nil || !slices.Equal(merge(loginScopes(prepared.Login)), []string{"admin", "events"}) {
		t.Fatalf("step-up consent dropped the previous grant: %v", err)
	}
	f.mode.Store("admin-scope")
	if _, err := p.Complete(budget(t), r, callback(prepared.Login, "step-up")); err != nil {
		t.Fatal(err)
	}
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if !sameScopes(record.Scopes, []string{"events", "admin"}) {
		t.Fatalf("step-up lost earlier scopes: %v", record.Scopes)
	}
}

// A 403 insufficient_scope keeps the still-valid token: only the scope
// requirement drives step-up.
func TestLifecycleInsufficientScopeKeepsToken(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	allowAdmin(p)
	first := finishLogin(t, p, r)
	key := first.Attempt.(attempted).key
	record, _ := f.store.Load(budget(t), key)
	stripped := cloneRecord(record)
	stripped.RefreshToken, stripped.Generation = "", randomID()
	if ok, err := f.store.CompareAndSwap(budget(t), key, record.Generation, stripped); !ok || err != nil {
		t.Fatal(err)
	}
	_, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 403, Header: http.Header{"Www-Authenticate": {`Bearer error="insufficient_scope", scope="admin"`}}, Attempt: first.Attempt})
	assertCode(t, err, auth.CodeInteractionRequired)
	if next, err := p.Credential(budget(t), r); err != nil || next.Token != first.Token {
		t.Fatalf("step-up challenge dropped the still-valid token: %v", err)
	}
}

// cancelAfterToken cancels the caller right after the token response arrives.
type cancelAfterToken struct {
	base   http.RoundTripper
	cancel func()
}

func (c cancelAfterToken) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := c.base.RoundTrip(r)
	if err == nil && r.URL.Path == "/token" {
		c.cancel()
	}
	return response, err
}

type slowSaveStore struct {
	*memoryStore
	delay time.Duration
}

// CompareAndSwap is slow only for the write after the refresh token is spent.
func (s slowSaveStore) CompareAndSwap(ctx context.Context, key, expected string, value *Record) (bool, error) {
	if value != nil && value.RefreshToken == "rotated-refresh" {
		time.Sleep(s.delay)
	}
	return s.memoryStore.CompareAndSwap(ctx, key, expected, value)
}

// Once a refresh token is spent, persisting the rotated one survives a slow
// store or a caller cancelled right after the token response.
func TestLifecycleRotationPersistsPastCancellation(t *testing.T) {
	for _, mode := range []string{"slow-store", "cancel-after-response", "cancel-after-undecodable"} {
		t.Run(mode, func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			first := finishLogin(t, p, r)
			expire(t, f, first)
			f.mode.Store("refresh-unknown-expiry")
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			switch mode {
			case "slow-store":
				p.options.Store = slowSaveStore{f.store, 500 * time.Millisecond}
			case "cancel-after-undecodable":
				f.tokenBody.Store(`{"refresh_token":"rotated-refresh","token_type":"Bearer"}`)
				p.client.Transport = cancelAfterToken{p.client.Transport, cancel}
			default:
				validate := p.options.ValidateToken
				p.options.ValidateToken = func(c context.Context, config ClientConfig, token *oauth2.Token) error {
					cancel()
					return validate(c, config, token)
				}
			}
			_, _ = p.Prepare(ctx, r)
			record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
			if record == nil || record.RefreshToken != "rotated-refresh" {
				t.Fatal("rotated refresh lost to caller cancellation")
			}
		})
	}
}

// Once a refresh request is sent, its response is received and committed even
// if the caller cancels mid-flight; the caller still sees cancellation.
func TestLifecycleSentExchangeCompletesDetached(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	first := finishLogin(t, p, r)
	expire(t, f, first)
	sent, resume := make(chan struct{}), make(chan struct{})
	serve := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/token" {
			req.ParseForm()
			if req.PostForm.Get("grant_type") == "refresh_token" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				close(sent)
				<-resume
				w.Write([]byte(`{"access_token":"new-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600}`))
				return
			}
		}
		serve.ServeHTTP(w, req)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := p.Prepare(ctx, r); done <- err }()
	<-sent
	cancel()
	time.Sleep(50 * time.Millisecond)
	close(resume)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller did not see cancellation: %v", err)
	}
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if record == nil || record.RefreshToken != "rotated-refresh" || record.AccessToken != "new-access" {
		t.Fatal("sent exchange was abandoned on caller cancellation")
	}
}

// stalledDial models a connect that never completes: nothing is written.
type stalledDial struct{ base http.RoundTripper }

func (s stalledDial) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/token" {
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-time.After(10 * time.Second):
		}
	}
	return s.base.RoundTrip(r)
}

// Before the request is written, caller cancellation still aborts a token
// exchange promptly and releases the grant lock.
func TestLifecycleCancelBeforeSendReturnsPromptly(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	first := finishLogin(t, p, r)
	expire(t, f, first)
	p.client.Transport = stalledDial{p.client.Transport}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err := p.Prepare(ctx, r)
	if !errors.Is(err, context.Canceled) || time.Since(start) > 2*time.Second {
		t.Fatalf("cancelled pre-send exchange blocked %v: %v", time.Since(start), err)
	}
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if record == nil || record.RefreshToken != "refresh-token" {
		t.Fatal("unsent refresh changed the stored grant")
	}
}

// A form-encoded token response follows the JSON scope rules: an absent field
// is absent rather than "", a present empty field is blank, both inherit, and
// a present value keeps its exact text even when it looks numeric.
func TestLifecycleFormEncodedScope(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		granted    []string
		expiry     bool
		malformed  bool
	}{
		{name: "absent", body: "access_token=new-access&token_type=Bearer", granted: []string{"events"}},
		{name: "blank", body: "access_token=new-access&token_type=Bearer&scope=", granted: []string{"events"}},
		{name: "whitespace", body: "access_token=new-access&token_type=Bearer&scope=%20%09%0D%0A", granted: []string{"events"}},
		{name: "numeric", body: "access_token=new-access&token_type=Bearer&scope=123", granted: []string{"123"}},
		{name: "list", body: "access_token=new-access&token_type=Bearer&scope=events+123&expires_in=3600", granted: []string{"123", "events"}, expiry: true},
		{name: "repeated separator", body: "access_token=new-access&token_type=Bearer&scope=events++123", malformed: true},
		{name: "tab separator", body: "access_token=new-access&token_type=Bearer&scope=events%09123", malformed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			selectClient := p.options.SelectClient
			p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
				c, err := selectClient(ctx, r, issuers, resource)
				c.AllowedScopes = []string{"events", "123"}
				return c, err
			}
			f.tokenBody.Store("form " + tc.body)
			credential, err := p.Credential(budget(t), r)
			if tc.malformed {
				assertCode(t, err, auth.CodeProviderFailed)
				return
			}
			if err != nil {
				t.Fatalf("form response rejected: %v", err)
			}
			record, _ := f.store.Load(budget(t), credential.Attempt.(attempted).key)
			if !slices.Equal(merge(record.Scopes), merge(tc.granted)) {
				t.Fatalf("granted %v; want %v", record.Scopes, tc.granted)
			}
			if record.ExpiresAt.IsZero() == tc.expiry {
				t.Fatal("expiry classification mismatch")
			}
		})
	}
	t.Run("refresh absent inherits previous grant", func(t *testing.T) {
		f, p, r := setup(t, "authorization_code_pkce")
		first := finishLogin(t, p, r)
		expire(t, f, first)
		f.tokenBody.Store("form access_token=new-access&token_type=Bearer&refresh_token=rotated-refresh")
		prepared, err := p.Prepare(budget(t), r)
		if err != nil || prepared.Credential == nil {
			t.Fatalf("form refresh rejected: %v", err)
		}
		record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
		if record.RefreshToken != "rotated-refresh" || !slices.Equal(record.Scopes, []string{"events"}) {
			t.Fatalf("refresh record = %v %v", record.RefreshToken != "", record.Scopes)
		}
	})
}

// Preparations counts only successful host prepares for one endpoint: a login
// that has not completed does not count; its completion and a prepare that
// returns a credential do.
func TestProviderPreparations(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	var tracker auth.PreparationTracker = p
	other := r
	other.Destination = f.server.URL + "/other"
	state, err := p.Prepare(budget(t), r)
	if err != nil || state.Login == nil || tracker.Preparations(r) != 0 {
		t.Fatalf("pending login counted: %v %d", err, tracker.Preparations(r))
	}
	if _, err := p.Complete(budget(t), r, callback(state.Login, "test-code")); err != nil || tracker.Preparations(r) != 1 {
		t.Fatalf("completed login not counted: %v", err)
	}
	if prepared, err := p.Prepare(budget(t), r); err != nil || prepared.Credential == nil || tracker.Preparations(r) != 2 {
		t.Fatalf("credential prepare not counted: %v", err)
	}
	unbound := r
	unbound.Binding = nil
	normalized := unbound
	normalized.Destination = strings.Replace(r.Destination, "https://", "HTTPS://", 1)
	if tracker.Preparations(unbound) != 2 || tracker.Preparations(normalized) != 2 || tracker.Preparations(other) != 0 {
		t.Fatal("preparations keyed by binding or shared across destinations")
	}
	f.mode.Store("non-oauth")
	expire(t, f, auth.Credential{Attempt: attempted{key: p.key(r, mustConfig(t, p, r))}})
	if _, err := p.Prepare(budget(t), r); err == nil || tracker.Preparations(r) != 2 {
		t.Fatalf("failed prepare counted: %v", err)
	}
}

func mustConfig(t *testing.T, p *Provider, r auth.Request) ClientConfig {
	t.Helper()
	config, _, _, err := p.cachedBinding(budget(t), r)
	if err != nil {
		t.Fatal(err)
	}
	return config
}
