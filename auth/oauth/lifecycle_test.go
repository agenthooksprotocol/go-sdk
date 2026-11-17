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

// anyPending reports whether any stored record holds a pending login.
func anyPending(s *memoryStore) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.values {
		if record.Pending != nil {
			return true
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
	if anyPending(f.store) {
		t.Fatal("delivery path created a pending login")
	}
	if prepared, err := p.Prepare(budget(t), r); err != nil || prepared.Login == nil || !anyPending(f.store) {
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
				if !slices.Equal(errorScopes(t, err), []string{"admin"}) || anyPending(f.store) {
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
	invalid := []string{`0`, `-1`, `3600.5`, `"0"`, `"-1"`, `"3600.5"`, `"1e3"`, `"abc"`, `true`, `{}`}
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
		"missing access token": `{"refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600}`,
		"numeric access token": `{"access_token":5,"refresh_token":"rotated-refresh","token_type":"Bearer"}`,
		"numeric token type":   `{"access_token":"new-access","refresh_token":"rotated-refresh","token_type":5}`,
		"201 malformed expiry": `201 {"access_token":"new-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600.5}`,
		"overflowing expiry":   `{"access_token":"new-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":1e400}`,
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
	for _, raw := range []string{`3600`, `"3600"`, `99999999999999999999`, `"99999999999999999999"`, `null`} {
		t.Run("valid "+raw, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			f.tokenBody.Store(`{"access_token":"access-token","token_type":"Bearer","expires_in":` + raw + `}`)
			credential, err := p.Credential(budget(t), r)
			if err != nil || credential.Token != "access-token" {
				t.Fatalf("valid expiry rejected: %v", err)
			}
			record, _ := f.store.Load(budget(t), credential.Attempt.(attempted).key)
			if (raw == `null`) != record.ExpiresAt.IsZero() {
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
			if anyPending(f.store) {
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
	if pendingRecord(t, f, p, r) == nil || f.tokenCalls.Load() != 0 {
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
	f, p, r := setup(t, "authorization_code_pkce")
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
	if anyPending(f.store) {
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
				if record == nil || record.RefreshToken != "refresh-token" || usable(record) || record.Pending != nil {
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
				if record == nil || record.Pending != nil || record.AccessToken != "" || record.RefreshToken != "" {
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
	if anyPending(f.store) {
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
	if anyPending(f.store) || f.tokenCalls.Load() != 0 {
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
	for _, mode := range []string{"slow-store", "cancel-after-response"} {
		t.Run(mode, func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			first := finishLogin(t, p, r)
			expire(t, f, first)
			f.mode.Store("refresh-unknown-expiry")
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			if mode == "slow-store" {
				p.options.Store = slowSaveStore{f.store, 500 * time.Millisecond}
			} else {
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
