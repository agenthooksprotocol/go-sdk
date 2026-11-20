package oauth

// One test per rule of the cross-SDK scope and step-up contract: R is
// H (host RequiredScopes) ∪ E (explicit Prepare scopes) ∪ Ch (validated 403
// insufficient_scope scopes); requested scopes are never required.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

// configure edits every client the host selects from now on.
func configure(p *Provider, edit func(*ClientConfig)) {
	selectClient := p.options.SelectClient
	p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		c, err := selectClient(ctx, r, issuers, resource)
		edit(&c)
		return c, err
	}
}

// network counts requests to the fixture's metadata and token endpoints.
func network(f *fixture) int32 { return f.metadataCalls.Load() + f.tokenCalls.Load() }

// contractError asserts an exact code and exact scope slice (nil for none).
func contractError(t *testing.T, err error, code auth.Code, scopes ...string) *auth.Error {
	t.Helper()
	assertCode(t, err, code)
	var classified *auth.Error
	errors.As(err, &classified)
	if !slices.Equal(classified.Scopes, scopes) || (len(scopes) == 0 && classified.Scopes != nil) {
		t.Fatalf("%s scopes = %#v; want %#v", code, classified.Scopes, scopes)
	}
	return classified
}

func stepUp(scope string, attempt any) auth.Challenge {
	header := `Bearer error="insufficient_scope"`
	if scope != "" {
		header += `, scope="` + scope + `"`
	}
	return auth.Challenge{StatusCode: 403, Header: http.Header{"Www-Authenticate": {header}}, Attempt: attempt}
}

func tokenScope(f *fixture, scope string) {
	f.tokenBody.Store(`{"access_token":"access-token","refresh_token":"refresh-token","token_type":"Bearer","expires_in":3600,"scope":"` + scope + `"}`)
}

// Rule 1: preset scopes are requested, never required, and never in an error.
func TestScopeContractPresetScopesRequested(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	allowAdmin(p)
	configure(p, func(c *ClientConfig) { c.RequiredScopes = []string{"admin"} })
	// The preset requests events; only the host requirement is in the error.
	_, err := p.Credential(budget(t), r)
	contractError(t, err, auth.CodeInteractionRequired, "admin")
	prepared, err := p.Prepare(budget(t), r)
	if err != nil || prepared.Login == nil || !slices.Equal(merge(loginScopes(prepared.Login)), []string{"admin", "events"}) {
		t.Fatalf("login did not request the preset scopes: %v", err)
	}
	// The grant lacks the preset's events but covers R.
	tokenScope(f, "admin")
	if _, err := p.Complete(budget(t), r, callback(prepared.Login, "code")); err != nil {
		t.Fatalf("grant without preset scopes refused: %v", err)
	}
	if credential, err := p.Credential(budget(t), r); err != nil || credential.Token != "access-token" {
		t.Fatalf("grant covering R unusable: %v", err)
	}
	record, _ := f.store.Load(budget(t), p.key(r, mustConfig(t, p, r)))
	if !slices.Equal(record.Scopes, []string{"admin"}) {
		t.Fatalf("recorded grant = %v", record.Scopes)
	}
}

// Rule 2: a scoped error carries the full R, not only the challenged scopes.
func TestScopeContractOneScopeSet(t *testing.T) {
	_, p, r := setup(t, "authorization_code_pkce")
	allowAdmin(p)
	configure(p, func(c *ClientConfig) { c.RequiredScopes = []string{"events"} })
	first := finishLogin(t, p, r)
	_, err := p.Challenge(budget(t), r, stepUp("admin", first.Attempt))
	contractError(t, err, auth.CodeInteractionRequired, "admin", "events")
	_, err = p.Prepare(budget(t), r, "write")
	contractError(t, err, auth.CodeAccessDenied, "events", "write")
}

// Rule 3: a required scope outside the ceiling is refused locally, before any
// network request, on every path; a 401 still retires its token first.
func TestScopeContractCeilingRefusalIsLocal(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	required := []string(nil)
	configure(p, func(c *ClientConfig) { c.RequiredScopes = required })
	unbound := r
	unbound.Binding = nil

	// Fresh explicit binding, no stored binding: no issuer metadata either.
	required = []string{"admin"}
	_, err := p.Credential(budget(t), r)
	contractError(t, err, auth.CodeAccessDenied, "admin")
	_, err = p.Prepare(budget(t), r)
	contractError(t, err, auth.CodeAccessDenied, "admin")
	if n := network(f); n != 0 {
		t.Fatalf("fresh refusal made %d network calls", n)
	}

	required = nil
	first := finishLogin(t, p, r)
	required = []string{"admin"}
	before := network(f)
	_, err = p.Challenge(budget(t), r, stepUp("events", first.Attempt))
	contractError(t, err, auth.CodeAccessDenied, "admin", "events")
	_, err = p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer`}}, Attempt: first.Attempt})
	contractError(t, err, auth.CodeAccessDenied, "admin")
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if record.AccessToken != "" || record.RefreshToken == "" {
		t.Fatal("401 refusal did not retire the rejected token first")
	}
	// The grant now needs a refresh: still no renewal before the refusal.
	_, err = p.Credential(budget(t), r)
	contractError(t, err, auth.CodeAccessDenied, "admin")
	_, err = p.Prepare(budget(t), r, "write")
	contractError(t, err, auth.CodeAccessDenied, "admin", "write")
	cached, err := p.PreemptiveCredential(budget(t), unbound)
	contractError(t, err, auth.CodeAccessDenied, "admin")
	if cached != nil {
		t.Fatal("preemptive refusal served a credential")
	}
	if n := network(f) - before; n != 0 {
		t.Fatalf("cached refusals made %d network calls", n)
	}
}

// Rule 4: a requested scope outside the ceiling is invalid configuration.
func TestScopeContractRequestedOutsideCeilingInvalid(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	configure(p, func(c *ClientConfig) {
		c.Scopes, c.AllowedScopes = []string{"events", "extra"}, []string{"events"}
	})
	r.Binding, _ = json.Marshal(map[string]any{"type": "oauth", "issuer": f.server.URL, "resource": f.resource, "clientId": "client", "flow": "client_credentials", "scopes": []string{"events", "extra"}})
	_, err := p.Credential(budget(t), r)
	contractError(t, err, auth.CodeInvalidConfiguration)
	if !errors.Is(err, auth.ErrConfig) {
		t.Fatal("invalid configuration is not auth.ErrConfig")
	}
	_, err = p.Prepare(budget(t), r)
	contractError(t, err, auth.CodeInvalidConfiguration)
	if n := network(f); n != 0 {
		t.Fatalf("invalid configuration made %d network calls", n)
	}
}

// Rule 5: a 401 scope retires the token and is requested next (within the
// ceiling), never required, and never yields access_denied.
func TestScopeContract401ScopeIsRequestedNotRequired(t *testing.T) {
	t.Run("client_credentials", func(t *testing.T) {
		f, p, r := setup(t, "client_credentials")
		allowAdmin(p)
		first, err := p.Credential(budget(t), r)
		if err != nil {
			t.Fatal(err)
		}
		// The server grants only events; admin was requested, not required.
		next, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer scope="admin write"`}}, Attempt: first.Attempt})
		if err != nil || next == nil {
			t.Fatalf("401 scope became a requirement: %v", err)
		}
		f.grantsMu.Lock()
		wire := f.grants[len(f.grants)-1].Get("scope")
		f.grantsMu.Unlock()
		if wire != "admin events" || f.tokenCalls.Load() != 2 {
			t.Fatalf("reacquisition requested %q after %d calls", wire, f.tokenCalls.Load())
		}
	})
	t.Run("authorization_code_pkce", func(t *testing.T) {
		f, p, r := setup(t, "authorization_code_pkce")
		allowAdmin(p)
		first := finishLogin(t, p, r)
		f.mode.Store("reject")
		_, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer scope="admin write"`}}, Attempt: first.Attempt})
		contractError(t, err, auth.CodeRefreshRejected)
		f.mode.Store("ok")
		prepared, err := p.Prepare(budget(t), r)
		if err != nil || prepared.Login == nil {
			t.Fatalf("no sign-in after a rejected refresh: %v", err)
		}
		if got := merge(loginScopes(prepared.Login)); !slices.Equal(got, []string{"admin", "events"}) {
			t.Fatalf("sign-in requested %v", got)
		}
		if record := pendingRecord(t, p, r); record.Required != nil {
			t.Fatalf("401 scope stored as required: %v", record.Required)
		}
	})
}

// Rule 6: a 403 insufficient_scope without scope uses H ∪ E, else access_denied
// with no scopes.
func TestScopeContract403WithoutScope(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	allowAdmin(p)
	first := finishLogin(t, p, r)
	before := network(f)
	_, err := p.Challenge(budget(t), r, stepUp("", first.Attempt))
	contractError(t, err, auth.CodeAccessDenied)
	if n := network(f) - before; n != 0 {
		t.Fatalf("scopeless step-up made %d network calls", n)
	}
	configure(p, func(c *ClientConfig) { c.RequiredScopes = []string{"admin"} })
	_, err = p.Challenge(budget(t), r, stepUp("", first.Attempt))
	contractError(t, err, auth.CodeInteractionRequired, "admin")
}

// Rule 7: a malformed challenge scope fails closed with access_denied, no
// scopes and recovery none, for a 403 and for a 401.
func TestScopeContractMalformedChallengeScope(t *testing.T) {
	for _, header := range []string{
		`Bearer error="insufficient_scope", scope=""`,
		`Bearer error="insufficient_scope", scope="a  b"`,
		`Bearer error="insufficient_scope", scope=" a"`,
		`Bearer error="insufficient_scope", scope="a "`,
		`Bearer error="insufficient_scope", scope="a\\b"`,
		`Bearer error="insufficient_scope", scope="a", scope="b"`,
		`Bearer error="insufficient_scope", scope="a", Bearer scope="b"`,
	} {
		t.Run(header, func(t *testing.T) {
			_, p, r := setup(t, "client_credentials")
			first, err := p.Credential(budget(t), r)
			if err != nil {
				t.Fatal(err)
			}
			for _, status := range []int{403, 401} {
				_, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: status, Header: http.Header{"Www-Authenticate": {header}}, Attempt: first.Attempt})
				if classified := contractError(t, err, auth.CodeAccessDenied); classified.Recovery() != auth.RecoveryNone {
					t.Fatalf("recovery %s", classified.Recovery())
				}
			}
		})
	}
}

// Rule 8: a 403 for scopes the stored grant already records is refused, with
// no replay, no interaction and no login.
func TestScopeContractInsufficientButGranted(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	allowAdmin(p)
	f.mode.Store("admin-scope")
	first := finishLogin(t, p, r, "admin")
	before := network(f)
	next, err := p.Challenge(budget(t), r, stepUp("admin", first.Attempt))
	contractError(t, err, auth.CodeAccessDenied, "admin")
	if next != nil || anyPending(p) || network(f) != before {
		t.Fatal("granted step-up replayed, renewed or created a login")
	}
}

// Rule 9: Complete enforces the required set the login was prepared with.
func TestScopeContractCompleteEnforcesStoredRequired(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	allowAdmin(p)
	configure(p, func(c *ClientConfig) { c.RequiredScopes = []string{"events"} })
	prepared, err := p.Prepare(budget(t), r, "admin")
	if err != nil || prepared.Login == nil {
		t.Fatal(err)
	}
	if record := pendingRecord(t, p, r); !slices.Equal(record.Required, []string{"admin", "events"}) {
		t.Fatalf("pending login stored R = %v", record.Required)
	}
	// The server grants events only: R is not covered.
	_, err = p.Complete(budget(t), r, callback(prepared.Login, "code"))
	if classified := contractError(t, err, auth.CodeAccessDenied, "admin", "events"); !classified.LoginEnded {
		t.Fatal("refused completion did not end the login")
	}
	record, _ := f.store.Load(budget(t), p.key(r, mustConfig(t, p, r)))
	if record == nil || record.AccessToken != "access-token" || record.RefreshToken != "refresh-token" || !slices.Equal(record.Scopes, []string{"events"}) {
		t.Fatal("refused completion did not persist the grant")
	}
	_, err = p.Complete(budget(t), r, callback(prepared.Login, "code"))
	contractError(t, err, auth.CodeInteractionRequired)
}

// Rule 10: refresh and client-credentials grants narrower than R are refused
// with R, the grant persisted.
func TestScopeContractNarrowerRenewal(t *testing.T) {
	t.Run("client_credentials", func(t *testing.T) {
		f, p, r := setup(t, "client_credentials")
		allowAdmin(p)
		configure(p, func(c *ClientConfig) { c.RequiredScopes = []string{"admin"} })
		_, err := p.Credential(budget(t), r)
		contractError(t, err, auth.CodeAccessDenied, "admin")
		record, _ := f.store.Load(budget(t), p.key(r, mustConfig(t, p, r)))
		if record == nil || !usable(record) || !slices.Equal(record.Scopes, []string{"events"}) {
			t.Fatal("narrower client-credentials grant not persisted")
		}
	})
	t.Run("refresh", func(t *testing.T) {
		f, p, r := setup(t, "authorization_code_pkce")
		allowAdmin(p)
		first := finishLogin(t, p, r)
		configure(p, func(c *ClientConfig) { c.RequiredScopes = []string{"admin"} })
		expire(t, f, first)
		f.tokenBody.Store(`{"access_token":"refreshed-token","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600,"scope":"events"}`)
		_, err := p.Credential(budget(t), r)
		contractError(t, err, auth.CodeAccessDenied, "admin")
		record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
		if f.refreshCalls.Load() != 1 || record.AccessToken != "refreshed-token" || record.RefreshToken != "rotated-refresh" {
			t.Fatal("narrower refresh not persisted")
		}
	})
}

// Rule 11: errors from host callbacks never carry scopes.
func TestScopeContractHostErrorsCarryNoScopes(t *testing.T) {
	hostError := &auth.Error{Code: auth.CodeAccessDenied, Scopes: []string{"host-scope"}, LoginEnded: true}
	t.Run("SelectClient", func(t *testing.T) {
		_, p, r := setup(t, "client_credentials")
		p.options.SelectClient = func(context.Context, auth.Request, []string, string) (ClientConfig, error) {
			return ClientConfig{}, hostError
		}
		_, err := p.Credential(budget(t), r)
		if contractError(t, err, auth.CodeAccessDenied).LoginEnded {
			t.Fatal("host login state escaped")
		}
	})
	t.Run("CheckDestination", func(t *testing.T) {
		_, p, r := setup(t, "client_credentials")
		p.options.CheckDestination = func(context.Context, string, Purpose) error { return hostError }
		_, err := p.Credential(budget(t), r)
		contractError(t, err, auth.CodeDiscoveryFailed)
	})
	t.Run("ValidateToken", func(t *testing.T) {
		_, p, r := setup(t, "client_credentials")
		p.options.ValidateToken = func(context.Context, ClientConfig, *oauth2.Token) error { return hostError }
		_, err := p.Credential(budget(t), r)
		contractError(t, err, auth.CodeAccessDenied)
	})
	t.Run("ValidateToken on Complete", func(t *testing.T) {
		_, p, r := setup(t, "authorization_code_pkce")
		prepared, err := p.Prepare(budget(t), r)
		if err != nil {
			t.Fatal(err)
		}
		p.options.ValidateToken = func(context.Context, ClientConfig, *oauth2.Token) error { return hostError }
		_, err = p.Complete(budget(t), r, callback(prepared.Login, "code"))
		if !contractError(t, err, auth.CodeAccessDenied).LoginEnded {
			t.Fatal("consumed login not reported ended")
		}
	})
}

// Rule 12: every Complete error reports whether the login named by its state
// still exists.
func TestScopeContractCompleteLoginEnded(t *testing.T) {
	_, p, r := setup(t, "authorization_code_pkce")
	prepared, err := p.Prepare(budget(t), r)
	if err != nil {
		t.Fatal(err)
	}
	valid := callback(prepared.Login, "code")
	state := pendingRecord(t, p, r).State
	ended := func(err error, want bool) {
		t.Helper()
		var classified *auth.Error
		if !errors.As(err, &classified) || classified.LoginEnded != want || !errors.Is(err, auth.ErrCredential) {
			t.Fatalf("LoginEnded = %v; want %v (%v)", classified, want, err)
		}
	}
	// Rejected before the claim: still pending.
	_, err = p.Complete(budget(t), r, "https://elsewhere.example/callback?state="+state+"&code=code")
	ended(err, false)
	_, err = p.Complete(budget(t), r, "https://client.example/callback?state="+state)
	ended(err, false)
	_, err = p.Complete(context.Background(), r, valid)
	assertCode(t, err, auth.CodeInvalidConfiguration)
	ended(err, false)
	cancelled, cancel := context.WithCancel(budget(t))
	cancel()
	_, err = p.Complete(cancelled, r, valid)
	ended(err, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation identity lost")
	}
	// Unknown state, or no state: no such login.
	_, err = p.Complete(budget(t), r, "https://client.example/callback?state=unknown&code=code")
	assertCode(t, err, auth.CodeInteractionRequired)
	ended(err, true)
	_, err = p.Complete(budget(t), r, "https://client.example/callback?code=code")
	ended(err, true)
	if encoded, _ := json.Marshal(err.(*auth.Error)); string(encoded) != `{"Code":"interaction_required","LoginEnded":true}` {
		t.Fatalf("JSON = %s", encoded)
	}
	// Without a login named by its state, even an invalid callback is
	// interaction_required.
	_, err = p.Complete(budget(t), r, "https://client.example/callback?state=unknown&code=code#fragment")
	assertCode(t, err, auth.CodeInteractionRequired)
	ended(err, true)
	// A callback with both code and error is invalid, before the claim.
	_, err = p.Complete(budget(t), r, "https://client.example/callback?state="+state+"&code=code&error=access_denied")
	assertCode(t, err, auth.CodeAccessDenied)
	ended(err, false)
	// Consent denial consumes the login; a replay finds it gone.
	denied := "https://client.example/callback?state=" + state + "&error=access_denied&iss=" + mustConfig(t, p, r).Issuer
	_, err = p.Complete(budget(t), r, denied)
	assertCode(t, err, auth.CodeAccessDenied)
	ended(err, true)
	_, err = p.Complete(budget(t), r, valid)
	assertCode(t, err, auth.CodeInteractionRequired)
	ended(err, true)
}

// A redirect with its own query is invalid configuration, so a callback is
// matched on scheme, host, port and path; parameters the authorization server
// adds (session_state) are allowed.
func TestCompleteRedirectQuery(t *testing.T) {
	_, p, r := setup(t, "authorization_code_pkce")
	_, err := p.PrepareWith(budget(t), r, PrepareOptions{RedirectURI: "https://client.example/callback?tenant=a"})
	contractError(t, err, auth.CodeInvalidConfiguration)
	prepared, err := p.Prepare(budget(t), r)
	if err != nil || prepared.Login == nil {
		t.Fatal(err)
	}
	if _, err := p.Complete(budget(t), r, callback(prepared.Login, "code")+"&session_state=added-by-server"); err != nil {
		t.Fatalf("authorization-server parameter refused: %v", err)
	}
}

// With a nil AllowedScopes, Complete's ceiling is the current requested
// scopes, never the login's requested scopes.
func TestCompleteNilCeilingIsCurrentScopes(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	original := p.options.SelectClient
	allowAdmin(p)
	prepared, err := p.Prepare(budget(t), r, "admin")
	if err != nil || prepared.Login == nil {
		t.Fatal(err)
	}
	// The host drops admin: the ceiling defaults to Scopes, events.
	p.options.SelectClient = original
	f.mode.Store("admin-scope")
	_, err = p.Complete(budget(t), r, callback(prepared.Login, "code"))
	contractError(t, err, auth.CodeAccessDenied, "admin")
}
