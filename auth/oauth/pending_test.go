package oauth

import (
	"context"
	"maps"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

func TestPendingLoginFixedLifetime(t *testing.T) {
	for _, lifetime := range []time.Duration{0, 2 * time.Minute} {
		f, p, r := setup(t, "authorization_code_pkce")
		p.options.LoginLifetime = lifetime
		if lifetime == 0 {
			p.options.LoginLifetime = maxLoginLifetime
		}
		creator, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		before := time.Now()
		prepared, err := p.Prepare(creator, r)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		want := p.options.LoginLifetime
		if got := prepared.Login.Deadline().Sub(before); got < want || got > want+time.Minute {
			t.Fatalf("lifetime %v, want %v independent of the creating deadline", got, want)
		}
		// The creating prepare is cancelled; the stored login still completes.
		if _, err := p.Complete(budget(t), r, callback(prepared.Login, "code")); err != nil || f.tokenCalls.Load() != 1 {
			t.Fatalf("login did not survive its creator: %v", err)
		}
	}
	_, p, _ := setup(t, "authorization_code_pkce")
	options := p.options
	for _, invalid := range []time.Duration{-time.Second, maxLoginLifetime + time.Second} {
		options.LoginLifetime = invalid
		if _, err := New(options); err == nil {
			t.Fatalf("unbounded login lifetime %v accepted", invalid)
		}
	}
}

func TestPendingLoginEndStates(t *testing.T) {
	for _, end := range []string{"completion", "denial", "cancel", "expiry", "cap"} {
		t.Run(end, func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			if end == "expiry" {
				p.options.LoginLifetime = 50 * time.Millisecond
			}
			prepared, err := p.Prepare(budget(t), r)
			if err != nil {
				t.Fatal(err)
			}
			valid := callback(prepared.Login, "code")
			switch end {
			case "completion":
				if _, err := p.Complete(budget(t), r, valid); err != nil {
					t.Fatal(err)
				}
			case "denial":
				u, _ := url.Parse(valid)
				q := u.Query()
				q.Del("code")
				q.Set("error", "access_denied")
				_, err := p.Complete(budget(t), r, "https://client.example/callback?"+q.Encode())
				assertCode(t, err, auth.CodeAccessDenied)
			case "cancel":
				// Another login for the grant stays pending.
				other, err := p.Prepare(budget(t), r)
				if err != nil {
					t.Fatal(err)
				}
				if err := p.Cancel(budget(t), r, prepared.Login); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := p.Complete(budget(t), r, callback(other.Login, "other")); err != nil {
						t.Fatalf("cancel ended another login: %v", err)
					}
				}()
			case "expiry":
				time.Sleep(100 * time.Millisecond)
			case "cap":
				p.options.MaxPendingLogins = 1
				if _, err := p.Prepare(budget(t), r); err != nil {
					t.Fatal(err)
				}
			}
			calls := f.tokenCalls.Load()
			_, err = p.Complete(budget(t), r, valid)
			assertCode(t, err, auth.CodeInteractionRequired)
			if f.tokenCalls.Load() != calls {
				t.Fatal("ended login exchanged a code")
			}
		})
	}
	// Cancel never deletes a valid stored grant.
	f, p, r := setup(t, "authorization_code_pkce")
	allowAdmin(p)
	first := finishLogin(t, p, r)
	prepared, err := p.Prepare(budget(t), r, "admin")
	if err != nil || prepared.Login == nil {
		t.Fatal(err)
	}
	if err := p.Cancel(budget(t), r, prepared.Login); err != nil {
		t.Fatal(err)
	}
	if err := p.Cancel(budget(t), r, nil); err != nil {
		t.Fatal(err)
	}
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if record == nil || record.AccessToken != first.Token || anyPending(p) {
		t.Fatal("cancel changed the stored grant or kept a login")
	}
}

// By default a pending login lives in the Provider that created it: another
// process sharing the Store cannot complete it.
func TestPendingLoginOwnedByCreatingProcess(t *testing.T) {
	f, first, r := setup(t, "authorization_code_pkce")
	prepared, err := first.Prepare(budget(t), r)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(first.options)
	if err != nil {
		t.Fatal(err)
	}
	_, err = second.Complete(budget(t), r, callback(prepared.Login, "code"))
	assertCode(t, err, auth.CodeInteractionRequired)
	if f.tokenCalls.Load() != 0 || len(f.dumpStore(t, "ahp.oauth.pending:")) != 0 {
		t.Fatal("process-owned login reached the store or the token endpoint")
	}
	credential, err := first.Complete(budget(t), r, callback(prepared.Login, "code"))
	if err != nil || credential.Token == "" {
		t.Fatalf("creating process could not complete its login: %v", err)
	}
	if cached, err := second.Credential(budget(t), r); err != nil || cached.Token != credential.Token {
		t.Fatal("other process did not see the completed grant")
	}
}

// With PersistLogins, another process sharing the Store completes a login by
// state; the PKCE verifier lives only in the pending record.
func TestPendingLoginPersistedCrossProcessCompletion(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	options := p.options
	options.PersistLogins = true
	first, _ := New(options)
	second, _ := New(options)
	prepared, err := first.Prepare(budget(t), r)
	if err != nil {
		t.Fatal(err)
	}
	pending := pendingRecord(t, first, r)
	for key, record := range f.dumpStore(t, "") {
		if strings.Contains(record, pending.Verifier) != strings.HasPrefix(key, "ahp.oauth.pending:") {
			t.Fatalf("verifier placement in %q", key)
		}
	}
	credential, err := second.Complete(budget(t), r, callback(prepared.Login, "code"))
	if err != nil || credential.Token == "" {
		t.Fatalf("other process could not complete the persisted login: %v", err)
	}
	_, err = first.Complete(budget(t), r, callback(prepared.Login, "code"))
	assertCode(t, err, auth.CodeInteractionRequired)
	if f.tokenCalls.Load() != 1 || strings.Contains(strings.Join(slices.Collect(maps.Values(f.dumpStore(t, ""))), ""), pending.Verifier) {
		t.Fatal("completed login exchanged twice or kept its verifier")
	}
	if cached, err := first.Credential(budget(t), r); err != nil || cached.Token != credential.Token {
		t.Fatal("creating process did not see the completed grant")
	}
}

// Concurrent prepares create independent logins; each callback completes
// only its own login and leaves the others pending.
func TestPendingLoginsConcurrentPerState(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	a, err := p.Prepare(budget(t), r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Prepare(budget(t), r)
	if err != nil || a.Login.AuthorizationURL() == b.Login.AuthorizationURL() {
		t.Fatalf("second prepare did not create its own login: %v", err)
	}
	if _, err := p.Complete(budget(t), r, callback(b.Login, "b")); err != nil {
		t.Fatal(err)
	}
	_, err = p.Complete(budget(t), r, callback(b.Login, "b"))
	assertCode(t, err, auth.CodeInteractionRequired)
	if _, err := p.Complete(budget(t), r, callback(a.Login, "a")); err != nil {
		t.Fatalf("completing one login ended another: %v", err)
	}
	f.grantsMu.Lock()
	defer f.grantsMu.Unlock()
	if len(f.grants) != 2 || f.grants[0].Get("code") != "b" || f.grants[1].Get("code") != "a" || f.grants[0].Get("code_verifier") == f.grants[1].Get("code_verifier") {
		t.Fatal("logins shared a verifier or exchanged the wrong code")
	}
}

// Each login keeps its creating caller's ceiling: completion records scopes
// bounded by it, and each caller's ceiling filters them at use.
func TestPendingLoginKeepsCreatingCeiling(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	original := p.options.SelectClient
	ceiling := []string{"events", "admin"}
	p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		c, err := original(ctx, r, issuers, resource)
		c.AllowedScopes = ceiling
		return c, err
	}
	broad, err := p.Prepare(budget(t), r, "admin")
	if err != nil {
		t.Fatal(err)
	}
	ceiling = []string{"events"}
	narrow, err := p.Prepare(budget(t), r)
	if err != nil || slices.Contains(loginScopes(narrow.Login), "admin") {
		t.Fatalf("narrower caller's login: %v", err)
	}
	f.mode.Store("admin-scope")
	credential, err := p.Complete(budget(t), r, callback(broad.Login, "code"))
	if err != nil {
		t.Fatal(err)
	}
	record, _ := f.store.Load(budget(t), credential.Attempt.(attempted).key)
	if !sameScopes(record.Scopes, []string{"events", "admin"}) {
		t.Fatalf("completion not bounded by the creating ceiling: %v", record.Scopes)
	}
	_, err = p.Prepare(budget(t), r, "admin")
	assertCode(t, err, auth.CodeAccessDenied)
}

// Pending logins are capped per grant key, per process or per store when
// persisted; the oldest is cancelled and expired ones are deleted.
func TestPendingLoginsCappedPerGrantKey(t *testing.T) {
	for _, persisted := range []bool{false, true} {
		t.Run(map[bool]string{false: "process", true: "store"}[persisted], func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			options := p.options
			options.PersistLogins, options.MaxPendingLogins = persisted, 2
			providers := []*Provider{}
			for range 2 {
				provider, err := New(options)
				if err != nil {
					t.Fatal(err)
				}
				providers = append(providers, provider)
			}
			// Persisted logins share one cap across processes.
			creators := []*Provider{providers[0], providers[0], providers[0]}
			if persisted {
				creators = []*Provider{providers[0], providers[1], providers[0]}
			}
			var logins []*PendingLogin
			for _, creator := range creators {
				prepared, err := creator.Prepare(budget(t), r)
				if err != nil {
					t.Fatal(err)
				}
				logins = append(logins, prepared.Login)
			}
			_, err := creators[0].Complete(budget(t), r, callback(logins[0], "oldest"))
			assertCode(t, err, auth.CodeInteractionRequired)
			if f.tokenCalls.Load() != 0 {
				t.Fatal("cancelled login exchanged a code")
			}
			completer := providers[0]
			if persisted {
				completer = providers[1]
			}
			for _, login := range logins[1:] {
				if _, err := completer.Complete(budget(t), r, callback(login, "code")); err != nil {
					t.Fatalf("login within the cap: %v", err)
				}
			}
		})
	}
	// The default cap is 5, and expired logins are deleted.
	_, p, r := setup(t, "authorization_code_pkce")
	if p.options.MaxPendingLogins != 5 {
		t.Fatalf("default cap %d", p.options.MaxPendingLogins)
	}
	p.options.LoginLifetime = 50 * time.Millisecond
	for range 3 {
		if _, err := p.Prepare(budget(t), r); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	p.options.LoginLifetime = time.Minute
	if _, err := p.Prepare(budget(t), r); err != nil {
		t.Fatal(err)
	}
	config, _, _, _ := p.cachedBinding(budget(t), r)
	if record, _ := p.logins.Load(budget(t), pendingKey(p.key(r, config))); record == nil || len(record.Pending) != 1 {
		t.Fatal("expired logins were not deleted")
	}
	if _, err := New(Options{Namespace: "n", Store: newStore(), HTTPClient: p.options.HTTPClient, CheckDestination: p.options.CheckDestination, SelectClient: p.options.SelectClient, ValidateToken: p.options.ValidateToken, MaxPendingLogins: -1}); err == nil {
		t.Fatal("negative cap accepted")
	}
}

// Each completion replaces the grant, so the newest completed login wins.
func TestPendingCompletionNewestGrantWins(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	allowAdmin(p)
	older, err := p.Prepare(budget(t), r, "admin")
	if err != nil {
		t.Fatal(err)
	}
	newer, err := p.Prepare(budget(t), r)
	if err != nil {
		t.Fatal(err)
	}
	f.mode.Store("admin-scope")
	first, err := p.Complete(budget(t), r, callback(older.Login, "older"))
	if err != nil {
		t.Fatal(err)
	}
	f.mode.Store("ok")
	if _, err := p.Complete(budget(t), r, callback(newer.Login, "newer")); err != nil {
		t.Fatal(err)
	}
	// The newer login requested the previously granted scopes, so it kept them.
	if !slices.Contains(loginScopes(newer.Login), "events") {
		t.Fatal("login did not request the grant's scopes")
	}
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if record == nil || !sameScopes(record.Scopes, []string{"events"}) {
		t.Fatalf("newest completion did not replace the grant: %+v", record)
	}
}

// A host binds a fresh loopback port per login; the callback and code
// exchange use that login's exact redirect.
func TestPendingLoginEphemeralRedirect(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	var logins []*PendingLogin
	for _, redirect := range []string{"http://127.0.0.1:50001/callback", "http://127.0.0.1:50002/callback"} {
		prepared, err := p.PrepareWith(budget(t), r, PrepareOptions{RedirectURI: redirect})
		if err != nil {
			t.Fatal(err)
		}
		logins = append(logins, prepared.Login)
	}
	u, _ := url.Parse(logins[1].AuthorizationURL())
	query := url.Values{"state": {u.Query().Get("state")}, "code": {"code"}}.Encode()
	_, err := p.Complete(budget(t), r, "http://127.0.0.1:50001/callback?"+query)
	assertCode(t, err, auth.CodeAccessDenied)
	if _, err := p.Complete(budget(t), r, "http://127.0.0.1:50002/callback?"+query); err != nil {
		t.Fatal(err)
	}
	f.grantsMu.Lock()
	defer f.grantsMu.Unlock()
	if f.grants[0].Get("redirect_uri") != "http://127.0.0.1:50002/callback" {
		t.Fatalf("exchange redirect %q", f.grants[0].Get("redirect_uri"))
	}
	for _, invalid := range []string{"http://localhost:50003/callback", "http://192.0.2.1:50003/callback"} {
		_, err := p.PrepareWith(budget(t), r, PrepareOptions{RedirectURI: invalid})
		assertCode(t, err, auth.CodeInvalidConfiguration)
	}
}

// With PersistLogins, a host Prepare sweeps the grant's expired logins and
// their verifiers, even when it serves a cached credential.
func TestPersistedExpiredLoginsSweptOnPrepare(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	allowAdmin(p)
	p.options.PersistLogins, p.logins = true, f.store
	finishLogin(t, p, r)
	p.options.LoginLifetime = 50 * time.Millisecond
	stepUp, err := p.Prepare(budget(t), r, "admin")
	if err != nil || stepUp.Login == nil {
		t.Fatal(err)
	}
	verifier := pendingRecord(t, p, r).Verifier
	time.Sleep(100 * time.Millisecond)
	cached, err := p.Prepare(budget(t), r)
	if err != nil || cached.Credential == nil {
		t.Fatal(err)
	}
	for key, record := range f.dumpStore(t, "") {
		if strings.Contains(record, verifier) {
			t.Fatalf("expired verifier kept at %q", key)
		}
	}
}
