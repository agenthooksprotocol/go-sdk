package oauth

// Section 7 of the scope decision contract: entry-point routing (including
// the transport), the generation race, the pre-required-set upgrade and host
// failure stripping. The shared decision table runs in scope_vectors_test.go.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

// traced records the operations p decides for.
func traced(p *Provider) func() []operation {
	var mu sync.Mutex
	var ops []operation
	p.trace = func(op operation, _ decision) {
		mu.Lock()
		defer mu.Unlock()
		ops = append(ops, op)
	}
	return func() []operation {
		mu.Lock()
		defer mu.Unlock()
		return append([]operation(nil), ops...)
	}
}

const intercept = `{"jsonrpc":"2.0","id":1,"method":"hooks/intercept"}`

func deliver(t *testing.T, f *fixture, p *Provider, r auth.Request, body string) (*http.Response, error) {
	t.Helper()
	request, err := http.NewRequestWithContext(budget(t), http.MethodPost, r.Destination, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := auth.Do(f.server.Client(), request, r, auth.Route(auth.Routes{OAuth: p}))
	if response != nil {
		response.Body.Close()
	}
	return response, err
}

// Every entry point, and the transport, yields decide's outcome: here a host
// requirement outside the ceiling, refused before any network request.
func TestDecideEntryPointRouting(t *testing.T) {
	for _, flow := range []string{pkceFlow, "client_credentials"} {
		t.Run(flow, func(t *testing.T) {
			f, p, r := setup(t, flow)
			var first auth.Credential
			if flow == pkceFlow {
				first = finishLogin(t, p, r)
			} else {
				var err error
				if first, err = p.Credential(budget(t), r); err != nil {
					t.Fatal(err)
				}
			}
			configure(p, func(c *ClientConfig) { c.RequiredScopes = []string{"admin"} })
			unbound := r
			unbound.Binding = nil
			entries := []struct {
				name string
				op   operation
				run  func() error
			}{
				{"Credential", opCredential, func() error { _, err := p.Credential(budget(t), r); return err }},
				{"Prepare", opPrepare, func() error { _, err := p.Prepare(budget(t), r); return err }},
				{"PrepareWith ForceRegistration", opPrepare, func() error {
					_, err := p.PrepareWith(budget(t), r, PrepareOptions{ForceRegistration: true})
					return err
				}},
				{"Challenge 401", opChallenge, func() error {
					_, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{}, Attempt: first.Attempt})
					return err
				}},
				{"Challenge 403", opChallenge, func() error { _, err := p.Challenge(budget(t), r, stepUp("events", first.Attempt)); return err }},
				{"PreemptiveCredential", opPreemptive, func() error { _, err := p.PreemptiveCredential(budget(t), unbound); return err }},
				{"transport", opCredential, func() error { _, err := deliver(t, f, p, r, intercept); return err }},
				{"transport unbound", opPreemptive, func() error { _, err := deliver(t, f, p, unbound, intercept); return err }},
			}
			for _, entry := range entries {
				t.Run(entry.name, func(t *testing.T) {
					ops := traced(p)
					before := network(f)
					err := entry.run()
					want := []string{"admin"}
					if entry.name == "Challenge 403" {
						want = []string{"admin", "events"}
					}
					contractError(t, err, auth.CodeAccessDenied, want...)
					if got := ops(); len(got) == 0 || got[0] != entry.op {
						t.Fatalf("decisions = %v; want %v", got, entry.op)
					}
					if n := network(f) - before; n != 0 {
						t.Fatalf("%d network calls before the refusal", n)
					}
				})
			}
		})
	}
}

// The transport hands challenges to the provider, which decides them.
func TestDecideTransportChallenges(t *testing.T) {
	t.Run("malformed scope 403", func(t *testing.T) {
		f, p, r := setup(t, pkceFlow)
		finishLogin(t, p, r)
		f.onEvents = func(w http.ResponseWriter, _ *http.Request) bool {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope=""`)
			w.WriteHeader(403)
			return true
		}
		ops := traced(p)
		_, err := deliver(t, f, p, r, intercept)
		contractError(t, err, auth.CodeAccessDenied)
		if got := ops(); len(got) != 2 || got[1] != opChallenge {
			t.Fatalf("decisions = %v", got)
		}
	})
	for _, header := range []string{`Bearer error="invalid_token"`, `Bearer error="insufficient_scope", Bearer error="insufficient_scope"`, `Bearer error="insufficient_scope", scope="`} {
		t.Run("other 403 "+header, func(t *testing.T) {
			// Not exactly one parseable Bearer insufficient_scope challenge:
			// returned as is, without the provider or a retry.
			f, p, r := setup(t, pkceFlow)
			finishLogin(t, p, r)
			f.onEvents = func(w http.ResponseWriter, _ *http.Request) bool {
				w.Header().Set("WWW-Authenticate", header)
				w.WriteHeader(403)
				return true
			}
			ops := traced(p)
			response, err := deliver(t, f, p, r, intercept)
			if err != nil || response.StatusCode != 403 || f.eventCalls.Load() != 1 {
				t.Fatalf("403 retried or failed: %v", err)
			}
			if got := ops(); len(got) != 1 || got[0] != opCredential {
				t.Fatalf("decisions = %v", got)
			}
		})
	}
	t.Run("401 with insufficient_scope", func(t *testing.T) {
		f, p, r := setup(t, pkceFlow)
		allowAdmin(p)
		finishLogin(t, p, r)
		var calls int
		f.onEvents = func(w http.ResponseWriter, _ *http.Request) bool {
			if calls++; calls > 1 {
				return false
			}
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="admin"`)
			w.WriteHeader(401)
			return true
		}
		// A 401 is never a step-up requirement: the token is renewed and replayed.
		response, err := deliver(t, f, p, r, intercept)
		if err != nil || response.StatusCode != 200 || f.refreshCalls.Load() != 1 {
			t.Fatalf("401 scope treated as a requirement: %v", err)
		}
	})
	t.Run("replay rejection", func(t *testing.T) {
		f, p, r := setup(t, pkceFlow)
		first := finishLogin(t, p, r)
		f.onEvents = func(w http.ResponseWriter, _ *http.Request) bool {
			w.WriteHeader(401)
			return true
		}
		ops := traced(p)
		response, err := deliver(t, f, p, r, intercept)
		if err != nil || response.StatusCode != 401 {
			t.Fatalf("replay rejection: %v", err)
		}
		// Both the first and the replayed token go to the provider: each is
		// retired and renewed (one refresh each), and the replayed generation
		// is no longer current.
		if got := ops(); len(got) == 0 || got[len(got)-1] != opChallenge {
			t.Fatalf("decisions = %v", got)
		}
		record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
		if f.eventCalls.Load() != 2 || f.refreshCalls.Load() != 2 || record.Generation == first.Attempt.(attempted).generation {
			t.Fatalf("events = %d, refreshes = %d", f.eventCalls.Load(), f.refreshCalls.Load())
		}
	})
}

// Step 5: a 403 for a generation that is no longer current serves the newer
// grant; for the current generation it is refused.
func TestDecideNewerGenerationRace(t *testing.T) {
	f, p, r := setup(t, pkceFlow)
	allowAdmin(p)
	f.mode.Store("admin-scope")
	first := finishLogin(t, p, r, "admin")
	key := first.Attempt.(attempted).key
	// Another caller rotated the grant after the rejected request was sent.
	record, _ := f.store.Load(budget(t), key)
	newer := cloneRecord(record)
	newer.AccessToken, newer.Generation = "newer-access", randomID()
	if ok, err := f.store.CompareAndSwap(budget(t), key, record.Generation, newer); !ok || err != nil {
		t.Fatal(err)
	}
	before := network(f)
	served, err := p.Challenge(budget(t), r, stepUp("admin", first.Attempt))
	if err != nil || served == nil || served.Token != "newer-access" || network(f) != before {
		t.Fatalf("newer generation not served: %v", err)
	}
	_, err = p.Challenge(budget(t), r, stepUp("admin", served.Attempt))
	contractError(t, err, auth.CodeAccessDenied, "admin")
	// An anonymous request (no token sent) is refused too.
	unbound := r
	unbound.Binding = nil
	_, err = p.Challenge(budget(t), unbound, stepUp("admin", nil))
	contractError(t, err, auth.CodeAccessDenied, "admin")
}

// A pending record from an older release has no stored required set:
// completion requires the current host RequiredScopes.
func TestCompleteUpgradeWithoutStoredRequired(t *testing.T) {
	for _, required := range [][]string{nil, {"admin"}} {
		t.Run(fmt.Sprint(required), func(t *testing.T) {
			f, p, r := setup(t, pkceFlow)
			allowAdmin(p)
			prepared, err := p.Prepare(budget(t), r, "admin")
			if err != nil || prepared.Login == nil {
				t.Fatal(err)
			}
			logins := p.logins.(*processLogins)
			logins.mu.Lock()
			for _, record := range logins.values {
				for i := range record.Pending {
					record.Pending[i].Required, record.Pending[i].HasRequired = nil, false
				}
			}
			logins.mu.Unlock()
			configure(p, func(c *ClientConfig) { c.RequiredScopes = required })
			// The server grants events only.
			_, err = p.Complete(budget(t), r, callback(prepared.Login, "code"))
			if required == nil {
				if err != nil {
					t.Fatalf("legacy login without requirements refused: %v", err)
				}
				return
			}
			contractError(t, err, auth.CodeAccessDenied, "admin")
			if network(f) == 0 {
				t.Fatal("no exchange")
			}
		})
	}
}

// Host store, network, callback and client-source failures carry no scopes.
func TestDecideHostFailuresCarryNoScopes(t *testing.T) {
	hostErr := &auth.Error{Code: auth.CodeAccessDenied, Scopes: []string{"host-scope"}}
	t.Run("store", func(t *testing.T) {
		f, p, r := setup(t, "client_credentials")
		p.options.Store = failingLoadStore{Store: f.store, err: hostErr}
		_, err := p.Credential(budget(t), r)
		contractError(t, err, auth.CodeAccessDenied)
	})
	t.Run("network", func(t *testing.T) {
		f, p, r := setup(t, "client_credentials")
		configure(p, func(c *ClientConfig) { c.RequiredScopes = []string{"events"} })
		f.mode.Store("temporary")
		_, err := p.Credential(budget(t), r)
		contractError(t, err, auth.CodeProviderFailed)
	})
	t.Run("client selection on complete", func(t *testing.T) {
		_, p, r := setup(t, pkceFlow)
		prepared, err := p.Prepare(budget(t), r)
		if err != nil {
			t.Fatal(err)
		}
		selectClient := p.options.SelectClient
		selections := 0
		p.options.SelectClient = func(context.Context, auth.Request, []string, string) (ClientConfig, error) {
			selections++
			return ClientConfig{}, hostErr
		}
		// An unknown state is decided before any host callback.
		_, err = p.Complete(budget(t), r, "https://client.example/callback?state=unknown&code=code")
		if ended := contractError(t, err, auth.CodeInteractionRequired).LoginEnded; ended == nil || !*ended || selections != 0 {
			t.Fatal("unknown state reached client selection")
		}
		_, err = p.Complete(budget(t), r, callback(prepared.Login, "code"))
		if ended := contractError(t, err, auth.CodeAccessDenied).LoginEnded; ended == nil || *ended {
			t.Fatal("host failure ended the login")
		}
		p.options.SelectClient = selectClient
		if _, err := p.Complete(budget(t), r, callback(prepared.Login, "code")); err != nil {
			t.Fatalf("login not pending after the host failure: %v", err)
		}
	})
	t.Run("client source no longer permitted", func(t *testing.T) {
		_, p, r := setup(t, pkceFlow)
		prepared, err := p.Prepare(budget(t), r)
		if err != nil {
			t.Fatal(err)
		}
		configure(p, func(c *ClientConfig) { c.GrantPartition = "moved" })
		_, err = p.Complete(budget(t), r, callback(prepared.Login, "code"))
		if ended := contractError(t, err, auth.CodeInvalidConfiguration).LoginEnded; ended == nil || *ended {
			t.Fatal("source refusal ended the login")
		}
	})
	t.Run("uncertain claim", func(t *testing.T) {
		f, p, r := setup(t, pkceFlow)
		p.options.PersistLogins = true
		p.logins = &failingSwapStore{Store: f.store}
		prepared, err := p.Prepare(budget(t), r)
		if err != nil {
			t.Fatal(err)
		}
		p.logins.(*failingSwapStore).fail = true
		_, err = p.Complete(budget(t), r, callback(prepared.Login, "code"))
		if ended := contractError(t, err, auth.CodeProviderFailed).LoginEnded; ended == nil || *ended {
			t.Fatal("a login still stored after a failed claim reported ended")
		}
	})
}

// failingSwapStore fails pending-login writes once fail is set.
type failingSwapStore struct {
	Store
	fail bool
}

func (s *failingSwapStore) CompareAndSwap(ctx context.Context, key, expected string, value *Record) (bool, error) {
	if s.fail {
		return false, errors.New("store unavailable")
	}
	return s.Store.CompareAndSwap(ctx, key, expected, value)
}

// Token-endpoint errors outside Complete never carry scopes or a scope code:
// a PKCE refresh invalid_grant is refresh_rejected, a client-credentials
// invalid_grant and unauthorized_client credential_unavailable, a
// pre-registered client's invalid_client credential_unavailable, and
// everything else provider_failed.
func TestDecideTokenEndpointErrorsOutsideComplete(t *testing.T) {
	cases := []struct {
		name, mode, body string
		pkce, machine    auth.Code
	}{
		{"invalid_grant", "", `400 {"error":"invalid_grant"}`, auth.CodeRefreshRejected, auth.CodeCredentialUnavailable},
		{"unauthorized_client", "", `400 {"error":"unauthorized_client"}`, auth.CodeCredentialUnavailable, auth.CodeCredentialUnavailable},
		{"invalid_client", "", `401 {"error":"invalid_client"}`, auth.CodeCredentialUnavailable, auth.CodeCredentialUnavailable},
		{"access_denied", "", `400 {"error":"access_denied"}`, auth.CodeProviderFailed, auth.CodeProviderFailed},
		{"invalid_scope", "", `400 {"error":"invalid_scope"}`, auth.CodeProviderFailed, auth.CodeProviderFailed},
		{"server_error", "", `500 {"error":"server_error"}`, auth.CodeProviderFailed, auth.CodeProviderFailed},
		{"invalid response", "", `{"access_token":"access-token","expires_in":3600}`, auth.CodeProviderFailed, auth.CodeProviderFailed},
		{"unreachable", "reset", "", auth.CodeProviderFailed, auth.CodeProviderFailed},
	}
	for _, tc := range cases {
		t.Run("refresh "+tc.name, func(t *testing.T) {
			f, p, r := setup(t, pkceFlow)
			first := finishLogin(t, p, r)
			expire(t, f, first)
			f.tokenBody.Store(tc.body)
			if tc.mode != "" {
				f.mode.Store(tc.mode)
			}
			_, err := p.Credential(budget(t), r)
			contractError(t, err, tc.pkce)
			if f.refreshCalls.Load() != 1 {
				t.Fatal("no refresh")
			}
		})
		t.Run("client credentials "+tc.name, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			f.tokenBody.Store(tc.body)
			if tc.mode != "" {
				f.mode.Store(tc.mode)
			}
			_, err := p.Credential(budget(t), r)
			contractError(t, err, tc.machine)
		})
	}
	for source, code := range map[string]auth.Code{sourcePreregistered: auth.CodeCredentialUnavailable, sourceCIMD: auth.CodeInvalidConfiguration, sourceDCR: auth.CodeInteractionRequired} {
		if err := clientError(source); auth.Classify(err).Code != code {
			t.Fatalf("invalid_client for %s = %v; want %s", source, err, code)
		}
	}
}

// An unusable resource_metadata hint in a well-formed 401 falls back to the
// default discovery locations instead of failing discovery.
func TestDecideUnusableHintFallsBack(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	r.Binding = nil
	credential, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer resource_metadata="http://insecure.example/prm"`}}})
	if err != nil || credential == nil || f.resourceCalls.Load() != 1 {
		t.Fatalf("unusable hint did not fall back: %v", err)
	}
}

// An unbound target's unparseable challenge falls back to the default
// discovery locations (one protected-resource fetch for client selection),
// then decide refuses it: access_denied, no scopes, no authorization-server
// request.
func TestDecideUnboundUnparseableChallenge(t *testing.T) {
	for _, header := range []string{`Bearer realm="unterminated`, `Bearer scope="a  b", resource_metadata="https://elsewhere.example/prm"`} {
		t.Run(header, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			r.Binding = nil
			_, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {header}}})
			contractError(t, err, auth.CodeAccessDenied)
			if f.resourceCalls.Load() > 1 || f.metadataCalls.Load() != f.resourceCalls.Load() || f.tokenCalls.Load() != 0 {
				t.Fatalf("network: %d resource, %d metadata, %d token", f.resourceCalls.Load(), f.metadataCalls.Load(), f.tokenCalls.Load())
			}
		})
	}
}

// Step 0: a 401 retires the sent generation before any other check,
// including the context-budget check.
func TestDecideChallengeRetiresBeforeBudget(t *testing.T) {
	f, p, r := setup(t, pkceFlow)
	first := finishLogin(t, p, r)
	before := network(f)
	_, err := p.Challenge(context.Background(), r, auth.Challenge{StatusCode: 401, Header: http.Header{}, Attempt: first.Attempt})
	contractError(t, err, auth.CodeInvalidConfiguration)
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if record.AccessToken != "" || record.Generation == first.Attempt.(attempted).generation {
		t.Fatal("a 401 without a deadline did not retire the rejected token")
	}
	if n := network(f) - before; n != 0 {
		t.Fatalf("network calls = %d", n)
	}
}
