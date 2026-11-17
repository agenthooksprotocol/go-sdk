package oauth

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

const ccFlow = "client_credentials"

func prepared(t *testing.T, p *Provider, r auth.Request) Preparation {
	t.Helper()
	result, err := p.Prepare(budget(t), r)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func unboundChallenge(t *testing.T, p *Provider, r auth.Request) (*auth.Credential, error) {
	t.Helper()
	return p.Challenge(budget(t), r, auth.Challenge{StatusCode: http.StatusUnauthorized, Header: http.Header{"Www-Authenticate": {`Bearer error="invalid_token"`}}})
}

func lookup(t *testing.T, p *Provider, r auth.Request) (*auth.Credential, error) {
	t.Helper()
	return p.PreemptiveCredential(budget(t), r)
}

func mustToken(t *testing.T, c *auth.Credential, err error, want string) *auth.Credential {
	t.Helper()
	if err != nil || c == nil || c.Token != want {
		t.Fatalf("credential = %+v, %v; want %s", c, err, want)
	}
	return c
}

func TestPreregisteredClientReplacesRegistration(t *testing.T) {
	f := dcrSetup(t, ccFlow)
	p, r := f.provider(), f.request("backend")
	first := prepared(t, p, r).Credential
	mustToken(t, first, nil, "access-dcr-1")
	f.set(func(f *dcrFixture) { f.config.ClientID, f.config.ClientSecret = "client", "test-secret" })
	second := prepared(t, p, r).Credential
	mustToken(t, second, nil, "access-client")
	if second.Attempt.(attempted).key == first.Attempt.(attempted).key || f.lastTokenClient() != "client" || f.registerCalls.Load() != 1 {
		t.Fatal("pre-registered client did not select a new grant")
	}
}

func TestCIMDClientLifecycle(t *testing.T) {
	f := dcrSetup(t, pkceFlow)
	document := f.server.URL + "/client.json"
	f.set(func(f *dcrFixture) {
		f.metadata["client_id_metadata_document_supported"] = true
		f.config.ClientIDMetadataDocument = &MetadataDocument{URL: document, RedirectURIs: []string{"https://other.example/cb", f.config.RedirectURI}}
	})
	p, r := f.provider(), f.request("backend")
	login := prepared(t, p, r).Login
	if loginClientID(t, login) != document {
		t.Fatal("CIMD URL is not the client_id")
	}
	credential, err := f.complete(t, p, r, login)
	if err != nil {
		t.Fatal(err)
	}
	form := f.tokens[len(f.tokens)-1]
	if form.Get("client_id") != document || form.Get("client_secret") != "" || f.registerCalls.Load() != 0 || f.registration(t, f.config) != nil || f.documentCalls.Load() != 0 {
		t.Fatalf("CIMD exchange %v", form)
	}
	// invalid_client for a CIMD client is configuration, never a DCR fallback.
	f.set(func(f *dcrFixture) { f.rejected[document] = true })
	expireGrant(t, f, &credential)
	_, err = p.Prepare(budget(t), r)
	assertCode(t, err, auth.CodeInvalidConfiguration)
	if f.registerCalls.Load() != 0 || f.documentCalls.Load() != 0 {
		t.Fatal("CIMD invalid_client fell back to registration")
	}
}

func TestRegistrationEndpointDestinationPolicy(t *testing.T) {
	f := dcrSetup(t, pkceFlow)
	p := f.provider(func(o *Options) {
		check := o.CheckDestination
		o.CheckDestination = func(ctx context.Context, raw string, purpose Purpose) error {
			if purpose == Registration {
				return fmt.Errorf("secret-refused")
			}
			return check(ctx, raw, purpose)
		}
	})
	_, err := p.Prepare(budget(t), f.request("backend"))
	assertCode(t, err, auth.CodeUntrustedDestination)
	if f.registerCalls.Load() != 0 {
		t.Fatal("refused registration endpoint contacted")
	}
	// A redirect is never followed, even back to the registration endpoint.
	f.set(func(f *dcrFixture) {
		f.respond = respondStatus(307, map[string]string{"Location": f.server.URL + "/register"}, "")
	})
	_, err = f.provider().Prepare(budget(t), f.request("backend"))
	assertCode(t, err, auth.CodeUntrustedDestination)
	if f.registerCalls.Load() != 1 {
		t.Fatalf("redirect followed: %d", f.registerCalls.Load())
	}
}

// Only host Prepare registers a PKCE client; client credentials also register
// on challenge handling and the up-front lookup.
func TestRegistrationOnlyWherePermitted(t *testing.T) {
	t.Run("pkce", func(t *testing.T) {
		f := dcrSetup(t, pkceFlow)
		p, r := f.provider(), f.request("backend")
		_, err := unboundChallenge(t, p, r)
		assertCode(t, err, auth.CodeInteractionRequired)
		_, err = lookup(t, p, r)
		assertCode(t, err, auth.CodeInteractionRequired)
		if _, err := p.Credential(budget(t), r); err == nil {
			t.Fatal("delivery acquired without consent")
		}
		if f.registerCalls.Load() != 0 || anyPending(f.store) {
			t.Fatal("delivery path registered a PKCE client or created a login")
		}
		credential, err := f.complete(t, p, r, prepared(t, p, r).Login)
		if err != nil || f.registerCalls.Load() != 1 {
			t.Fatalf("prepare registration: %v", err)
		}
		f.editRegistration(t, func(record *Record) { record.Registration = nil })
		expireGrant(t, f, &credential)
		_, err = lookup(t, p, r)
		assertCode(t, err, auth.CodeInteractionRequired)
		if f.registerCalls.Load() != 1 {
			t.Fatal("lookup registered a PKCE client")
		}
	})
	t.Run("client-credentials", func(t *testing.T) {
		f := dcrSetup(t, ccFlow)
		p, r := f.provider(), f.request("backend")
		credential, err := unboundChallenge(t, p, r)
		mustToken(t, credential, err, "access-dcr-1")
		f.editRegistration(t, func(record *Record) { record.Registration.SecretExpiresAt = time.Now().Add(-time.Second) })
		expireGrant(t, f, credential)
		before := len(f.tokenClients)
		credential, err = lookup(t, p, r)
		mustToken(t, credential, err, "access-dcr-2")
		if f.registerCalls.Load() != 2 || slices.Contains(f.tokenClients[before:], "dcr-1") {
			t.Fatalf("lookup did not re-register before the token request: %v", f.tokenClients[before:])
		}
	})
}

// looseStore loses registration coordination, as when a lease lapses: only
// the generation compare-and-swap fences concurrent registrations.
type looseStore struct{ *memoryStore }

func (s looseStore) Coordinate(ctx context.Context, key string, work func(context.Context) error) error {
	if strings.HasPrefix(key, "ahp.oauth.registration:") {
		return work(ctx)
	}
	return s.memoryStore.Coordinate(ctx, key, work)
}

func TestRegistersOnceAcrossProcesses(t *testing.T) {
	t.Run("coordinated", func(t *testing.T) {
		f := dcrSetup(t, ccFlow)
		processes := []*Provider{f.provider(), f.provider()}
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := processes[i%2].Prepare(budget(t), f.request("backend")); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if f.registerCalls.Load() != 1 || f.secrets.count() != 1 {
			t.Fatalf("registrations=%d secrets=%d", f.registerCalls.Load(), f.secrets.count())
		}
	})
	t.Run("compare-and-set-loser", func(t *testing.T) {
		f := dcrSetup(t, ccFlow)
		arrived, release := make(chan struct{}, 2), make(chan struct{})
		f.set(func(f *dcrFixture) {
			f.respond = func(w http.ResponseWriter, n int) {
				arrived <- struct{}{}
				<-release
				id := fmt.Sprintf("dcr-%d", n)
				f.mu.Lock()
				f.issued[id] = "secret-issued-" + id
				f.mu.Unlock()
				w.WriteHeader(201)
				fmt.Fprintf(w, `{"client_id":%q,"client_secret":%q}`, id, "secret-issued-"+id)
			}
		})
		loose := func(o *Options) { o.Store = looseStore{f.store} }
		processes := []*Provider{f.provider(loose), f.provider(loose)}
		credentials := make([]*auth.Credential, 2)
		var wg sync.WaitGroup
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				prepared, err := processes[i].Prepare(budget(t), f.request("backend"))
				if err != nil {
					t.Error(err)
					return
				}
				credentials[i] = prepared.Credential
			}()
		}
		<-arrived
		<-arrived
		close(release)
		wg.Wait()
		record := f.registration(t, f.config)
		if f.registerCalls.Load() != 2 || f.secrets.count() != 1 || len(f.secrets.deleted) != 1 || record.Registration == nil {
			t.Fatalf("secrets=%d deleted=%v", f.secrets.count(), f.secrets.deleted)
		}
		winner := "access-" + record.Registration.ClientID
		for _, c := range credentials {
			mustToken(t, c, nil, winner)
		}
	})
}

func TestRegistrationReusedAcrossGrants(t *testing.T) {
	f := dcrSetup(t, ccFlow)
	p := f.provider()
	a, b := prepared(t, p, f.request("backend-a")).Credential, prepared(t, p, f.request("backend-b")).Credential
	mustToken(t, a, nil, "access-dcr-1")
	mustToken(t, b, nil, "access-dcr-1")
	if f.registerCalls.Load() != 1 || a.Attempt.(attempted).key == b.Attempt.(attempted).key {
		t.Fatal("registration not shared by independent grants")
	}
}

func TestUnusableRegistrationReregisters(t *testing.T) {
	f := dcrSetup(t, ccFlow)
	p, r := f.provider(), f.request("backend")
	credential := prepared(t, p, r).Credential
	first := f.registration(t, f.config).Registration.SecretRef
	// An expired secret is replaced and its reference deleted.
	f.editRegistration(t, func(record *Record) { record.Registration.SecretExpiresAt = time.Now().Add(-time.Minute) })
	expireGrant(t, f, credential)
	credential, err := lookup(t, p, r)
	mustToken(t, credential, err, "access-dcr-2")
	if !slices.Equal(f.secrets.deleted, []string{first}) {
		t.Fatalf("deleted %v; want old reference", f.secrets.deleted)
	}
	// An unresolvable secret makes the record unusable too.
	f.secrets.Delete(budget(t), f.registration(t, f.config).Registration.SecretRef)
	expireGrant(t, f, credential)
	c, err := p.Credential(budget(t), r)
	if err != nil || c.Token != "access-dcr-3" || f.registerCalls.Load() != 3 {
		t.Fatalf("unresolvable secret: %v %d", err, f.registerCalls.Load())
	}
}

func TestInvalidClientReregistersOnce(t *testing.T) {
	t.Run("client-credentials", func(t *testing.T) {
		f := dcrSetup(t, ccFlow)
		p, r := f.provider(), f.request("backend")
		old := prepared(t, p, r).Credential
		f.set(func(f *dcrFixture) { f.rejected["dcr-1"] = true })
		expireGrant(t, f, old)
		metadata := f.metadataCalls.Load()
		credential, err := lookup(t, p, r)
		mustToken(t, credential, err, "access-dcr-2")
		if f.registerCalls.Load() != 2 || f.metadataCalls.Load() != metadata || credential.Attempt.(attempted).key == old.Attempt.(attempted).key {
			t.Fatal("invalid_client did not re-register once with a new grant")
		}
		credential, err = lookup(t, p, r)
		mustToken(t, credential, err, "access-dcr-2")
		// A replacement also rejected backs off with credential_unavailable.
		f.set(func(f *dcrFixture) { f.rejected["dcr-2"], f.rejected["dcr-3"] = true, true })
		expireGrant(t, f, credential)
		_, err = p.Credential(budget(t), r)
		assertCode(t, err, auth.CodeCredentialUnavailable)
		record := f.registration(t, f.config)
		if f.registerCalls.Load() != 3 || record.Registration != nil || record.RegistrationFailure == nil || record.RegistrationFailure.Attempts != 1 {
			t.Fatalf("repeated invalid_client: calls=%d record=%+v", f.registerCalls.Load(), record)
		}
		_, err = p.Credential(budget(t), r)
		assertCode(t, err, auth.CodeCredentialUnavailable)
		if f.registerCalls.Load() != 3 {
			t.Fatal("marker did not bound re-registration")
		}
	})
	t.Run("pkce", func(t *testing.T) {
		f := dcrSetup(t, pkceFlow)
		p, r := f.provider(), f.request("backend")
		credential, err := f.complete(t, p, r, prepared(t, p, r).Login)
		if err != nil {
			t.Fatal(err)
		}
		f.set(func(f *dcrFixture) { f.rejected["dcr-1"] = true })
		expireGrant(t, f, &credential)
		_, err = p.Credential(budget(t), r)
		assertCode(t, err, auth.CodeInteractionRequired)
		if f.registerCalls.Load() != 1 || f.registration(t, f.config).Registration != nil {
			t.Fatal("PKCE invalid_client must delete the registration without registering")
		}
		if loginClientID(t, prepared(t, p, r).Login) != "dcr-2" || f.registerCalls.Load() != 2 {
			t.Fatal("next prepare did not register anew")
		}
	})
}

func TestRegisteredSecretOnlyInSecretStore(t *testing.T) {
	for _, flow := range []string{ccFlow, pkceFlow} {
		f := dcrSetup(t, flow)
		p, r := f.provider(), f.request("backend")
		prepared(t, p, r)
		if strings.Contains(f.dump(t), "secret-") {
			t.Fatalf("%s: a secret reached the store", flow)
		}
		if flow == ccFlow {
			ref := f.registration(t, f.config).Registration.SecretRef
			if secret, _ := f.secrets.Resolve(budget(t), ref); secret != "secret-issued-1" {
				t.Fatal("secret not written through the hook")
			}
			f.set(func(f *dcrFixture) { f.rejected["dcr-1"], f.rejected["dcr-2"] = true, true })
			expireGrant(t, f, mustToken(t, prepared(t, p, r).Credential, nil, "access-dcr-1"))
			_, err := p.Credential(budget(t), r)
			assertCode(t, err, auth.CodeCredentialUnavailable)
		} else if f.secrets.count() != 0 {
			t.Fatal("public client stored a secret")
		}
	}
}

func TestNoSecretStoreNoConfidentialRegistration(t *testing.T) {
	without := func(o *Options) { o.Secrets = nil }
	f := dcrSetup(t, ccFlow)
	_, err := f.provider(without).Prepare(budget(t), f.request("backend"))
	assertCode(t, err, auth.CodeCredentialUnavailable)
	if f.registerCalls.Load() != 0 {
		t.Fatal("confidential registration without a secret store")
	}
	f = dcrSetup(t, pkceFlow)
	if loginClientID(t, prepared(t, f.provider(without), f.request("backend")).Login) != "dcr-1" {
		t.Fatal("PKCE registration needs no secret store")
	}
}

func TestRecordedSelectionSurvivesMetadataChange(t *testing.T) {
	f := dcrSetup(t, pkceFlow)
	p, r := f.provider(), f.request("backend")
	credential, err := f.complete(t, p, r, prepared(t, p, r).Login)
	if err != nil {
		t.Fatal(err)
	}
	f.set(func(f *dcrFixture) {
		f.metadata["client_id_metadata_document_supported"] = true
		f.metadata["registration_endpoint"] = nil
		f.config.ClientIDMetadataDocument = &MetadataDocument{URL: f.server.URL + "/client.json", RedirectURIs: []string{f.config.RedirectURI}}
	})
	expireGrant(t, f, &credential)
	if result := prepared(t, p, r); result.Credential == nil || f.lastTokenClient() != "dcr-1" || f.registerCalls.Load() != 1 {
		t.Fatal("metadata change moved a working DCR grant")
	}
	// Removing the DCR permission (host policy) does move it, to CIMD.
	f.set(func(f *dcrFixture) { f.config.Registration = nil })
	if loginClientID(t, prepared(t, p, r).Login) != f.server.URL+"/client.json" {
		t.Fatal("removed DCR permission kept the recorded client")
	}
}

func TestInitialAccessTokenScopedToIssuer(t *testing.T) {
	a, b := dcrSetup(t, ccFlow), dcrSetup(t, ccFlow)
	a.secrets.Store(budget(t), "iat-ref", "initial-access-token")
	a.set(func(f *dcrFixture) { f.config.Registration.InitialAccessTokenRef = "iat-ref" })
	p := a.provider(func(o *Options) {
		o.CheckDestination = func(ctx context.Context, raw string, _ Purpose) error {
			if !strings.HasPrefix(raw, a.server.URL) && !strings.HasPrefix(raw, b.server.URL) {
				return fmt.Errorf("refused")
			}
			return nil
		}
		o.SelectClient = func(ctx context.Context, r auth.Request, _ []string, _ string) (ClientConfig, error) {
			if r.Destination == b.resource {
				return cloneConfig(b.config), nil
			}
			return cloneConfig(a.config), nil
		}
	})
	prepared(t, p, a.request("backend"))
	prepared(t, p, b.request("backend"))
	if a.registrations[0].Authorization != "Bearer initial-access-token" || b.registrations[0].Authorization != "" {
		t.Fatalf("initial access token sent as %q / %q", a.registrations[0].Authorization, b.registrations[0].Authorization)
	}
	if strings.Contains(a.dump(t), "initial-access-token") {
		t.Fatal("initial access token persisted")
	}
}

func TestFailedMarkerBoundsRegistration(t *testing.T) {
	hijack := func(w http.ResponseWriter, _ int) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}
	for _, tc := range []struct {
		name    string
		respond func(http.ResponseWriter, int)
		code    auth.Code
	}{
		{"5xx", respondStatus(503, nil, ""), auth.CodeProviderFailed},
		{"408", respondStatus(408, nil, ""), auth.CodeProviderFailed},
		{"429", respondStatus(429, nil, ""), auth.CodeProviderFailed},
		{"401", respondStatus(401, nil, `{"error":"invalid_token"}`), auth.CodeCredentialUnavailable},
		{"403", respondStatus(403, nil, ""), auth.CodeCredentialUnavailable},
		{"network", hijack, auth.CodeProviderFailed},
		{"invalid-metadata", respondStatus(400, nil, `{"error":"invalid_client_metadata"}`), auth.CodeInvalidConfiguration},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := dcrSetup(t, ccFlow)
			f.set(func(f *dcrFixture) { f.respond = tc.respond })
			one, two, r := f.provider(), f.provider(), f.request("backend")
			_, err := one.Prepare(budget(t), r)
			assertCode(t, err, tc.code)
			marker := f.registration(t, f.config).RegistrationFailure
			if marker == nil || marker.Attempts != 1 || marker.NextAttempt.Sub(marker.FailedAt) != time.Minute {
				t.Fatalf("marker = %+v", marker)
			}
			// Lookups, deliveries and challenges in any process send nothing.
			_, err = lookup(t, one, r)
			assertCode(t, err, auth.CodeCredentialUnavailable)
			_, err = two.Credential(budget(t), r)
			assertCode(t, err, auth.CodeCredentialUnavailable)
			_, err = unboundChallenge(t, two, r)
			assertCode(t, err, auth.CodeCredentialUnavailable)
			if f.registerCalls.Load() != 1 {
				t.Fatalf("backoff not honoured: %d", f.registerCalls.Load())
			}
			// Host prepare clears the marker, so its failure restarts the backoff.
			_, err = two.Prepare(budget(t), r)
			assertCode(t, err, tc.code)
			marker = f.registration(t, f.config).RegistrationFailure
			if f.registerCalls.Load() != 2 || marker.Attempts != 1 || marker.NextAttempt.Sub(marker.FailedAt) != time.Minute {
				t.Fatalf("prepare attempt: %+v", marker)
			}
			// A changed request digest clears it for every path.
			f.set(func(f *dcrFixture) { f.config.Registration.ClientName = "Renamed" })
			lookup(t, one, r)
			if f.registerCalls.Load() != 3 || f.registration(t, f.config).RegistrationFailure.Attempts != 1 {
				t.Fatal("policy change did not clear the marker")
			}
			f.set(func(f *dcrFixture) { f.respond = nil })
			if _, err := two.Prepare(budget(t), r); err != nil || f.registration(t, f.config).RegistrationFailure != nil {
				t.Fatalf("success did not clear the marker: %v", err)
			}
		})
	}
}

func TestForcedReregistration(t *testing.T) {
	f := dcrSetup(t, ccFlow)
	p, r := f.provider(), f.request("backend")
	prepared(t, p, r)
	first := f.registration(t, f.config).Registration
	f.editRegistration(t, func(record *Record) {
		record.RegistrationFailure = &RegistrationFailure{RequestDigest: first.RequestDigest, Attempts: 3, NextAttempt: time.Now().Add(time.Hour)}
	})
	result, err := p.PrepareWith(budget(t), r, PrepareOptions{ForceRegistration: true})
	mustToken(t, result.Credential, err, "access-dcr-2")
	record := f.registration(t, f.config)
	if record.Registration.ClientID != "dcr-2" || record.RegistrationFailure != nil || !slices.Equal(f.secrets.deleted, []string{first.SecretRef}) {
		t.Fatalf("forced re-registration: %+v deleted=%v", record, f.secrets.deleted)
	}

	f = dcrSetup(t, pkceFlow)
	p, r = f.provider(), f.request("backend")
	prepared(t, p, r)
	if loginClientID(t, mustLogin(t, p, r, PrepareOptions{ForceRegistration: true})) != "dcr-2" {
		t.Fatal("forced PKCE re-registration")
	}
	// An abandoned (expired) login never triggers re-registration.
	config, _, _, _ := p.cachedBinding(budget(t), r)
	f.editKey(t, p.key(r, config), func(record *Record) { record.Pending.ExpiresAt = time.Now().Add(-time.Second) })
	if loginClientID(t, prepared(t, p, r).Login) != "dcr-2" || f.registerCalls.Load() != 2 {
		t.Fatal("expired login re-registered")
	}
}

func mustLogin(t *testing.T, p *Provider, r auth.Request, options PrepareOptions) *PendingLogin {
	t.Helper()
	result, err := p.PrepareWith(budget(t), r, options)
	if err != nil {
		t.Fatal(err)
	}
	return result.Login
}

func TestRegistrationPolicyChangeReregisters(t *testing.T) {
	f := dcrSetup(t, ccFlow)
	p, r := f.provider(), f.request("backend")
	credential := prepared(t, p, r).Credential
	first := f.registration(t, f.config).Registration.SecretRef
	f.set(func(f *dcrFixture) {
		f.config.Registration = &RegistrationPolicy{ClientName: "Renamed", SoftwareID: "adapter", Scopes: []string{"events"}}
	})
	expireGrant(t, f, credential)
	c, err := p.Credential(budget(t), r)
	if err != nil || c.Token != "access-dcr-2" {
		t.Fatalf("policy change: %v", err)
	}
	body := f.registrations[1].Body
	if body["client_name"] != "Renamed" || body["software_id"] != "adapter" || body["scope"] != "events" || !slices.Equal(f.secrets.deleted, []string{first}) || f.secrets.count() != 1 {
		t.Fatalf("re-registration %v deleted=%v", body, f.secrets.deleted)
	}
}

func TestRegistrationRepairsAfterBackoff(t *testing.T) {
	f := dcrSetup(t, ccFlow)
	f.set(func(f *dcrFixture) { f.respond = respondStatus(503, nil, "") })
	p, r := f.provider(), f.request("backend")
	p.Prepare(budget(t), r)
	f.set(func(f *dcrFixture) { f.respond = nil })
	_, err := lookup(t, p, r)
	assertCode(t, err, auth.CodeCredentialUnavailable)
	f.editRegistration(t, func(record *Record) { record.RegistrationFailure.NextAttempt = time.Now().Add(-time.Second) })
	credential, err := lookup(t, p, r)
	mustToken(t, credential, err, "access-dcr-2")
	if f.registerCalls.Load() != 2 {
		t.Fatal("unattended repair")
	}
}

// renewable registers a client-credentials client whose secret expires in an
// hour, then backdates its local registration time so renewal is due.
func renewable(t *testing.T) (*dcrFixture, *auth.Credential) {
	f := dcrSetup(t, ccFlow)
	f.set(func(f *dcrFixture) { f.expiresAt = time.Now().Add(time.Hour).Unix() })
	p, r := f.provider(), f.request("backend")
	credential := prepared(t, p, r).Credential
	// client_id_issued_at (1970) is ignored: one hour of a fresh lifetime is outside the margin.
	expireGrant(t, f, credential)
	credential, err := lookup(t, p, r)
	mustToken(t, credential, err, "access-dcr-1")
	if f.registerCalls.Load() != 1 {
		t.Fatal("renewed outside the margin")
	}
	// Let the post-acquisition renewal checks (not due) finish first.
	time.Sleep(100 * time.Millisecond)
	f.editRegistration(t, func(record *Record) { record.Registration.RegisteredAt = time.Now().Add(-10 * time.Hour) })
	expireGrant(t, f, credential)
	return f, credential
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func TestProactiveRenewal(t *testing.T) {
	f, _ := renewable(t)
	p, r := f.provider(), f.request("backend")
	// The operation acquires with the current registration; renewal follows.
	credential, err := lookup(t, p, r)
	mustToken(t, credential, err, "access-dcr-1")
	eventually(t, "renewal", func() bool { return f.registration(t, f.config).Registration.ClientID == "dcr-2" })
	expireGrant(t, f, credential)
	credential, err = lookup(t, p, r)
	mustToken(t, credential, err, "access-dcr-2")
	if f.registerCalls.Load() != 2 {
		t.Fatal("proactive renewal")
	}
}

func TestProactiveRenewalOnceAcrossProcesses(t *testing.T) {
	f, _ := renewable(t)
	processes := []*Provider{f.provider(), f.provider()}
	var wg sync.WaitGroup
	for i := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := processes[i%2].Credential(budget(t), f.request("backend")); err != nil {
				t.Errorf("credential %v", err)
			}
		}()
	}
	wg.Wait()
	eventually(t, "renewal", func() bool { return f.registration(t, f.config).Registration.ClientID == "dcr-2" })
	time.Sleep(100 * time.Millisecond)
	if f.registerCalls.Load() != 2 {
		t.Fatalf("renewals = %d", f.registerCalls.Load()-1)
	}
}

func TestProactiveRenewalFailureKeepsRegistration(t *testing.T) {
	f, _ := renewable(t)
	f.set(func(f *dcrFixture) { f.respond = respondStatus(429, nil, "") })
	credential, err := lookup(t, f.provider(), f.request("backend"))
	mustToken(t, credential, err, "access-dcr-1")
	eventually(t, "failed marker", func() bool { return f.registration(t, f.config).RegistrationFailure != nil })
	record := f.registration(t, f.config)
	if f.registerCalls.Load() != 2 || record.Registration.ClientID != "dcr-1" || record.RegistrationFailure.Attempts != 1 {
		t.Fatalf("failed renewal: %+v", record)
	}
}

// A slow failing renewal never fails, delays or extends the operation.
func TestSlowFailedRenewalDoesNotAffectLookup(t *testing.T) {
	f, _ := renewable(t)
	f.set(func(f *dcrFixture) {
		f.respond = func(w http.ResponseWriter, _ int) {
			time.Sleep(700 * time.Millisecond)
			w.WriteHeader(503)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	started := time.Now()
	credential, err := f.provider().PreemptiveCredential(ctx, f.request("backend"))
	elapsed := time.Since(started)
	mustToken(t, credential, err, "access-dcr-1")
	if elapsed >= 300*time.Millisecond {
		t.Fatalf("lookup waited %v for renewal", elapsed)
	}
	eventually(t, "failed marker", func() bool { return f.registration(t, f.config).RegistrationFailure != nil })
	if record := f.registration(t, f.config); record.Registration.ClientID != "dcr-1" || f.registerCalls.Load() != 2 {
		t.Fatalf("renewal outcome: %+v", record)
	}
}

func TestMarkerBlocksOnlyRegistration(t *testing.T) {
	block := func(f *dcrFixture) func(*Record) {
		return func(record *Record) {
			record.RegistrationFailure = &RegistrationFailure{RequestDigest: requestDigest(f.config.Registration), Attempts: 1, NextAttempt: time.Now().Add(time.Hour)}
		}
	}
	f := dcrSetup(t, ccFlow)
	p, r := f.provider(), f.request("backend")
	prepared(t, p, r)
	f.editRegistration(t, block(f))
	credential, err := lookup(t, p, r)
	mustToken(t, credential, err, "access-dcr-1")

	f = dcrSetup(t, pkceFlow)
	p, r = f.provider(), f.request("backend")
	login, err := f.complete(t, p, r, prepared(t, p, r).Login)
	if err != nil {
		t.Fatal(err)
	}
	f.editRegistration(t, block(f))
	if credential, err := lookup(t, p, r); err != nil || credential.Token != "access-dcr-1" {
		t.Fatal("marker blocked a still-valid PKCE token")
	}
	f.editRegistration(t, func(record *Record) { record.Registration = nil })
	expireGrant(t, f, &login)
	_, err = p.Credential(budget(t), r)
	assertCode(t, err, auth.CodeInteractionRequired)
}

func TestStaleCallbackKeepsNewerRegistration(t *testing.T) {
	for _, newer := range []bool{false, true} {
		f := dcrSetup(t, pkceFlow)
		p, r := f.provider(), f.request("backend")
		login := prepared(t, p, r).Login
		if newer {
			// Another process force-registered; the server reissued dcr-1.
			f.editRegistration(t, func(record *Record) { record.Registration.Generation = "newer" })
		}
		f.set(func(f *dcrFixture) { f.rejected["dcr-1"] = true })
		_, err := f.complete(t, p, r, login)
		assertCode(t, err, auth.CodeInteractionRequired)
		if kept := f.registration(t, f.config).Registration != nil; kept != newer {
			t.Fatalf("newer=%v: registration kept=%v", newer, kept)
		}
	}
}

func TestRegistrationRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		header string
		max    time.Duration
		want   time.Duration
	}{
		{"600", 0, 10 * time.Minute},
		{"10", 0, time.Minute},
		{"7200", 0, time.Hour},
		{"7200", 30 * time.Minute, 30 * time.Minute},
		{time.Now().Add(15 * time.Minute).UTC().Format(http.TimeFormat), 0, 15 * time.Minute},
	} {
		f := dcrSetup(t, ccFlow)
		f.set(func(f *dcrFixture) { f.respond = respondStatus(429, map[string]string{"Retry-After": tc.header}, "") })
		p := f.provider(func(o *Options) { o.RegistrationBackoffMax = tc.max })
		_, err := p.Prepare(budget(t), f.request("backend"))
		assertCode(t, err, auth.CodeProviderFailed)
		marker := f.registration(t, f.config).RegistrationFailure
		if got := marker.NextAttempt.Sub(marker.FailedAt); got < tc.want-2*time.Second || got > tc.want {
			t.Errorf("Retry-After %q: next attempt in %v; want %v", tc.header, got, tc.want)
		}
	}
}

func TestMarkerUpdateAtomicAcrossProcesses(t *testing.T) {
	f := dcrSetup(t, ccFlow)
	f.set(func(f *dcrFixture) { f.respond = respondStatus(503, nil, "") })
	processes := []*Provider{f.provider(), f.provider()}
	r := f.request("backend")
	processes[0].Prepare(budget(t), r)
	f.editRegistration(t, func(record *Record) { record.RegistrationFailure.NextAttempt = time.Now() })
	run := func(n int, call func(*Provider)) {
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() { defer wg.Done(); call(processes[i%2]) }()
		}
		wg.Wait()
	}
	// Each permitted attempt is sent by exactly one process, and every
	// failure increments the attempt count without loss.
	for round := 2; round <= 4; round++ {
		run(8, func(p *Provider) { p.PreemptiveCredential(budget(t), r) })
		marker := f.registration(t, f.config).RegistrationFailure
		if f.registerCalls.Load() != int32(round) || marker.Attempts != round || marker.NextAttempt.Sub(marker.FailedAt) != time.Minute<<(round-1) {
			t.Fatalf("round %d: calls=%d marker=%+v", round, f.registerCalls.Load(), marker)
		}
		f.editRegistration(t, func(record *Record) { record.RegistrationFailure.NextAttempt = time.Now() })
	}
	// Concurrent host prepares each send, each clearing the marker first.
	run(6, func(p *Provider) { p.Prepare(budget(t), r) })
	if f.registerCalls.Load() != 10 || f.registration(t, f.config).RegistrationFailure.Attempts != 1 {
		t.Fatalf("prepare: calls=%d marker=%+v", f.registerCalls.Load(), f.registration(t, f.config).RegistrationFailure)
	}
}

// A cancel after the registration request is written still receives,
// stores and persists the registration, so no client is orphaned.
func TestRegistrationCompletesPastCancellation(t *testing.T) {
	f := dcrSetup(t, ccFlow)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f.set(func(f *dcrFixture) {
		f.respond = func(w http.ResponseWriter, n int) {
			cancel()
			time.Sleep(50 * time.Millisecond)
			f.mu.Lock()
			f.issued["dcr-1"] = "secret-issued-1"
			f.mu.Unlock()
			w.WriteHeader(201)
			fmt.Fprint(w, `{"client_id":"dcr-1","client_secret":"secret-issued-1"}`)
		}
	})
	p, r := f.provider(), f.request("backend")
	if _, err := p.Prepare(ctx, r); err == nil {
		t.Fatal("cancellation not reported")
	}
	record := f.registration(t, f.config)
	if record == nil || record.Registration == nil || record.Registration.ClientID != "dcr-1" || f.secrets.count() != 1 || record.RegistrationFailure != nil {
		t.Fatalf("cancelled registration lost: %+v", record)
	}
	f.set(func(f *dcrFixture) { f.respond = nil })
	mustToken(t, prepared(t, p, r).Credential, nil, "access-dcr-1")
	if f.registerCalls.Load() != 1 {
		t.Fatalf("registered %d times", f.registerCalls.Load())
	}
}

// A recorded DCR selection re-registering without a secret store, or without a
// confidential method, fails credential_unavailable before any request.
func TestRecordedConfidentialRegistrationNeedsSecretStore(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*dcrFixture, *Options)
	}{
		{"no-secret-store", func(_ *dcrFixture, o *Options) { o.Secrets = nil }},
		{"no-secret-method", func(f *dcrFixture, _ *Options) {
			f.metadata["token_endpoint_auth_methods_supported"] = []string{"private_key_jwt"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := dcrSetup(t, ccFlow)
			r := f.request("backend")
			credential := prepared(t, f.provider(), r).Credential
			f.editRegistration(t, func(record *Record) { record.Registration.SecretExpiresAt = time.Now().Add(-time.Second) })
			expireGrant(t, f, credential)
			p := f.provider(func(o *Options) { f.set(func(f *dcrFixture) { tc.change(f, o) }) })
			_, err := p.Credential(budget(t), r)
			assertCode(t, err, auth.CodeCredentialUnavailable)
			if f.registerCalls.Load() != 1 {
				t.Fatal("registration sent without a confidential method")
			}
		})
	}
}

// A login created under an older registration generation is not reused after
// a forced re-registration, even when the server reissues the same client_id.
func TestForcedReregistrationSupersedesPendingLogin(t *testing.T) {
	f := dcrSetup(t, pkceFlow)
	f.set(func(f *dcrFixture) {
		f.respond = respondStatus(201, nil, `{"client_id":"dcr-1"}`)
	})
	p, r := f.provider(), f.request("backend")
	first := prepared(t, p, r).Login
	second := mustLogin(t, p, r, PrepareOptions{ForceRegistration: true})
	if loginClientID(t, second) != "dcr-1" || second.AuthorizationURL() == first.AuthorizationURL() {
		t.Fatal("stale-generation login reused")
	}
	config, _, _, _ := p.cachedBinding(budget(t), r)
	stored, _ := f.store.Load(budget(t), p.key(r, config))
	if pending := stored.Pending; pending.RegistrationGeneration != f.registration(t, f.config).Registration.Generation {
		t.Fatal("login not bound to the new registration")
	}
}

// A replaced client's binding-scoped grant is compare-and-deleted; a shared
// partition's grant is kept.
func TestReplacedClientDropsOldGrant(t *testing.T) {
	for _, tc := range []struct {
		name      string
		partition string
		replace   func(*testing.T, *dcrFixture, *Provider, auth.Request)
	}{
		{"invalid-client", "", func(t *testing.T, f *dcrFixture, p *Provider, r auth.Request) {
			f.set(func(f *dcrFixture) { f.rejected["dcr-1"] = true })
			config, _, _, _ := p.cachedBinding(budget(t), r)
			f.editKey(t, p.key(r, config), func(record *Record) { record.ExpiresAt = time.Now().Add(-time.Hour) })
			mustToken(t, prepared(t, p, r).Credential, nil, "access-dcr-2")
		}},
		{"forced", "", func(t *testing.T, f *dcrFixture, p *Provider, r auth.Request) {
			result, err := p.PrepareWith(budget(t), r, PrepareOptions{ForceRegistration: true})
			mustToken(t, result.Credential, err, "access-dcr-2")
		}},
		{"shared-partition", "shared", func(t *testing.T, f *dcrFixture, p *Provider, r auth.Request) {
			result, err := p.PrepareWith(budget(t), r, PrepareOptions{ForceRegistration: true})
			mustToken(t, result.Credential, err, "access-dcr-2")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := dcrSetup(t, ccFlow)
			f.set(func(f *dcrFixture) { f.config.GrantPartition = tc.partition })
			p, r := f.provider(), f.request("backend")
			old := prepared(t, p, r).Credential.Attempt.(attempted).key
			tc.replace(t, f, p, r)
			record, _ := f.store.Load(budget(t), old)
			if kept := record != nil && record.AccessToken != ""; kept != (tc.partition != "") {
				t.Fatalf("old grant kept=%v", kept)
			}
		})
	}
}
