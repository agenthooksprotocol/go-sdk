package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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
		if f.registerCalls.Load() != 0 || anyPending(p) {
			t.Fatal("delivery path registered a PKCE client or created a login")
		}
		credential, err := f.complete(t, p, r, prepared(t, p, r).Login)
		if err != nil || f.registerCalls.Load() != 1 {
			t.Fatalf("prepare registration: %v", err)
		}
		// The lookup refreshes with the client stored in the grant, and
		// without one returns interaction_required; it never registers.
		expireGrant(t, f, &credential)
		mustToken(t, mustLookup(t, p, r), nil, "access-dcr-1")
		f.editKey(t, credential.Attempt.(attempted).key, func(record *Record) {
			record.ExpiresAt, record.RefreshToken = time.Now().Add(-time.Hour), ""
		})
		_, err = lookup(t, p, r)
		assertCode(t, err, auth.CodeInteractionRequired)
		if f.registerCalls.Load() != 1 || f.registration(t, f.config) != nil {
			t.Fatal("lookup registered a PKCE client or a registration record exists")
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
	f := dcrSetup(t, ccFlow)
	p, r := f.provider(), f.request("backend")
	old := prepared(t, p, r).Credential
	f.set(func(f *dcrFixture) { f.rejected["dcr-1"] = true })
	expireGrant(t, f, old)
	metadata := f.metadataCalls.Load()
	credential, err := lookup(t, p, r)
	mustToken(t, credential, err, "access-dcr-2")
	if f.registerCalls.Load() != 2 || f.metadataCalls.Load() != metadata || credential.Attempt.(attempted).key != old.Attempt.(attempted).key {
		t.Fatal("invalid_client did not re-register once under the same grant key")
	}
	// The replacement's successful token request cleared the count.
	if record := f.registration(t, f.config); record.RegistrationFailure != nil {
		t.Fatalf("successful client kept the failure count: %+v", record.RegistrationFailure)
	}
}

// A server that accepts registrations but rejects their clients: each
// invalid_client counts as a failed registration, the count survives the new
// registration, so the backoff doubles round after round and only a
// successful token request clears it.
func TestInvalidClientBackoffDoubles(t *testing.T) {
	f := dcrSetup(t, ccFlow)
	f.set(func(f *dcrFixture) { f.rejectAll = true })
	p, r := f.provider(), f.request("backend")
	for round := 1; round <= 3; round++ {
		before := time.Now()
		var err error
		if round == 1 {
			// Host prepare learns the binding; later rounds are unattended lookups.
			_, err = p.Prepare(budget(t), r)
		} else {
			_, err = lookup(t, p, r)
		}
		assertCode(t, err, auth.CodeCredentialUnavailable)
		marker := f.registration(t, f.config).RegistrationFailure
		if got := f.registerCalls.Load(); got != int32(2*round) {
			t.Fatalf("round %d: registrations = %d; want 2 per round", round, got)
		}
		// Two rejections per round: attempts 2r, backoff 2^(2r-1) minutes.
		want := time.Minute << (2*round - 1)
		if marker == nil || marker.Attempts != 2*round || marker.Code != auth.CodeCredentialUnavailable || marker.NextAttempt.Before(before.Add(want)) || marker.NextAttempt.After(time.Now().Add(want)) {
			t.Fatalf("round %d: marker = %+v; want backoff %v", round, marker, want)
		}
		// Every operation during the backoff sends nothing.
		for range 3 {
			_, err = p.Credential(budget(t), r)
			assertCode(t, err, auth.CodeCredentialUnavailable)
		}
		if got := f.registerCalls.Load(); got != int32(2*round) {
			t.Fatalf("round %d: re-registered during the backoff: %d", round, got)
		}
		f.editRegistration(t, func(record *Record) { record.RegistrationFailure.NextAttempt = time.Now() })
	}
	// A client that works clears the count.
	f.set(func(f *dcrFixture) { f.rejectAll = false })
	mustToken(t, mustLookup(t, p, r), nil, "access-dcr-7")
	if record := f.registration(t, f.config); record.RegistrationFailure != nil || record.Registration.ClientID != "dcr-7" {
		t.Fatalf("success did not clear the count: %+v", record.RegistrationFailure)
	}
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

func TestRegistrationBackoff(t *testing.T) {
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
			before := time.Now()
			_, err := one.Prepare(budget(t), r)
			assertCode(t, err, tc.code)
			marker := f.registration(t, f.config).RegistrationFailure
			if marker == nil || marker.Attempts != 1 || marker.Code != tc.code || marker.NextAttempt.Before(before.Add(time.Minute)) || marker.NextAttempt.After(time.Now().Add(time.Minute)) {
				t.Fatalf("marker = %+v", marker)
			}
			// Lookups, deliveries and challenges in any process send nothing
			// and return the last failure's code.
			_, err = lookup(t, one, r)
			assertCode(t, err, tc.code)
			_, err = two.Credential(budget(t), r)
			assertCode(t, err, tc.code)
			_, err = unboundChallenge(t, two, r)
			assertCode(t, err, tc.code)
			if f.registerCalls.Load() != 1 {
				t.Fatalf("backoff not honoured: %d", f.registerCalls.Load())
			}
			// Host prepare bypasses the backoff; its failure doubles it.
			_, err = two.Prepare(budget(t), r)
			assertCode(t, err, tc.code)
			marker = f.registration(t, f.config).RegistrationFailure
			if f.registerCalls.Load() != 2 || marker.Attempts != 2 || marker.NextAttempt.Before(before.Add(2*time.Minute)) {
				t.Fatalf("prepare attempt: %+v", marker)
			}
			f.set(func(f *dcrFixture) { f.respond = nil })
			if _, err := two.Prepare(budget(t), r); err != nil || f.registration(t, f.config).RegistrationFailure != nil {
				t.Fatalf("success did not clear the backoff: %v", err)
			}
		})
	}
}

func mustLogin(t *testing.T, p *Provider, r auth.Request, options PrepareOptions) *PendingLogin {
	t.Helper()
	result, err := p.PrepareWith(budget(t), r, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Login == nil {
		t.Fatal("expected a login")
	}
	return result.Login
}

func mustLookup(t *testing.T, p *Provider, r auth.Request) *auth.Credential {
	t.Helper()
	credential, err := lookup(t, p, r)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

// Only a host Prepare replaces a usable registration made under other
// registration settings; the old secret reference is then deleted.
func TestPrepareReplacesRegistrationOnPolicyChange(t *testing.T) {
	f := dcrSetup(t, ccFlow)
	p, r := f.provider(), f.request("backend")
	credential := prepared(t, p, r).Credential
	first := f.registration(t, f.config).Registration.SecretRef
	f.set(func(f *dcrFixture) {
		f.config.Registration = &RegistrationPolicy{ClientName: "Renamed", SoftwareID: "adapter", Scopes: []string{"events"}}
	})
	expireGrant(t, f, credential)
	mustToken(t, mustLookup(t, p, r), nil, "access-dcr-1")
	if f.registerCalls.Load() != 1 {
		t.Fatal("lookup replaced a usable registration")
	}
	expireGrant(t, f, credential)
	result := prepared(t, p, r)
	mustToken(t, result.Credential, nil, "access-dcr-2")
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
	assertCode(t, err, auth.CodeProviderFailed)
	f.editRegistration(t, func(record *Record) { record.RegistrationFailure.NextAttempt = time.Now().Add(-time.Second) })
	credential, err := lookup(t, p, r)
	mustToken(t, credential, err, "access-dcr-2")
	if f.registerCalls.Load() != 2 {
		t.Fatal("unattended repair")
	}
}

// The backoff blocks only registration requests: a usable registration and
// a still-valid stored token are still used.
func TestBackoffBlocksOnlyRegistration(t *testing.T) {
	f := dcrSetup(t, ccFlow)
	p, r := f.provider(), f.request("backend")
	credential := prepared(t, p, r).Credential
	f.editRegistration(t, func(record *Record) {
		record.RegistrationFailure = &RegistrationFailure{Code: auth.CodeProviderFailed, Attempts: 1, NextAttempt: time.Now().Add(time.Hour)}
	})
	mustToken(t, mustLookup(t, p, r), nil, "access-dcr-1")
	expireGrant(t, f, credential)
	mustToken(t, mustLookup(t, p, r), nil, "access-dcr-1")
	if f.registerCalls.Load() != 1 {
		t.Fatal("backoff sent a registration")
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
		before := time.Now()
		_, err := p.Prepare(budget(t), f.request("backend"))
		assertCode(t, err, auth.CodeProviderFailed)
		marker := f.registration(t, f.config).RegistrationFailure
		if got := marker.NextAttempt.Sub(before); got < tc.want-2*time.Second || got > tc.want+2*time.Second {
			t.Errorf("Retry-After %q: next attempt in %v; want %v", tc.header, got, tc.want)
		}
	}
}

func TestBackoffSharedAcrossProcesses(t *testing.T) {
	f := dcrSetup(t, ccFlow)
	f.set(func(f *dcrFixture) { f.respond = respondStatus(503, nil, "") })
	processes := []*Provider{f.provider(), f.provider()}
	r := f.request("backend")
	processes[0].Prepare(budget(t), r)
	f.editRegistration(t, func(record *Record) { record.RegistrationFailure.NextAttempt = time.Now() })
	// Each permitted attempt is sent by exactly one process, and every
	// failure increments the attempt count without loss.
	for round := 2; round <= 4; round++ {
		var wg sync.WaitGroup
		before := time.Now()
		for i := range 8 {
			wg.Add(1)
			go func() { defer wg.Done(); processes[i%2].PreemptiveCredential(budget(t), r) }()
		}
		wg.Wait()
		marker := f.registration(t, f.config).RegistrationFailure
		if f.registerCalls.Load() != int32(round) || marker.Attempts != round || marker.NextAttempt.Before(before.Add(time.Minute<<(round-1))) {
			t.Fatalf("round %d: calls=%d marker=%+v", round, f.registerCalls.Load(), marker)
		}
		f.editRegistration(t, func(record *Record) { record.RegistrationFailure.NextAttempt = time.Now() })
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

// grantRecord loads the grant record a credential was issued from.
func grantRecord(t *testing.T, f *dcrFixture, c *auth.Credential) *Record {
	t.Helper()
	record, err := f.store.Load(budget(t), c.Attempt.(attempted).key)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// Each PKCE login registers its own client, with that login's exact
// redirect, including a fresh loopback port; lookups and deliveries never
// register.
func TestDCRPKCERegistersPerLogin(t *testing.T) {
	f := dcrSetup(t, pkceFlow)
	p, r := f.provider(), f.request("backend")
	ports := []string{"http://127.0.0.1:51001/callback", "http://[::1]:51002/callback"}
	var logins []*PendingLogin
	for _, redirect := range ports {
		logins = append(logins, mustLogin(t, p, r, PrepareOptions{RedirectURI: redirect}))
	}
	if f.registerCalls.Load() != 2 {
		t.Fatalf("registrations = %d; want one per login", f.registerCalls.Load())
	}
	_, err := lookup(t, p, r)
	assertCode(t, err, auth.CodeInteractionRequired)
	_, err = p.Credential(budget(t), r)
	assertCode(t, err, auth.CodeInteractionRequired)
	for i, login := range logins {
		body := f.registrations[i].Body
		if redirects, _ := body["redirect_uris"].([]any); len(redirects) != 1 || redirects[0] != ports[i] || body["application_type"] != "native" || body["token_endpoint_auth_method"] != "none" {
			t.Fatalf("registration %d = %v", i, body)
		}
		u, _ := url.Parse(login.AuthorizationURL())
		if u.Query().Get("redirect_uri") != ports[i] || loginClientID(t, login) != fmt.Sprintf("dcr-%d", i+1) {
			t.Fatalf("login %d authorization URL", i)
		}
	}
	// The callback must arrive on the login's own port.
	u, _ := url.Parse(logins[1].AuthorizationURL())
	_, err = p.Complete(budget(t), r, "http://[::1]:51001/callback?"+url.Values{"state": {u.Query().Get("state")}, "code": {"code"}, "iss": {f.server.URL}}.Encode())
	assertCode(t, err, auth.CodeAccessDenied)
	if _, err := f.complete(t, p, r, logins[1]); err != nil {
		t.Fatal(err)
	}
	if form := f.tokens[len(f.tokens)-1]; form.Get("redirect_uri") != ports[1] || form.Get("client_id") != "dcr-2" {
		t.Fatalf("token request %v", form)
	}
	if f.registration(t, f.config) != nil || f.registerCalls.Load() != 2 {
		t.Fatal("PKCE registration persisted or repeated outside a login")
	}
	// A localhost redirect is invalid before any registration or login.
	_, err = p.PrepareWith(budget(t), r, PrepareOptions{RedirectURI: "http://localhost:51003/callback"})
	assertCode(t, err, auth.CodeInvalidConfiguration)
	if f.registerCalls.Load() != 2 {
		t.Fatal("localhost redirect registered")
	}
}

// Completion stores the issued client with the tokens under the dcr client
// identity; the newest completed login wins and refresh uses its client.
func TestDCRIssuedClientStoredWithGrant(t *testing.T) {
	f := dcrSetup(t, pkceFlow)
	p, r := f.provider(), f.request("backend")
	first, second := prepared(t, p, r).Login, prepared(t, p, r).Login
	b, err := f.complete(t, p, r, second)
	mustToken(t, &b, err, "access-dcr-2")
	a, err := f.complete(t, p, r, first)
	mustToken(t, &a, err, "access-dcr-1")
	key := a.Attempt.(attempted).key
	if key != b.Attempt.(attempted).key || !strings.Contains(key, "3:dcr23:authorization_code_pkce") || strings.Contains(key, "dcr-") {
		t.Fatalf("grant key %q is not keyed by the dcr client identity", key)
	}
	if record := grantRecord(t, f, &a); record.ClientID != "dcr-1" || record.AccessToken != "access-dcr-1" {
		t.Fatalf("newest completion did not replace client and tokens: %+v", record)
	}
	expireGrant(t, f, &a)
	mustToken(t, mustLookup(t, p, r), nil, "access-dcr-1")
	if form := f.tokens[len(f.tokens)-1]; form.Get("grant_type") != "refresh_token" || form.Get("client_id") != "dcr-1" || form.Get("refresh_token") != "refresh-dcr-1" {
		t.Fatalf("refresh %v", form)
	}
}

// invalid_client at completion ends only that login; at refresh it
// compare-and-deletes the grant holding the presented client and token.
func TestDCRPKCEInvalidClientDropsGrant(t *testing.T) {
	t.Run("completion", func(t *testing.T) {
		f := dcrSetup(t, pkceFlow)
		p, r := f.provider(), f.request("backend")
		f.set(func(f *dcrFixture) { f.config.AllowedScopes = []string{"events", "admin"} })
		credential, err := f.complete(t, p, r, prepared(t, p, r).Login)
		mustToken(t, &credential, err, "access-dcr-1")
		// A step-up login registers dcr-2 while the dcr-1 grant stays usable.
		login := mustLogin(t, p, r, PrepareOptions{RequiredScopes: []string{"admin"}})
		if loginClientID(t, login) != "dcr-2" {
			t.Fatal("step-up login did not register anew")
		}
		f.set(func(f *dcrFixture) { f.rejected["dcr-2"] = true })
		_, err = f.complete(t, p, r, login)
		assertCode(t, err, auth.CodeInteractionRequired)
		if record := grantRecord(t, f, &credential); record.ClientID != "dcr-1" || record.AccessToken != "access-dcr-1" {
			t.Fatalf("completion invalid_client changed the grant: %+v", record)
		}
		_, err = f.complete(t, p, r, login)
		assertCode(t, err, auth.CodeInteractionRequired)
		mustToken(t, mustLookup(t, p, r), nil, "access-dcr-1")
	})
	for _, stale := range []bool{false, true} {
		t.Run(map[bool]string{false: "refresh", true: "refresh-stale"}[stale], func(t *testing.T) {
			f := dcrSetup(t, pkceFlow)
			p, r := f.provider(), f.request("backend")
			credential, err := f.complete(t, p, r, prepared(t, p, r).Login)
			mustToken(t, &credential, err, "access-dcr-1")
			key := credential.Attempt.(attempted).key
			f.set(func(f *dcrFixture) {
				f.rejected["dcr-1"] = true
				if stale {
					// Another process commits a newer login while this refresh is in flight.
					f.onToken = func(url.Values) {
						current, _ := f.store.Load(context.Background(), key)
						newer := cloneRecord(current)
						newer.ClientID, newer.AccessToken, newer.RefreshToken, newer.Generation = "dcr-9", "access-dcr-9", "refresh-dcr-9", "newer"
						f.store.CompareAndSwap(context.Background(), key, current.Generation, newer)
					}
				}
			})
			expireGrant(t, f, &credential)
			_, err = p.Credential(budget(t), r)
			assertCode(t, err, auth.CodeInteractionRequired)
			record, _ := f.store.Load(budget(t), key)
			if stale {
				if record == nil || record.Generation != "newer" || record.ClientID != "dcr-9" {
					t.Fatalf("stale invalid_client deleted a newer grant: %+v", record)
				}
				return
			}
			if record != nil && (record.AccessToken != "" || record.RefreshToken != "" || record.ClientID != "") {
				t.Fatalf("invalid_client kept the grant: %+v", record)
			}
			if f.registerCalls.Load() != 1 || loginClientID(t, prepared(t, p, r).Login) != "dcr-2" {
				t.Fatal("next prepare did not register anew")
			}
		})
	}
}

// A CIMD redirect declared without a port matches a loopback redirect on any
// port; the exact redirect, with its port, is used for the login.
func TestCIMDPortlessLoopbackRedirect(t *testing.T) {
	f := dcrSetup(t, pkceFlow)
	document := f.server.URL + "/client.json"
	f.set(func(f *dcrFixture) {
		f.metadata["client_id_metadata_document_supported"] = true
		f.config.ClientIDMetadataDocument = &MetadataDocument{URL: document, RedirectURIs: []string{"http://127.0.0.1/callback"}}
	})
	p, r := f.provider(), f.request("backend")
	login := mustLogin(t, p, r, PrepareOptions{RedirectURI: "http://127.0.0.1:52001/callback"})
	if loginClientID(t, login) != document {
		t.Fatal("CIMD not selected")
	}
	if _, err := f.complete(t, p, r, login); err != nil {
		t.Fatal(err)
	}
	if form := f.tokens[len(f.tokens)-1]; form.Get("redirect_uri") != "http://127.0.0.1:52001/callback" {
		t.Fatalf("token request redirect %q", form.Get("redirect_uri"))
	}
	for i, redirect := range []string{"http://127.0.0.1:52002/other", "http://[::1]:52002/callback"} {
		_, err := p.PrepareWith(budget(t), f.request(fmt.Sprint("other-", i)), PrepareOptions{RedirectURI: redirect})
		assertCode(t, err, auth.CodeInvalidConfiguration)
	}
	for _, c := range []struct {
		declared, redirect string
		match              bool
	}{
		{"http://127.0.0.1/cb", "http://127.0.0.1:1/cb", true},
		{"http://127.0.0.1:2/cb", "http://127.0.0.1:1/cb", true},
		{"http://[::1]/cb", "http://[::1]:1/cb", true},
		{"http://127.0.0.1/cb", "http://user@127.0.0.1:1/cb", false},
		{"http://localhost/cb", "http://localhost:1/cb", false},
		{"https://127.0.0.1/cb", "https://127.0.0.1:1/cb", false},
		{"http://127.0.0.1/cb", "http://127.0.0.2:1/cb", false},
	} {
		if redirectMatches(c.declared, c.redirect) != c.match {
			t.Errorf("redirectMatches(%q, %q) != %v", c.declared, c.redirect, c.match)
		}
	}
}

// A redirect passed only through PrepareWith is enough: SelectClient need not
// return one, and lookup, refresh and Complete work without it.
func TestRedirectOnlyThroughPrepareWith(t *testing.T) {
	for _, source := range []string{sourcePreregistered, sourceCIMD, sourceDCR} {
		t.Run(source, func(t *testing.T) {
			f := dcrSetup(t, pkceFlow)
			f.set(func(f *dcrFixture) {
				f.config.RedirectURI = ""
				switch source {
				case sourcePreregistered:
					f.config.ClientID = "client"
				case sourceCIMD:
					f.metadata["client_id_metadata_document_supported"] = true
					f.config.ClientIDMetadataDocument = &MetadataDocument{URL: f.server.URL + "/client.json", RedirectURIs: []string{"http://127.0.0.1/callback"}}
				}
			})
			p, r := f.provider(), f.request("backend")
			_, err := p.Prepare(budget(t), r)
			assertCode(t, err, auth.CodeInvalidConfiguration)
			if f.registerCalls.Load() != 0 || anyPending(p) {
				t.Fatal("login without a redirect registered or was created")
			}
			redirect := "http://127.0.0.1:53001/callback"
			credential, err := f.complete(t, p, r, mustLogin(t, p, r, PrepareOptions{RedirectURI: redirect}))
			if err != nil {
				t.Fatal(err)
			}
			if form := f.tokens[len(f.tokens)-1]; form.Get("redirect_uri") != redirect {
				t.Fatalf("exchange redirect %q", form.Get("redirect_uri"))
			}
			mustLookup(t, p, r)
			expireGrant(t, f, &credential)
			if c := mustLookup(t, p, r); c == nil || f.tokens[len(f.tokens)-1].Get("grant_type") != "refresh_token" {
				t.Fatal("refresh without a configured redirect")
			}
			if _, err := p.Credential(budget(t), r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A recorded CIMD selection still checks each new login's redirect against
// the declared redirect URIs.
func TestRecordedCIMDChecksNewRedirect(t *testing.T) {
	f := dcrSetup(t, pkceFlow)
	f.set(func(f *dcrFixture) {
		f.metadata["client_id_metadata_document_supported"] = true
		f.config.ClientIDMetadataDocument = &MetadataDocument{URL: f.server.URL + "/client.json", RedirectURIs: []string{"http://127.0.0.1/callback"}}
	})
	p, r := f.provider(), f.request("backend")
	mustLogin(t, p, r, PrepareOptions{RedirectURI: "http://127.0.0.1:53001/callback"})
	_, err := p.PrepareWith(budget(t), r, PrepareOptions{RedirectURI: "http://127.0.0.1:53002/other"})
	assertCode(t, err, auth.CodeInvalidConfiguration)
	mustLogin(t, p, r, PrepareOptions{RedirectURI: "http://127.0.0.1:53003/callback"})
}
