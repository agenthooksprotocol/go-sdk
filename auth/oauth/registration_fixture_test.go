package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

// memorySecrets fakes the host secret-storage hook boundary.
type memorySecrets struct {
	mu      sync.Mutex
	values  map[string]string
	deleted []string
}

func newSecrets() *memorySecrets { return &memorySecrets{values: map[string]string{}} }
func (s *memorySecrets) Store(ctx context.Context, ref, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.values[ref]; exists || ref == "" {
		return errors.New("reference reused")
	}
	s.values[ref] = secret
	return ctx.Err()
}
func (s *memorySecrets) Resolve(ctx context.Context, ref string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[ref]
	if !ok {
		return "", errors.New("secret-missing-detail")
	}
	return value, ctx.Err()
}
func (s *memorySecrets) Delete(_ context.Context, ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, ref)
	s.deleted = append(s.deleted, ref)
	return nil
}
func (s *memorySecrets) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.values)
}

// registrationRequest is one observed RFC 7591 request.
type registrationRequest struct {
	Body          map[string]any
	Authorization string
}

// dcrFixture is a TLS authorization server and protected resource with a
// registration endpoint. Only the network, store and secret hooks are real
// boundaries; the provider under test is unmodified.
type dcrFixture struct {
	t        *testing.T
	server   *httptest.Server
	store    *memoryStore
	secrets  *memorySecrets
	flow     string
	resource string

	mu sync.Mutex
	// config is what SelectClient returns; metadata overrides issuer metadata.
	config   ClientConfig
	metadata map[string]any
	// respond, when set, replaces the default registration response.
	respond       func(w http.ResponseWriter, n int)
	registrations []registrationRequest
	tokens        []url.Values
	tokenClients  []string
	issued        map[string]string // client_id -> secret
	rejected      map[string]bool   // client_ids rejected with invalid_client
	expiresAt     int64
	// onToken, when set, runs before the token endpoint answers.
	onToken func(form url.Values)

	registerCalls, tokenCalls, metadataCalls, documentCalls atomic.Int32
}

func dcrSetup(t *testing.T, flow string) *dcrFixture {
	t.Helper()
	f := &dcrFixture{t: t, store: newStore(), secrets: newSecrets(), flow: flow, issued: map[string]string{}, rejected: map[string]bool{}, metadata: map[string]any{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	f.resource = f.server.URL + "/events"
	f.config = ClientConfig{Issuer: f.server.URL, Resource: f.resource, Flow: flow, Scopes: []string{"events"}, Registration: &RegistrationPolicy{ClientName: "Example Adapter"}}
	if flow == pkceFlow {
		f.config.RedirectURI = "http://127.0.0.1:8765/callback"
	}
	return f
}

func (f *dcrFixture) set(change func(*dcrFixture)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

// provider builds one host process sharing the fixture's store and secrets.
func (f *dcrFixture) provider(change ...func(*Options)) *Provider {
	f.t.Helper()
	options := Options{Namespace: "account", Store: f.store, Secrets: f.secrets, HTTPClient: f.server.Client(), CheckDestination: func(ctx context.Context, raw string, _ Purpose) error {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme+"://"+u.Host != f.server.URL {
			return errors.New("secret-policy-detail")
		}
		return ctx.Err()
	}, SelectClient: func(ctx context.Context, _ auth.Request, _ []string, _ string) (ClientConfig, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return cloneConfig(f.config), ctx.Err()
	}, ValidateToken: func(ctx context.Context, _ ClientConfig, _ *oauth2.Token) error { return ctx.Err() }}
	for _, c := range change {
		c(&options)
	}
	p, err := New(options)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

// request is an unbound delivery to the protected resource: the host, not a
// preset, selects the client.
func (f *dcrFixture) request(backend string) auth.Request {
	return auth.Request{BackendID: backend, Purpose: auth.Event, Destination: f.resource}
}

func (f *dcrFixture) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/oauth-protected-resource/events", "/.well-known/oauth-protected-resource":
		json.NewEncoder(w).Encode(map[string]any{"resource": f.resource, "authorization_servers": []string{f.server.URL}})
	case "/.well-known/oauth-authorization-server":
		f.metadataCalls.Add(1)
		m := map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "registration_endpoint": f.server.URL + "/register", "grant_types_supported": []string{"authorization_code", "client_credentials", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"}}
		f.mu.Lock()
		for k, v := range f.metadata {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		f.mu.Unlock()
		json.NewEncoder(w).Encode(m)
	case "/client.json":
		f.documentCalls.Add(1)
		w.WriteHeader(500)
	case "/register":
		n := int(f.registerCalls.Add(1))
		var body map[string]any
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&body) != nil {
			f.t.Error("malformed registration request")
		}
		f.mu.Lock()
		f.registrations = append(f.registrations, registrationRequest{body, r.Header.Get("Authorization")})
		respond, expiresAt := f.respond, f.expiresAt
		f.mu.Unlock()
		if respond != nil {
			respond(w, n)
			return
		}
		id := fmt.Sprintf("dcr-%d", n)
		response := map[string]any{"client_id": id, "client_id_issued_at": 1, "registration_access_token": "secret-management-token", "registration_client_uri": f.server.URL + "/register/" + id}
		for _, name := range []string{"redirect_uris", "grant_types", "token_endpoint_auth_method", "client_name"} {
			if value, ok := body[name]; ok {
				response[name] = value
			}
		}
		secret := ""
		if body["token_endpoint_auth_method"] != "none" {
			secret = fmt.Sprintf("secret-issued-%d", n)
			response["client_secret"] = secret
			response["client_secret_expires_at"] = expiresAt
		}
		f.mu.Lock()
		f.issued[id] = secret
		f.mu.Unlock()
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(response)
	case "/token":
		f.tokenCalls.Add(1)
		r.ParseForm()
		client, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		if id, password, ok := r.BasicAuth(); ok {
			client, secret = id, password
		}
		f.mu.Lock()
		f.tokens = append(f.tokens, r.PostForm)
		f.tokenClients = append(f.tokenClients, client)
		expected, known := f.issued[client]
		rejected := f.rejected[client]
		onToken := f.onToken
		f.mu.Unlock()
		if onToken != nil {
			onToken(r.PostForm)
		}
		if rejected || (known && expected != secret) || (!known && client != "client" && !strings.HasSuffix(client, "/client.json")) {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"invalid_client"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "access-" + strings.NewReplacer("/", "-", ":", "-").Replace(client), "refresh_token": "refresh-" + strings.NewReplacer("/", "-", ":", "-").Replace(client), "token_type": "Bearer", "expires_in": 3600, "scope": "events"})
	default:
		w.WriteHeader(404)
	}
}

func (f *dcrFixture) lastTokenClient() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.tokenClients) == 0 {
		return ""
	}
	return f.tokenClients[len(f.tokenClients)-1]
}

func (f *dcrFixture) registration(t *testing.T, c ClientConfig) *Record {
	t.Helper()
	p := &Provider{options: Options{Namespace: "account"}}
	record, err := f.store.Load(budget(t), p.registrationKey(c))
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// editRegistration rewrites the stored registration-key record, as another
// process or the passage of time would.
func (f *dcrFixture) editRegistration(t *testing.T, edit func(*Record)) {
	t.Helper()
	p := &Provider{options: Options{Namespace: "account"}}
	f.mu.Lock()
	key := p.registrationKey(f.config)
	f.mu.Unlock()
	f.editKey(t, key, edit)
}

func (f *dcrFixture) editKey(t *testing.T, key string, edit func(*Record)) {
	t.Helper()
	record, err := f.store.Load(budget(t), key)
	if err != nil || record == nil {
		t.Fatalf("load %v", err)
	}
	expected := record.Generation
	edit(record)
	record.Generation = randomID()
	if ok, err := f.store.CompareAndSwap(budget(t), key, expected, record); err != nil || !ok {
		t.Fatalf("edit: %v", err)
	}
}

// expireGrant expires the stored grant for credential c.
func expireGrant(t *testing.T, f *dcrFixture, c *auth.Credential) {
	t.Helper()
	f.editKey(t, c.Attempt.(attempted).key, func(r *Record) { r.ExpiresAt = time.Now().Add(-time.Hour) })
}

// dump serializes every stored record, as a host would persist it.
func (f *dcrFixture) dump(t *testing.T) string {
	t.Helper()
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	encoded, err := json.Marshal(f.store.values)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func respondStatus(status int, header map[string]string, body string) func(http.ResponseWriter, int) {
	return func(w http.ResponseWriter, _ int) {
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

func loginClientID(t *testing.T, login *PendingLogin) string {
	t.Helper()
	if login == nil {
		t.Fatal("expected a login")
	}
	u, _ := url.Parse(login.AuthorizationURL())
	return u.Query().Get("client_id")
}

// complete answers a login the way the authorization server would.
func (f *dcrFixture) complete(t *testing.T, p *Provider, r auth.Request, login *PendingLogin) (auth.Credential, error) {
	t.Helper()
	u, _ := url.Parse(login.AuthorizationURL())
	return p.Complete(budget(t), r, u.Query().Get("redirect_uri")+"?"+url.Values{"state": {u.Query().Get("state")}, "code": {"code"}, "iss": {f.server.URL}}.Encode())
}
