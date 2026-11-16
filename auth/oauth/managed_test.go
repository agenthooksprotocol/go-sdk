package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// Fake only the genuine host persistence/coordination boundary. No replacement
// production path, test callback or instrumentation exists in Provider.
type memoryStore struct {
	mu       sync.Mutex
	values   map[string]*Record
	guards   map[string]chan struct{}
	failSave atomic.Bool
}

func newStore() *memoryStore {
	return &memoryStore{values: map[string]*Record{}, guards: map[string]chan struct{}{}}
}
func (s *memoryStore) Load(ctx context.Context, key string) (*Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneRecord(s.values[key]), nil
}
func (s *memoryStore) CompareAndSwap(ctx context.Context, key, expected string, value *Record) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.failSave.Load() {
		return false, errors.New("secret-store-detail")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation(s.values[key]) != expected {
		return false, nil
	}
	if value == nil {
		delete(s.values, key)
	} else {
		s.values[key] = cloneRecord(value)
	}
	return true, nil
}
func (s *memoryStore) Coordinate(ctx context.Context, key string, work func(context.Context) error) error {
	s.mu.Lock()
	guard := s.guards[key]
	if guard == nil {
		guard = make(chan struct{}, 1)
		s.guards[key] = guard
	}
	s.mu.Unlock()
	select {
	case guard <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-guard }()
	if err := ctx.Err(); err != nil {
		return err
	}
	return work(ctx)
}

type fixture struct {
	server       *httptest.Server
	store        *memoryStore
	flow         string
	mode         atomic.Value
	tokenCalls   atomic.Int32
	refreshCalls atomic.Int32
	eventCalls   atomic.Int32
	grantsMu     sync.Mutex
	grants       []url.Values
	started      chan struct{}
	release      chan struct{}
	resource     string
}

func setup(t *testing.T, flow string) (*fixture, *Provider, auth.Request) {
	t.Helper()
	f := &fixture{store: newStore(), flow: flow, started: make(chan struct{}, 1), release: make(chan struct{})}
	f.mode.Store("ok")
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	f.resource = f.server.URL + "/events"
	t.Cleanup(f.server.Close)
	options := Options{Namespace: "account-A", Store: f.store, HTTPClient: f.server.Client(), CheckDestination: func(ctx context.Context, raw string, purpose Purpose) error {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme+"://"+u.Host != f.server.URL {
			return errors.New("secret-policy-detail")
		}
		return ctx.Err()
	}, SelectClient: func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		return ClientConfig{Issuer: f.server.URL, Resource: resource, ClientID: "client", Flow: flow, ClientSecret: "test-secret", Scopes: []string{"events"}, RedirectURI: "https://client.example/callback"}, ctx.Err()
	}, ValidateToken: func(ctx context.Context, c ClientConfig, t *oauth2.Token) error {
		if c.Resource != f.resource {
			return errors.New("bad audience")
		}
		return ctx.Err()
	}}
	p, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := json.Marshal(map[string]any{"type": "oauth", "issuer": f.server.URL, "resource": f.resource, "clientId": "client", "flow": flow, "scopes": []string{"events"}})
	return f, p, auth.Request{BackendID: "backend", Purpose: auth.Event, Destination: f.resource, Binding: binding}
}
func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/oauth-protected-resource/events", "/.well-known/oauth-protected-resource", "/custom-resource":
		json.NewEncoder(w).Encode(map[string]any{"resource": f.resource, "authorization_servers": []string{f.server.URL}})
	case "/.well-known/oauth-authorization-server":
		json.NewEncoder(w).Encode(map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "grant_types_supported": []string{"authorization_code", "client_credentials", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"}, "authorization_response_iss_parameter_supported": f.mode.Load().(string) == "require-issuer"})
	case "/token":
		f.tokenCalls.Add(1)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		f.grantsMu.Lock()
		f.grants = append(f.grants, r.PostForm)
		f.grantsMu.Unlock()
		if r.PostForm.Get("grant_type") == "refresh_token" {
			f.refreshCalls.Add(1)
		}
		clientID := r.PostForm.Get("client_id")
		if id, secret, ok := r.BasicAuth(); ok {
			if secret != "test-secret" {
				w.WriteHeader(400)
				return
			}
			clientID = id
		}
		if r.PostForm.Get("resource") != f.resource || clientID != "client" {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"invalid_request"}`)
			return
		}
		mode := f.mode.Load().(string)
		if mode == "cancel" {
			select {
			case f.started <- struct{}{}:
			default:
			}
			select {
			case <-r.Context().Done():
				return
			case <-f.release:
				return
			}
		}
		if mode == "temporary" {
			w.WriteHeader(503)
			fmt.Fprint(w, `{"error":"temporarily_unavailable","error_description":"secret-upstream-body"}`)
			return
		}
		if mode == "reject" {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"invalid_grant","error_description":"secret-upstream-body"}`)
			return
		}
		if mode == "redirect" {
			w.Header().Set("Location", f.server.URL+"/leak")
			w.WriteHeader(307)
			return
		}
		if mode == "fail-save" {
			f.store.failSave.Store(true)
		}
		scopes := "events"
		if mode == "extra-scope" {
			scopes = "events admin"
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "access-token", "refresh_token": "refresh-token", "token_type": "Bearer", "expires_in": 3600, "scope": scopes})
	case "/events":
		f.eventCalls.Add(1)
		if r.Header.Get("Authorization") == "Bearer access-token" {
			fmt.Fprint(w, `{}`)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+f.server.URL+`/custom-resource"`)
		w.WriteHeader(401)
	default:
		w.WriteHeader(404)
	}
}
func budget(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}
func assertCode(t *testing.T, err error, code auth.Code) {
	t.Helper()
	var classified *auth.Error
	if !errors.As(err, &classified) || classified.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
	if strings.Contains(fmt.Sprintf("%+v", err), "secret-") {
		t.Fatal("error leaked secret")
	}
}
func finishLogin(t *testing.T, p *Provider, r auth.Request) auth.Credential {
	t.Helper()
	ctx := budget(t)
	state, err := p.Prepare(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if state.Login == nil {
		t.Fatal("expected consent")
	}
	u, _ := url.Parse(state.Login.AuthorizationURL())
	callback := "https://client.example/callback?" + url.Values{"state": {u.Query().Get("state")}, "code": {"test-code"}, "iss": {state.Login.config.Issuer}}.Encode()
	credential, err := p.Complete(ctx, state.Login, callback)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}
func expire(t *testing.T, f *fixture, c auth.Credential) {
	t.Helper()
	owner := c.Attempt.(attempted)
	ctx := budget(t)
	err := f.store.Coordinate(ctx, owner.key, func(ctx context.Context) error {
		record, err := f.store.Load(ctx, owner.key)
		if err != nil {
			return err
		}
		expected := record.Generation
		record.ExpiresAt = time.Now().Add(-time.Hour)
		record.Generation = randomID()
		ok, err := f.store.CompareAndSwap(ctx, owner.key, expected, record)
		if !ok && err == nil {
			return errors.New("lost generation")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestManagedPKCECompletionAndPendingDedup(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	ctx := budget(t)
	state, err := p.Prepare(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	again, err := p.Prepare(ctx, r)
	if err != nil || state.Login != again.Login {
		t.Fatal("pending login was not shared")
	}
	u, _ := url.Parse(state.Login.AuthorizationURL())
	q := u.Query()
	digest := sha256.Sum256([]byte(state.Login.verifier))
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(digest[:]) || q.Get("resource") != f.resource {
		t.Fatal("PKCE/resource lost")
	}
	callback := "https://client.example/callback?" + url.Values{"state": {q.Get("state")}, "code": {"test-code"}, "iss": {f.server.URL}}.Encode()
	credential, err := p.Complete(ctx, state.Login, callback)
	if err != nil || credential.Token != "access-token" {
		t.Fatalf("completion: %v", err)
	}
	_, err = p.Complete(ctx, state.Login, callback)
	assertCode(t, err, auth.CodeInvalidConfiguration)
	cached, err := p.Prepare(ctx, r)
	if err != nil || cached.Credential == nil {
		t.Fatalf("restore: %v", err)
	}
	if f.tokenCalls.Load() != 1 {
		t.Fatal("single-use callback exchanged twice")
	}
	f.grantsMu.Lock()
	grant := f.grants[0]
	f.grantsMu.Unlock()
	if grant.Get("code_verifier") != state.Login.verifier || grant.Get("redirect_uri") != "https://client.example/callback" {
		t.Fatal("code exchange lost binding")
	}
	if text := fmt.Sprintf("%+v %#v %+v", state.Login, state.Login, state); strings.Contains(text, "test-code") || strings.Contains(text, state.Login.state) || strings.Contains(text, state.Login.verifier) {
		t.Fatal("login formatting leaked secrets")
	}
}
func TestManagedClientCredentialsSingleFlightAndIsolation(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	ctx := budget(t)
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state, err := p.Prepare(ctx, r)
			if err == nil && state.Credential == nil {
				err = errors.New("missing token")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.tokenCalls.Load() != 1 {
		t.Fatal("concurrent acquisitions were not coordinated")
	}
	upload := r
	upload.Purpose = auth.Upload
	state, err := p.Prepare(ctx, upload)
	if err != nil || state.Credential == nil {
		t.Fatal(err)
	}
	if f.tokenCalls.Load() != 2 {
		t.Fatal("upload reused event credentials")
	}
	different := r
	different.BackendID = "other"
	if _, err := p.Prepare(ctx, different); err != nil {
		t.Fatal(err)
	}
	different = r
	different.Destination += "/child"
	if _, err := p.Prepare(ctx, different); err != nil {
		t.Fatal(err)
	}
	options := p.options
	options.Namespace = "account-B"
	second, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Prepare(ctx, r); err != nil {
		t.Fatal(err)
	}
	if f.tokenCalls.Load() != 5 {
		t.Fatal("backend/path/namespace identities conflated")
	}
}
func TestManagedResourceBoundRefreshAndStaleRejection(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	first := finishLogin(t, p, r)
	expire(t, f, first)
	ctx := budget(t)
	next, err := p.Prepare(ctx, r)
	if err != nil || next.Credential == nil {
		t.Fatal(err)
	}
	if f.refreshCalls.Load() != 1 {
		t.Fatal("missing refresh")
	}
	f.grantsMu.Lock()
	form := f.grants[len(f.grants)-1]
	f.grantsMu.Unlock()
	if form.Get("resource") != f.resource || form.Get("refresh_token") != "refresh-token" {
		t.Fatal("refresh lost audience")
	}
	recovered, err := p.Challenge(ctx, r, auth.Challenge{StatusCode: 401, Attempt: first.Attempt})
	if err != nil || recovered == nil {
		t.Fatal(err)
	}
	if f.refreshCalls.Load() != 1 {
		t.Fatal("stale rejection refreshed current generation")
	}
}
func TestManagedTemporaryRefreshRetainsAndDefinitiveRejectionRepairs(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	first := finishLogin(t, p, r)
	expire(t, f, first)
	ctx := budget(t)
	f.mode.Store("temporary")
	_, err := p.Prepare(ctx, r)
	assertCode(t, err, auth.CodeProviderFailed)
	record, err := f.store.Load(ctx, first.Attempt.(attempted).key)
	if err != nil || record.RefreshToken != "refresh-token" || record.RefreshUncertain {
		t.Fatal("known-safe temporary failure discarded credentials")
	}
	f.mode.Store("ok")
	state, err := p.Prepare(ctx, r)
	if err != nil || state.Credential == nil {
		t.Fatal(err)
	}
	expire(t, f, *state.Credential)
	f.mode.Store("reject")
	_, err = p.Prepare(ctx, r)
	assertCode(t, err, auth.CodeRefreshRejected)
	repair, err := p.Prepare(ctx, r)
	if err != nil || repair.Login == nil {
		t.Fatal("rejected refresh cannot be repaired by consent")
	}
	f.mode.Store("ok")
	u, _ := url.Parse(repair.Login.AuthorizationURL())
	_, err = p.Complete(ctx, repair.Login, "https://client.example/callback?"+url.Values{"state": {u.Query().Get("state")}, "code": {"repair"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
}
func TestManagedCancellationLeavesAmbiguityAndReleasesCoordination(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	first := finishLogin(t, p, r)
	expire(t, f, first)
	f.mode.Store("cancel")
	ctx, cancel := context.WithCancel(budget(t))
	done := make(chan error, 1)
	go func() { _, err := p.Prepare(ctx, r); done <- err }()
	<-f.started
	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	close(f.release)
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if record == nil || !record.RefreshUncertain || record.RefreshToken != "refresh-token" {
		t.Fatal("ambiguous rotation was silently reused")
	}
	f.mode.Store("ok")
	repair, err := p.Prepare(budget(t), r)
	if err != nil || repair.Login == nil {
		t.Fatal("coordination not released or consent unavailable")
	}
	if f.refreshCalls.Load() != 1 {
		t.Fatal("ambiguous refresh retried")
	}
}
func TestManagedFailedRefreshCommitDoesNotReuseOldGeneration(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	first := finishLogin(t, p, r)
	expire(t, f, first)
	f.mode.Store("fail-save")
	_, err := p.Prepare(budget(t), r)
	assertCode(t, err, auth.CodeProviderFailed)
	f.store.failSave.Store(false)
	f.mode.Store("ok")
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if record == nil || !record.RefreshUncertain {
		t.Fatal("failed commit lost ambiguity marker")
	}
	repair, err := p.Prepare(budget(t), r)
	if err != nil || repair.Login == nil {
		t.Fatal("failed commit not repairable")
	}
}
func TestManagedCallbackBindingAndNoImplicitConsent(t *testing.T) {
	for _, change := range []string{"state", "redirect", "redirect-escape", "issuer", "duplicate"} {
		t.Run(change, func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			ctx := budget(t)
			_, err := p.Credential(ctx, r)
			assertCode(t, err, auth.CodeInteractionRequired)
			prepared, err := p.Prepare(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(prepared.Login.AuthorizationURL())
			q := url.Values{"state": {u.Query().Get("state")}, "code": {"code"}}
			redirect := "https://client.example/callback"
			switch change {
			case "state":
				q.Set("state", "wrong")
			case "redirect":
				redirect = "https://evil.example/callback"
			case "redirect-escape":
				redirect = "https://client.example/%63allback"
			case "issuer":
				q.Set("iss", "https://evil.example")
			case "duplicate":
				q.Add("state", q.Get("state"))
			}
			_, err = p.Complete(ctx, prepared.Login, redirect+"?"+q.Encode())
			assertCode(t, err, auth.CodeAccessDenied)
			if f.tokenCalls.Load() != 0 {
				t.Fatal("invalid callback reached exchange")
			}
		})
	}
}
func TestManagedTrustScopesRedirectsAndErrorRedaction(t *testing.T) {
	for _, mode := range []string{"deny-metadata", "deny-token", "deny-authorization", "extra-scope", "redirect", "bad-selection"} {
		t.Run(mode, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			options := p.options
			if strings.HasPrefix(mode, "deny-") {
				original := options.CheckDestination
				options.CheckDestination = func(ctx context.Context, raw string, purpose Purpose) error {
					if string(purpose) == strings.TrimPrefix(mode, "deny-") {
						return errors.New("secret-policy-detail")
					}
					return original(ctx, raw, purpose)
				}
			} else if mode == "bad-selection" {
				original := options.SelectClient
				options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
					c, err := original(ctx, r, issuers, resource)
					c.Scopes = []string{"admin"}
					return c, err
				}
			} else {
				f.mode.Store(mode)
			}
			candidate, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			_, err = candidate.Prepare(budget(t), r)
			if err == nil {
				t.Fatal("unsafe operation accepted")
			}
			if strings.Contains(fmt.Sprintf("%+v", err), "secret-") {
				t.Fatal("error leaked secret")
			}
			if strings.HasPrefix(mode, "deny-") || mode == "bad-selection" {
				if f.tokenCalls.Load() != 0 {
					t.Fatal("disallowed target contacted")
				}
			}
		})
	}
}
func TestManagedChallengeDiscoveryAndForeignAttempt(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	ctx := budget(t)
	unbound := r
	unbound.Binding = nil
	initial, err := p.Credential(ctx, unbound)
	if err != nil || initial.Token != "" {
		t.Fatal("unbound endpoint did not start anonymously")
	}
	token, err := p.Challenge(ctx, unbound, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer resource_metadata="` + f.server.URL + `/custom-resource"`}}})
	if err != nil || token == nil {
		t.Fatalf("challenge: %v", err)
	}
	other := unbound
	other.Purpose = auth.Upload
	_, err = p.Challenge(ctx, other, auth.Challenge{StatusCode: 401, Attempt: token.Attempt})
	assertCode(t, err, auth.CodeInvalidConfiguration)
	_, err = p.Prepare(context.Background(), r)
	assertCode(t, err, auth.CodeInvalidConfiguration)
}
func TestManagedCancelledPendingAndNewerLoginGeneration(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	ctx := budget(t)
	first, err := p.Prepare(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	p.Cancel(first.Login)
	_, err = p.Complete(ctx, first.Login, "https://client.example/callback?state=x&code=x")
	assertCode(t, err, auth.CodeInvalidConfiguration)
	second, err := p.Prepare(ctx, r)
	if err != nil || second.Login == first.Login {
		t.Fatal("cancelled login reused")
	}
	options := p.options
	other, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	finishLogin(t, other, r)
	u, _ := url.Parse(second.Login.AuthorizationURL())
	credential, err := p.Complete(ctx, second.Login, "https://client.example/callback?"+url.Values{"state": {u.Query().Get("state")}, "code": {"old"}}.Encode())
	if err != nil || credential.Token == "" {
		t.Fatal(err)
	}
	if f.tokenCalls.Load() != 1 {
		t.Fatal("stale pending login overwrote new generation")
	}
}
