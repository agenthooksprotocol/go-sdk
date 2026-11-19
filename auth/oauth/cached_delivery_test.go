package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

// An unavailable metadata service is a real host HTTP boundary. A cached grant
// must be usable without touching it, including after reconstructing Provider.
type unavailableMetadata struct{ calls atomic.Int32 }

func (u *unavailableMetadata) RoundTrip(*http.Request) (*http.Response, error) {
	u.calls.Add(1)
	return nil, errors.New("metadata temporarily unavailable")
}

func TestCachedUnboundUnsafeDeliveryAfterProviderRecreation(t *testing.T) {
	for _, purpose := range []auth.Operation{auth.Event, auth.Upload} {
		t.Run(string(purpose), func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			r.Binding = nil
			r.Purpose = purpose
			credential, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer resource_metadata="` + f.server.URL + `/custom-resource"`}}})
			if err != nil || credential == nil {
				t.Fatalf("authorize target: %v", err)
			}
			outage := &unavailableMetadata{}
			client := *f.server.Client()
			client.Transport = outage
			options := p.options
			options.HTTPClient = &client
			recreated, err := New(options)
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
			if response.StatusCode != http.StatusOK || f.eventCalls.Load() != 1 {
				t.Fatalf("unsafe delivery did not send cached bearer on first attempt: %d", response.StatusCode)
			}
			if prepared, err := recreated.Prepare(budget(t), r); err != nil || prepared.Credential == nil {
				t.Fatalf("host prepare did not serve the cached token: %v", err)
			}
			if outage.calls.Load() != 0 || f.tokenCalls.Load() != 1 {
				t.Fatal("cached grant performed metadata/token HTTP")
			}
		})
	}
}

// The up-front lookup falls back to an anonymous attempt only on a store miss
// (with or without a deadline) or a host policy refusal, and never discovers
// or logs in.
func TestUnboundLookupAnonymousFallback(t *testing.T) {
	for _, mode := range []string{"store-miss", "no-deadline", "policy-refusal"} {
		t.Run(mode, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			r.Binding = nil
			ctx := budget(t)
			if mode == "policy-refusal" {
				if _, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer resource_metadata="` + f.server.URL + `/custom-resource"`}}}); err != nil {
					t.Fatal(err)
				}
				expireStored(t, f, p, r)
			}
			if mode == "no-deadline" {
				ctx = context.Background()
			}
			if mode == "policy-refusal" {
				p.options.SelectClient = func(context.Context, auth.Request, []string, string) (ClientConfig, error) {
					return ClientConfig{}, errors.New("host refuses")
				}
			}
			metadata, tokens := f.metadataCalls.Load(), f.tokenCalls.Load()
			credential, err := p.PreemptiveCredential(ctx, r)
			if err != nil || credential != nil {
				t.Fatalf("lookup did not fall back to anonymous: %v", err)
			}
			if f.metadataCalls.Load() != metadata || f.tokenCalls.Load() != tokens || anyPending(p) {
				t.Fatal("lookup performed discovery, acquisition or login")
			}
		})
	}
}

// A known binding with an expired token is refreshed up front with cached
// issuer metadata, so a non-replayable upload carries a token first time.
func TestUnboundLookupRefreshesExpiredToken(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	r.Binding = nil
	r.Purpose = auth.Upload
	finishLogin(t, p, r)
	expireStored(t, f, p, r)
	recreated, err := New(p.options)
	if err != nil {
		t.Fatal(err)
	}
	metadata := f.metadataCalls.Load()
	request, err := http.NewRequestWithContext(budget(t), http.MethodPost, r.Destination, strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := auth.Do(f.server.Client(), request, r, auth.Route(auth.Routes{OAuth: recreated}))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || f.eventCalls.Load() != 1 || f.refreshCalls.Load() != 1 {
		t.Fatalf("expired stored token not refreshed before first send: %d", response.StatusCode)
	}
	if f.metadataCalls.Load() != metadata {
		t.Fatal("up-front refresh performed metadata discovery")
	}
}

func expireStored(t *testing.T, f *fixture, p *Provider, r auth.Request) {
	t.Helper()
	config, _, _, err := p.cachedBinding(budget(t), r)
	if err != nil {
		t.Fatal(err)
	}
	key := p.key(r, config)
	record, _ := f.store.Load(budget(t), key)
	next := cloneRecord(record)
	next.ExpiresAt, next.Generation = time.Now().Add(-time.Hour), randomID()
	if ok, err := f.store.CompareAndSwap(budget(t), key, record.Generation, next); !ok || err != nil {
		t.Fatalf("expire: %v", err)
	}
}

// A known binding whose up-front renewal fails fails the operation; it is never
// sent anonymously.
func TestUpFrontRefreshFailureNoAnonymousFallback(t *testing.T) {
	for mode, code := range map[string]auth.Code{"temporary": auth.CodeProviderFailed, "reject": auth.CodeRefreshRejected} {
		t.Run(mode, func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			r.Binding = nil
			finishLogin(t, p, r)
			expireStored(t, f, p, r)
			f.mode.Store(mode)
			request, err := http.NewRequestWithContext(budget(t), http.MethodPost, r.Destination, strings.NewReader(`{"jsonrpc":"2.0","method":"hooks/observe"}`))
			if err != nil {
				t.Fatal(err)
			}
			response, err := auth.Do(f.server.Client(), request, r, auth.Route(auth.Routes{OAuth: p}))
			assertCode(t, err, code)
			if response != nil || f.eventCalls.Load() != 0 {
				t.Fatal("failed up-front refresh sent anonymously")
			}
		})
	}
}

// A challenge on a request that is not replayed still prepares the next one.
func TestUnreplayedChallengePreparesNextAttempt(t *testing.T) {
	for _, purpose := range []auth.Operation{auth.Event, auth.Upload} {
		t.Run(string(purpose), func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			r.Binding, r.Purpose = nil, purpose
			provider := auth.Route(auth.Routes{OAuth: p})
			for attempt, want := range []int{http.StatusUnauthorized, http.StatusOK} {
				request, err := http.NewRequestWithContext(budget(t), http.MethodPost, r.Destination, strings.NewReader(`{"jsonrpc":"2.0","method":"hooks/observe"}`))
				if err != nil {
					t.Fatal(err)
				}
				response, err := auth.Do(f.server.Client(), request, r, provider)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != want || f.eventCalls.Load() != int32(attempt+1) {
					t.Fatalf("attempt %d: status %d", attempt, response.StatusCode)
				}
			}
			if f.tokenCalls.Load() != 1 || anyPending(p) {
				t.Fatal("challenge handling did not acquire exactly once without login")
			}
		})
	}
}

func learnUnbound(t *testing.T, f *fixture, p *Provider, r auth.Request) {
	t.Helper()
	if _, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer resource_metadata="` + f.server.URL + `/custom-resource"`}}}); err != nil {
		t.Fatal(err)
	}
}
func doNotification(t *testing.T, f *fixture, p *Provider, r auth.Request) (*http.Response, error) {
	t.Helper()
	request, err := http.NewRequestWithContext(budget(t), http.MethodPost, r.Destination, strings.NewReader(`{"jsonrpc":"2.0","method":"hooks/observe"}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := auth.Do(f.server.Client(), request, r, auth.Route(auth.Routes{OAuth: p}))
	if response != nil {
		response.Body.Close()
	}
	return response, err
}

// An expired client-credentials token without refresh material is re-acquired
// up front from persisted metadata.
func TestUpFrontClientCredentialsReacquire(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	r.Binding, r.Purpose = nil, auth.Upload
	learnUnbound(t, f, p, r)
	expireStored(t, f, p, r)
	recreated, err := New(p.options)
	if err != nil {
		t.Fatal(err)
	}
	metadata := f.metadataCalls.Load()
	response, err := doNotification(t, f, recreated, r)
	if err != nil || response.StatusCode != http.StatusOK || f.eventCalls.Load() != 1 || f.tokenCalls.Load() != 2 {
		t.Fatalf("expired machine token not re-acquired before first send: %v", err)
	}
	if f.metadataCalls.Load() != metadata {
		t.Fatal("re-acquisition fetched metadata despite persisted metadata")
	}
}

// Without persisted issuer metadata the lookup fetches only the stored issuer's
// metadata, never protected-resource metadata; a failure is discovery_failed.
func TestUpFrontLookupIssuerMetadataOnly(t *testing.T) {
	for _, fails := range []bool{false, true} {
		t.Run(map[bool]string{false: "fetch", true: "failure"}[fails], func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			r.Binding = nil
			learnUnbound(t, f, p, r)
			expireStored(t, f, p, r)
			key := p.bindingKey(r)
			binding, _ := f.store.Load(budget(t), key)
			stripped := cloneRecord(binding)
			stripped.Binding.IssuerMetadata, stripped.Generation = metadata{}, randomID()
			if ok, err := f.store.CompareAndSwap(budget(t), key, binding.Generation, stripped); !ok || err != nil {
				t.Fatal(err)
			}
			if fails {
				check := p.options.CheckDestination
				p.options.CheckDestination = func(ctx context.Context, raw string, purpose Purpose) error {
					if purpose == Metadata {
						return errors.New("metadata unavailable")
					}
					return check(ctx, raw, purpose)
				}
			}
			resources, metadataCalls := f.resourceCalls.Load(), f.metadataCalls.Load()
			credential, err := p.PreemptiveCredential(budget(t), r)
			if f.resourceCalls.Load() != resources {
				t.Fatal("lookup ran protected-resource discovery")
			}
			if fails {
				assertCode(t, err, auth.CodeDiscoveryFailed)
				return
			}
			if err != nil || credential == nil || f.metadataCalls.Load() == metadataCalls {
				t.Fatalf("lookup did not renew with the issuer's metadata: %v", err)
			}
		})
	}
}

// A known PKCE binding whose tokens were dropped needs consent: the lookup
// fails interaction_required instead of sending anonymously.
func TestKnownBindingWithoutTokenRequiresLogin(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	r.Binding = nil
	finishLogin(t, p, r)
	expireStored(t, f, p, r)
	f.mode.Store("reject")
	_, err := p.Prepare(budget(t), r)
	assertCode(t, err, auth.CodeRefreshRejected)
	_, err = doNotification(t, f, p, r)
	assertCode(t, err, auth.CodeInteractionRequired)
	if f.eventCalls.Load() != 0 {
		t.Fatal("known binding without token sent anonymously")
	}
	f.mode.Store("ok")
	finishLogin(t, p, r)
	if response, err := doNotification(t, f, p, r); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("prepare did not restore the binding: %v", err)
	}
}

// A 401 for an unexpired or unknown-expiry token marks it stale: challenge
// handling renews it even for a notification, which is not replayed.
func TestChallengeRenewsRejectedUnexpiredToken(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	r.Binding = nil
	finishLogin(t, p, r)
	config, _, _, _ := p.cachedBinding(budget(t), r)
	key := p.key(r, config)
	record, _ := f.store.Load(budget(t), key)
	revoked := cloneRecord(record)
	revoked.AccessToken, revoked.ExpiresAt, revoked.Generation = "revoked-token", time.Time{}, randomID()
	if ok, err := f.store.CompareAndSwap(budget(t), key, record.Generation, revoked); !ok || err != nil {
		t.Fatal(err)
	}
	response, err := doNotification(t, f, p, r)
	if err != nil || response.StatusCode != http.StatusUnauthorized || f.eventCalls.Load() != 1 || f.refreshCalls.Load() != 1 {
		t.Fatalf("rejected token not renewed: %v", err)
	}
	if response, err = doNotification(t, f, p, r); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("next operation resent the rejected token: %v", err)
	}
}

// A known binding renewed without a caller deadline uses a bounded default budget.
func TestUpFrontRenewalWithoutDeadline(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	r.Binding = nil
	learnUnbound(t, f, p, r)
	expireStored(t, f, p, r)
	credential, err := p.PreemptiveCredential(context.Background(), r)
	if err != nil || credential == nil || f.tokenCalls.Load() != 2 {
		t.Fatalf("renewal without a deadline failed: %v", err)
	}
}

// A renewal the token endpoint provably did not process (connect failure or
// 404/410) refetches the stored issuer's metadata once and retries; a changed
// issuer is discovery_failed.
func TestStaleMetadataRefetchOnce(t *testing.T) {
	for _, mode := range []string{"moved-endpoint", "connect-failure", "oauth-error", "moved-issuer"} {
		t.Run(mode, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			r.Binding = nil
			learnUnbound(t, f, p, r)
			expireStored(t, f, p, r)
			if mode != "oauth-error" {
				key := p.bindingKey(r)
				binding, _ := f.store.Load(budget(t), key)
				moved := cloneRecord(binding)
				moved.Binding.IssuerMetadata.TokenEndpoint, moved.Generation = f.server.URL+"/moved-token", randomID()
				if mode == "connect-failure" {
					closed, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					moved.Binding.IssuerMetadata.TokenEndpoint = "https://" + closed.Addr().String() + "/token"
					closed.Close()
					p.options.CheckDestination = func(ctx context.Context, raw string, _ Purpose) error { return ctx.Err() }
				}
				if ok, err := f.store.CompareAndSwap(budget(t), key, binding.Generation, moved); !ok || err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "oauth-error":
				f.mode.Store("invalid-client")
			case "moved-issuer":
				f.mode.Store("moved-issuer")
			}
			resources, metadata := f.resourceCalls.Load(), f.metadataCalls.Load()
			credential, err := p.PreemptiveCredential(budget(t), r)
			if f.resourceCalls.Load() != resources {
				t.Fatal("refetch ran protected-resource discovery")
			}
			switch mode {
			case "moved-endpoint", "connect-failure":
				if err != nil || credential == nil || f.metadataCalls.Load() != metadata+1 {
					t.Fatalf("stale endpoint not refetched once and retried: %v", err)
				}
				stored, _ := f.store.Load(budget(t), p.bindingKey(r))
				if stored.Binding.IssuerMetadata.TokenEndpoint != f.server.URL+"/token" {
					t.Fatal("refetched metadata not persisted")
				}
			case "oauth-error":
				assertCode(t, err, auth.CodeInvalidConfiguration)
				if f.metadataCalls.Load() != metadata {
					t.Fatal("OAuth error triggered a metadata refetch")
				}
			case "moved-issuer":
				assertCode(t, err, auth.CodeDiscoveryFailed)
			}
		})
	}
}

// Ambiguous renewal failures (read timeout, reset after send, 5xx, redirect,
// non-OAuth body) and OAuth errors return
// their error with no metadata refetch and no immediate retry, so a spent
// refresh token is never replayed.
func TestAmbiguousRenewalFailureNoRefetch(t *testing.T) {
	for mode, code := range map[string]auth.Code{"temporary": auth.CodeProviderFailed, "non-oauth": auth.CodeProviderFailed, "redirect": auth.CodeProviderFailed, "cancel": auth.CodeProviderFailed, "reset": auth.CodeProviderFailed, "reject": auth.CodeRefreshRejected} {
		t.Run(mode, func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			r.Binding = nil
			finishLogin(t, p, r)
			expireStored(t, f, p, r)
			f.mode.Store(mode)
			ctx := budget(t)
			if mode == "cancel" {
				// A read timeout: the endpoint received the request but never
				// answers within the exchange budget.
				budget := persistBudget
				persistBudget = 200 * time.Millisecond
				defer func() { persistBudget = budget }()
			}
			metadata := f.metadataCalls.Load()
			_, err := p.PreemptiveCredential(ctx, r)
			assertCode(t, err, code)
			if f.metadataCalls.Load() != metadata || f.refreshCalls.Load() != 1 {
				t.Fatal("ambiguous renewal refetched metadata or replayed the refresh token")
			}
		})
	}
}

// The lookup sends anonymously only on a store miss or a SelectClient
// refusal; any other failure of a known binding is returned.
func TestUnboundLookupFailuresAreNotAnonymous(t *testing.T) {
	for _, mode := range []string{"store-error", "invalid-config", "refusal", "binding-miss"} {
		t.Run(mode, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			r.Binding = nil
			if mode != "binding-miss" {
				learnUnbound(t, f, p, r)
			}
			original := p.options.SelectClient
			switch mode {
			case "store-error":
				p.options.Store = failingLoadStore{Store: f.store, err: errors.New("store down")}
			case "invalid-config":
				p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
					c, err := original(ctx, r, issuers, resource)
					c.ClientID = ""
					return c, err
				}
			case "refusal":
				p.options.SelectClient = func(context.Context, auth.Request, []string, string) (ClientConfig, error) {
					return ClientConfig{}, errors.New("host refuses")
				}
			}
			credential, err := p.PreemptiveCredential(budget(t), r)
			if credential != nil {
				t.Fatal("unexpected credential")
			}
			switch mode {
			case "store-error":
				assertCode(t, err, auth.CodeProviderFailed)
			case "invalid-config":
				assertCode(t, err, auth.CodeInvalidConfiguration)
			default:
				if err != nil {
					t.Fatalf("store miss or refusal did not send anonymously: %v", err)
				}
			}
		})
	}
}

// When the resource moves to a new issuer, exchange-needing host prepare and
// challenge handling run full discovery and rebind, whether or not the old
// issuer still answers.
func TestChangedIssuerRepairedByDiscovery(t *testing.T) {
	for _, via := range []string{"prepare", "challenge", "prepare-without-metadata", "challenge-without-metadata", "prepare-old-issuer-up", "challenge-old-issuer-up", "prepare-refused", "challenge-refused"} {
		t.Run(via, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			r.Binding = nil
			var moved atomic.Bool
			oldUp := strings.HasSuffix(via, "-old-issuer-up") || strings.HasSuffix(via, "-refused")
			hintOnly := oldUp && strings.HasPrefix(via, "challenge")
			serve := f.server.Config.Handler
			f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if moved.Load() {
					w.Header().Set("Content-Type", "application/json")
					switch req.URL.Path {
					case "/custom-resource", "/.well-known/oauth-protected-resource/events":
						// Old issuer still up: only the challenge's resource_metadata
						// hint advertises the move, so ignoring the hint fails.
						if !hintOnly || req.URL.Path == "/custom-resource" {
							json.NewEncoder(w).Encode(map[string]any{"resource": f.resource, "authorization_servers": []string{f.server.URL + "/new"}})
							return
						}
					case "/.well-known/oauth-authorization-server", "/token":
						if !oldUp {
							w.WriteHeader(http.StatusNotFound)
							return
						}
					case "/.well-known/oauth-authorization-server/new":
						json.NewEncoder(w).Encode(map[string]any{"issuer": f.server.URL + "/new", "token_endpoint": f.server.URL + "/new-token", "grant_types_supported": []string{"client_credentials"}, "token_endpoint_auth_methods_supported": []string{"client_secret_post"}})
						return
					case "/new-token":
						req.URL.Path = "/token"
					}
				}
				serve.ServeHTTP(w, req)
			})
			original := p.options.SelectClient
			p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
				if strings.HasSuffix(via, "-refused") && moved.Load() && issuers[0] == f.server.URL {
					return ClientConfig{}, errors.New("stored issuer no longer trusted")
				}
				c, err := original(ctx, r, issuers, resource)
				c.Issuer = issuers[0]
				return c, err
			}
			learnUnbound(t, f, p, r)
			expireStored(t, f, p, r)
			if strings.HasSuffix(via, "-without-metadata") {
				key := p.bindingKey(r)
				binding, _ := f.store.Load(budget(t), key)
				stripped := cloneRecord(binding)
				stripped.Binding.IssuerMetadata, stripped.Generation = metadata{}, randomID()
				if ok, err := f.store.CompareAndSwap(budget(t), key, binding.Generation, stripped); !ok || err != nil {
					t.Fatal(err)
				}
			}
			moved.Store(true)
			if strings.HasSuffix(via, "-refused") {
				if credential, err := p.PreemptiveCredential(budget(t), r); err != nil || credential != nil {
					t.Fatalf("refused binding lookup not anonymous: %v", err)
				}
			} else if !oldUp {
				_, err := p.PreemptiveCredential(budget(t), r)
				assertCode(t, err, auth.CodeDiscoveryFailed)
			}
			if strings.HasPrefix(via, "prepare") {
				if prepared, err := p.Prepare(budget(t), r); err != nil || prepared.Credential == nil {
					t.Fatalf("prepare did not repair the binding: %v", err)
				}
			} else if _, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer resource_metadata="` + f.server.URL + `/custom-resource"`}}}); err != nil {
				t.Fatalf("challenge did not repair the binding: %v", err)
			}
			stored, _ := f.store.Load(budget(t), p.bindingKey(r))
			if stored.Binding.Config.Issuer != f.server.URL+"/new" {
				t.Fatal("repaired binding not persisted")
			}
			if credential, err := p.PreemptiveCredential(budget(t), r); err != nil || credential == nil {
				t.Fatalf("lookup unusable after repair: %v", err)
			}
		})
	}
}

// Policy that now selects another client for a known binding makes the binding
// stale: the lookup fails discovery_failed instead of sending anonymously, and
// prepare reruns discovery.
func TestUnboundLookupStaleBindingIdentity(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	r.Binding = nil
	learnUnbound(t, f, p, r)
	original := p.options.SelectClient
	p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		c, err := original(ctx, r, issuers, resource)
		c.ClientID = "rotated-client"
		return c, err
	}
	credential, err := p.PreemptiveCredential(budget(t), r)
	assertCode(t, err, auth.CodeDiscoveryFailed)
	if credential != nil || f.eventCalls.Load() != 0 {
		t.Fatal("stale binding served or sent")
	}
	resources := f.resourceCalls.Load()
	_, _ = p.Prepare(budget(t), r)
	if f.resourceCalls.Load() == resources {
		t.Fatal("prepare did not rerun discovery for the stale binding")
	}
	stored, _ := f.store.Load(budget(t), p.bindingKey(r))
	if stored.Binding.Config.ClientID != "rotated-client" {
		t.Fatal("prepare did not rebuild the binding")
	}
}

// A 401 persists the rejection before renewal, so a failed renewal (503)
// never leaves the revoked token servable.
func TestRejectedTokenPersistedBeforeFailedRenewal(t *testing.T) {
	for _, flow := range []string{"client_credentials", "authorization_code_pkce"} {
		t.Run(flow, func(t *testing.T) {
			f, p, r := setup(t, flow)
			var first auth.Credential
			if flow == "client_credentials" {
				var err error
				if first, err = p.Credential(budget(t), r); err != nil {
					t.Fatal(err)
				}
			} else {
				first = finishLogin(t, p, r)
			}
			f.mode.Store("temporary")
			_, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: http.StatusUnauthorized, Attempt: first.Attempt})
			assertCode(t, err, auth.CodeProviderFailed)
			record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
			if record == nil || record.AccessToken == first.Token {
				t.Fatal("rejected token still stored after failed renewal")
			}
			if next, err := p.Credential(budget(t), r); err == nil && next.Token == first.Token {
				t.Fatal("rejected token resent")
			}
		})
	}
}

// A 401 persists the rejection before the challenge's full discovery, so a
// discovery failure never leaves the revoked token for the up-front lookup.
func TestRejectedTokenPersistedBeforeFailedDiscovery(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	r.Binding = nil
	learnUnbound(t, f, p, r)
	config, _, _, _ := p.cachedBinding(budget(t), r)
	key := p.key(r, config)
	record, _ := f.store.Load(budget(t), key)
	revoked := cloneRecord(record)
	revoked.AccessToken, revoked.Generation = "revoked-token", randomID()
	if ok, err := f.store.CompareAndSwap(budget(t), key, record.Generation, revoked); !ok || err != nil {
		t.Fatal(err)
	}
	first, err := p.PreemptiveCredential(budget(t), r)
	if err != nil || first == nil || first.Token != "revoked-token" {
		t.Fatalf("seeded token not served: %v", err)
	}
	serve := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/custom-resource" || strings.HasPrefix(req.URL.Path, "/.well-known/oauth-protected-resource") {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		serve.ServeHTTP(w, req)
	})
	_, err = p.Challenge(budget(t), r, auth.Challenge{StatusCode: http.StatusUnauthorized, Attempt: first.Attempt, Header: http.Header{"Www-Authenticate": {`Bearer resource_metadata="` + f.server.URL + `/custom-resource"`}}})
	assertCode(t, err, auth.CodeDiscoveryFailed)
	if stored, _ := f.store.Load(budget(t), key); stored == nil || stored.AccessToken == "revoked-token" {
		t.Fatal("rejection not persisted before discovery")
	}
	if next, _ := p.PreemptiveCredential(budget(t), r); next != nil && next.Token == "revoked-token" {
		t.Fatal("up-front lookup resent the revoked token")
	}
}
