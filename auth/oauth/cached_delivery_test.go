package oauth

import (
	"context"
	"errors"
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
			if f.metadataCalls.Load() != metadata || f.tokenCalls.Load() != tokens || anyPending(f.store) {
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
			if f.tokenCalls.Load() != 1 || anyPending(f.store) {
				t.Fatal("challenge handling did not acquire exactly once without login")
			}
		})
	}
}
