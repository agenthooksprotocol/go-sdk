package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

type contractFixture struct {
	Keys []struct {
		ID    string `json:"id"`
		Input struct {
			Namespace      string   `json:"namespace"`
			BackendID      string   `json:"backend_id"`
			Purpose        string   `json:"purpose"`
			Destination    string   `json:"destination"`
			Issuer         string   `json:"issuer"`
			Resource       string   `json:"resource"`
			ClientID       string   `json:"client_id"`
			Flow           string   `json:"flow"`
			AllowedScopes  []string `json:"allowed_scopes"`
			GrantPartition string   `json:"grant_partition"`
			ClientSecret   string   `json:"client_secret"`
		} `json:"input"`
		BindingKey string `json:"binding_key"`
		GrantKey   string `json:"grant_key"`
	} `json:"keys"`
	Tokens []struct {
		ID               string          `json:"id"`
		Exchange         string          `json:"exchange"`
		PreviousGranted  []string        `json:"previous_granted"`
		Requested        []string        `json:"requested"`
		Allowed          []string        `json:"allowed"`
		Required         []string        `json:"required"`
		Response         json.RawMessage `json:"response"`
		Accepted         bool            `json:"accepted"`
		Usable           bool            `json:"usable"`
		Expiry           string          `json:"expiry"`
		Granted          []string        `json:"granted"`
		RefreshPreserved bool            `json:"refresh_preserved"`
	} `json:"token_responses"`
}

func readContract(t *testing.T) contractFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/sdk-auth-lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture contractFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestCanonicalGrantKeys(t *testing.T) {
	for _, vector := range readContract(t).Keys {
		t.Run(vector.ID, func(t *testing.T) {
			i := vector.Input
			p := &Provider{options: Options{Namespace: i.Namespace}}
			r := auth.Request{BackendID: i.BackendID, Purpose: auth.Operation(i.Purpose), Destination: i.Destination}
			c := ClientConfig{Issuer: i.Issuer, Resource: i.Resource, ClientID: i.ClientID, Flow: i.Flow, AllowedScopes: i.AllowedScopes, GrantPartition: i.GrantPartition, ClientSecret: i.ClientSecret}
			if got := p.bindingKey(r); got != vector.BindingKey {
				t.Fatalf("binding key = %q; want %q", got, vector.BindingKey)
			}
			if got := p.key(r, c); got != vector.GrantKey {
				t.Fatalf("grant key = %q; want %q", got, vector.GrantKey)
			}
		})
	}
}

// The canonical token vectors cross the real HTTP parser and coordinated host
// store, rather than reconstructing token semantics in a fixture-only helper.
func TestCanonicalTokenResponses(t *testing.T) {
	for _, vector := range readContract(t).Tokens {
		t.Run(vector.ID, func(t *testing.T) {
			var issuer string
			var tokenCalls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/.well-known/oauth-authorization-server":
					json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "token_endpoint": issuer + "/token", "authorization_endpoint": issuer + "/authorize", "code_challenge_methods_supported": []string{"S256"}, "grant_types_supported": []string{"client_credentials", "authorization_code", "refresh_token"}, "token_endpoint_auth_methods_supported": []string{"client_secret_post"}})
				case "/token":
					call := tokenCalls.Add(1)
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					expectedGrant := "client_credentials"
					if vector.Exchange == "refresh" {
						expectedGrant = "refresh_token"
						expectedRefresh := "previous-refresh"
						if call > 1 {
							expectedRefresh = "fixture-refresh"
						}
						if r.Form.Get("refresh_token") != expectedRefresh {
							t.Error("refresh material not used")
						}
					}
					if r.Form.Get("resource") != issuer+"/events" || r.Form.Get("grant_type") != expectedGrant {
						t.Error("unbound token grant")
					}
					w.Write(vector.Response)
				default:
					t.Errorf("unexpected discovery: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			issuer = server.URL
			config := ClientConfig{Issuer: issuer, Resource: issuer + "/events", ClientID: "client", Flow: "client_credentials", ClientSecret: "fixture-secret", Scopes: vector.Requested, AllowedScopes: vector.Allowed, RequiredScopes: vector.Required}
			if vector.Exchange == "refresh" {
				config.Flow = "authorization_code_pkce"
				config.RedirectURI = "https://client.example/callback"
			}
			store := newStore()
			p, err := New(Options{Namespace: "contract", Store: store, HTTPClient: server.Client(), CheckDestination: func(ctx context.Context, raw string, _ Purpose) error {
				if !strings.HasPrefix(raw, issuer+"/") && raw != issuer {
					return &auth.Error{Code: auth.CodeUntrustedDestination}
				}
				return ctx.Err()
			}, SelectClient: func(context.Context, auth.Request, []string, string) (ClientConfig, error) { return config, nil }, ValidateToken: func(context.Context, ClientConfig, *oauth2.Token) error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			binding, _ := json.Marshal(map[string]any{"type": "oauth", "issuer": issuer, "resource": config.Resource, "clientId": "client", "flow": config.Flow, "scopes": vector.Requested})
			request := auth.Request{BackendID: "backend", Purpose: auth.Event, Destination: config.Resource, Binding: binding}
			if vector.Exchange == "refresh" {
				prior := &Record{AccessToken: "prior-access", RefreshToken: "previous-refresh", Generation: "prior-generation", ExpiresAt: time.Now().Add(-time.Hour), Scopes: vector.PreviousGranted}
				if ok, err := store.CompareAndSwap(budget(t), p.key(request, config), "", prior); err != nil || !ok {
					t.Fatalf("seed prior grant: %v", err)
				}
			}
			prepared, err := p.Prepare(budget(t), request)
			if vector.Usable {
				if err != nil || prepared.Credential == nil {
					t.Fatalf("usable token rejected: %v", err)
				}
			} else if err == nil {
				t.Fatal("unusable token accepted")
			}
			record, loadErr := store.Load(budget(t), p.key(request, config))
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if vector.RefreshPreserved && (record == nil || record.RefreshToken != "fixture-refresh") {
				t.Fatal("returned refresh credential not retained")
			}
			if vector.Accepted {
				if record == nil {
					t.Fatal("accepted grant not persisted")
				}
				if !slices.Equal(sortedScopes(record.Scopes), sortedScopes(vector.Granted)) {
					t.Fatalf("granted scopes = %v; want %v", record.Scopes, vector.Granted)
				}
				if (vector.Expiry == "unknown") != record.ExpiresAt.IsZero() {
					t.Fatal("expiry classification mismatch")
				}

				if vector.Exchange == "refresh" {
					if cached, err := p.Prepare(budget(t), request); err != nil || cached.Credential == nil {
						t.Fatalf("reuse unknown-expiry token: %v", err)
					}
					if tokenCalls.Load() != 1 {
						t.Fatal("unknown expiry caused eager refresh")
					}
					expected := record.Generation
					record.Generation = "expire-rotated"
					record.ExpiresAt = time.Now().Add(-time.Hour)
					if ok, err := store.CompareAndSwap(budget(t), p.key(request, config), expected, record); err != nil || !ok {
						t.Fatalf("expire rotated grant: %v", err)
					}
					if renewed, err := p.Prepare(budget(t), request); err != nil || renewed.Credential == nil {
						t.Fatalf("reuse rotated refresh: %v", err)
					}
					if tokenCalls.Load() != 2 {
						t.Fatal("rotated refresh was not reused")
					}
				}
			}
		})
	}
}
