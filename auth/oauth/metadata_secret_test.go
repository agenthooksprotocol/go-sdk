package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

func TestMetadataCapabilityAndRuntimeSecretRotation(t *testing.T) {
	var issuer string
	var rotated atomic.Bool
	var tokenCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			method := "client_secret_post"
			if rotated.Load() {
				method = "client_secret_basic"
			}
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "token_endpoint": issuer + "/token", "grant_types_supported": []string{"client_credentials"}, "token_endpoint_auth_methods_supported": []string{method}})
		case "/token":
			tokenCalls.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if rotated.Load() {
				id, secret, ok := r.BasicAuth()
				if !ok || id != "client" || secret != "current-secret" || r.Form.Get("client_secret") != "" {
					t.Error("renewal used stale secret or authentication capability")
				}
			} else if r.Form.Get("client_secret") != "initial-secret" {
				t.Error("initial runtime secret missing")
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-access", "token_type": "Bearer", "expires_in": 3600, "scope": "read"})
		default:
			t.Errorf("configured preset fetched protected-resource metadata: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	config := ClientConfig{Issuer: issuer, Resource: issuer + "/events", ClientID: "client", Flow: "client_credentials", Scopes: []string{"read"}}
	store := newStore()
	p, err := New(Options{Namespace: "rotation", Store: store, HTTPClient: server.Client(), CheckDestination: func(ctx context.Context, raw string, _ Purpose) error {
		if raw != issuer && !strings.HasPrefix(raw, issuer+"/") {
			return &auth.Error{Code: auth.CodeUntrustedDestination}
		}
		return ctx.Err()
	}, SelectClient: func(context.Context, auth.Request, []string, string) (ClientConfig, error) {
		c := config
		c.ClientSecret = "initial-secret"
		if rotated.Load() {
			c.ClientSecret = "current-secret"
		}
		return c, nil
	}, ValidateToken: func(context.Context, ClientConfig, *oauth2.Token) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := json.Marshal(map[string]any{"type": "oauth", "issuer": issuer, "resource": config.Resource, "clientId": "client", "flow": config.Flow, "scopes": config.Scopes})
	request := auth.Request{BackendID: "backend", Purpose: auth.Event, Destination: config.Resource, Binding: binding}
	if first, err := p.Prepare(budget(t), request); err != nil || first.Credential == nil {
		t.Fatalf("initial grant: %v", err)
	}
	key := p.key(request, config)
	previous, err := store.Load(budget(t), key)
	if err != nil {
		t.Fatal(err)
	}
	expected := previous.Generation
	previous.ExpiresAt = time.Now().Add(-time.Minute)
	previous.Generation = "expired-generation"
	if ok, err := store.CompareAndSwap(budget(t), key, expected, previous); err != nil || !ok {
		t.Fatalf("expire grant: %v", err)
	}
	rotated.Store(true)
	if next, err := p.Prepare(budget(t), request); err != nil || next.Credential == nil {
		t.Fatalf("capability/secret rotation wedged grant: %v", err)
	}
	if tokenCalls.Load() != 2 {
		t.Fatal("renewal did not acquire exactly once")
	}
	stored, err := store.Load(budget(t), p.bindingKey(request))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "initial-secret") || strings.Contains(string(data), "current-secret") {
		t.Fatal("runtime client secret persisted")
	}
}
