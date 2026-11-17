package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// These are compatibility/security spike tests, not managed-provider parity tests.
func TestLibraryPKCEAndResourceExchange(t *testing.T) {
	verifier := oauth2.GenerateVerifier()
	const resource = "https://resource.example/events"
	const state = "host-retained-random-state"
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/token" {
			t.Error("unexpected token request")
		}
		if err := r.ParseForm(); err != nil {
			t.Error("invalid grant form")
			w.WriteHeader(400)
			return
		}
		expected := map[string]string{
			"grant_type": "authorization_code", "client_id": "test-client",
			"code": "host-validated-code", "code_verifier": verifier,
			"redirect_uri": "https://client.example/callback", "resource": resource,
		}
		for key, value := range expected {
			if r.PostForm.Get(key) != value {
				t.Errorf("wrong grant field %s", key)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"fake-access","token_type":"Bearer","expires_in":3600,"refresh_token":"fake-refresh"}`)
	}))
	defer server.Close()
	config := oauth2.Config{ClientID: "test-client", RedirectURL: "https://client.example/callback", Scopes: []string{"events"}, Endpoint: oauth2.Endpoint{AuthURL: server.URL + "/authorize", TokenURL: server.URL + "/token", AuthStyle: oauth2.AuthStyleInParams}}
	loginURL, err := url.Parse(config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("resource", resource)))
	if err != nil {
		t.Fatal("invalid generated login URL")
	}
	digest := sha256.Sum256([]byte(verifier))
	query := loginURL.Query()
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(digest[:]) || query.Get("state") != state || query.Get("resource") != resource {
		t.Fatal("PKCE login parameters not preserved")
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	token, err := config.Exchange(ctx, "host-validated-code", oauth2.VerifierOption(verifier), oauth2.SetAuthURLParam("resource", resource))
	if err != nil {
		t.Fatal("exchange failed")
	}
	if !token.Valid() || token.RefreshToken != "fake-refresh" || calls.Load() != 1 {
		t.Fatal("unexpected grant result or repeated token POST")
	}
}

// Config.TokenSource does not accept AuthCodeOptions. This test records the
// RFC 8707 gap rather than presenting the upstream behavior as AHP compliant.
func TestLibraryRefreshOmitsResourceWithoutAdditionalPolicy(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error("invalid refresh form")
			w.WriteHeader(400)
			return
		}
		if r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != "fake-refresh" {
			t.Error("wrong refresh grant")
		}
		if _, present := r.PostForm["resource"]; present {
			t.Error("upstream behavior changed: reassess the resource-bound refresh gate")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"fake-new-access","token_type":"Bearer","expires_in":3600}`)
	}))
	defer server.Close()
	config := oauth2.Config{ClientID: "test-client", Endpoint: oauth2.Endpoint{TokenURL: server.URL, AuthStyle: oauth2.AuthStyleInParams}}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	old := &oauth2.Token{AccessToken: "fake-old-access", TokenType: "Bearer", RefreshToken: "fake-refresh", Expiry: time.Unix(1, 0)}
	// The source is scoped to this operation and never retained by the package.
	token, err := config.TokenSource(ctx, old).Token()
	if err != nil {
		t.Fatal("refresh failed")
	}
	if !token.Valid() || token.RefreshToken != "fake-refresh" || calls.Load() != 1 {
		t.Fatal("unexpected refresh result")
	}
}

func TestLibraryClientCredentialsResource(t *testing.T) {
	const resource = "https://resource.example/uploads"
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error("invalid credentials form")
			w.WriteHeader(400)
			return
		}
		id, secret, ok := r.BasicAuth()
		if !ok || id != "test-client" || secret != "fake-secret" {
			t.Error("wrong explicit client authentication")
		}
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("resource") != resource || r.PostForm.Get("scope") != "uploads" {
			t.Error("wrong client credentials parameters")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"fake-upload-access","token_type":"Bearer","expires_in":3600}`)
	}))
	defer server.Close()
	config := clientcredentials.Config{ClientID: "test-client", ClientSecret: "fake-secret", TokenURL: server.URL, Scopes: []string{"uploads"}, EndpointParams: url.Values{"resource": {resource}}, AuthStyle: oauth2.AuthStyleInHeader}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	token, err := config.Token(ctx)
	if err != nil {
		t.Fatal("client credentials grant failed")
	}
	if !token.Valid() || calls.Load() != 1 {
		t.Fatal("unexpected grant result or authentication probing")
	}
}

func TestLibraryExchangeCancellation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	config := oauth2.Config{ClientID: "test-client", Endpoint: oauth2.Endpoint{TokenURL: server.URL, AuthStyle: oauth2.AuthStyleInParams}}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), oauth2.HTTPClient, server.Client()))
	cancel()
	_, err := config.Exchange(ctx, "fake-code")
	if !errors.Is(err, context.Canceled) {
		t.Fatal("exchange did not preserve native cancellation")
	}
	if calls.Load() != 0 {
		t.Fatal("cancelled exchange reached the network")
	}
}

// Upstream RetrieveError.Error includes endpoint bodies. An adapter must redact
// it and must not expose it via Unwrap or a retained cause chain.
func TestLibraryErrorsRequireRedaction(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"fake-sensitive-marker"}`)
	}))
	defer server.Close()
	config := oauth2.Config{ClientID: "test-client", Endpoint: oauth2.Endpoint{TokenURL: server.URL, AuthStyle: oauth2.AuthStyleInParams}}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	_, err := config.Exchange(ctx, "fake-code")
	var rejection *oauth2.RetrieveError
	if !errors.As(err, &rejection) || rejection.ErrorCode != "invalid_grant" {
		t.Fatal("expected structured OAuth rejection")
	}
	if !strings.Contains(err.Error(), "fake-sensitive-marker") {
		t.Fatal("upstream error redaction behavior changed; reassess adapter boundary")
	}
}
