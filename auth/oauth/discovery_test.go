package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

func TestManagedDiscoveryFallbackAndExactIssuer(t *testing.T) {
	for _, mode := range []string{"fallback", "wrong-resource", "wrong-issuer", "missing-pkce", "unadvertised-machine", "private-token", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			var server *httptest.Server
			var paths []string
			var pathsMu sync.Mutex
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pathsMu.Lock()
				paths = append(paths, r.URL.Path)
				pathsMu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/.well-known/oauth-protected-resource/events":
					if mode == "fallback" {
						w.WriteHeader(404)
						return
					}
					if mode == "oversized" {
						w.Write([]byte(strings.Repeat(" ", discoveryLimit+1)))
						return
					}
					fallthrough
				case "/.well-known/oauth-protected-resource":
					resource := server.URL + "/events"
					if mode == "wrong-resource" {
						resource = server.URL + "/other"
					}
					w.Write([]byte(`{"resource":"` + resource + `","authorization_servers":["` + server.URL + `"]}`))
				case "/.well-known/oauth-authorization-server":
					issuer := server.URL
					if mode == "wrong-issuer" {
						issuer += "/different"
					}
					methods := `["S256"]`
					if mode == "missing-pkce" {
						methods = `["plain"]`
					}
					grants := `["client_credentials"]`
					if mode == "unadvertised-machine" {
						grants = `["authorization_code"]`
					}
					token := server.URL + "/token"
					if mode == "private-token" {
						token = "https://127.0.0.1/private"
					}
					w.Write([]byte(`{"issuer":"` + issuer + `","authorization_endpoint":"` + server.URL + `/authorize","token_endpoint":"` + token + `","grant_types_supported":` + grants + `,"code_challenge_methods_supported":` + methods + `}`))
				default:
					t.Error("discovery contacted unexpected endpoint")
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			flow := "authorization_code_pkce"
			if mode == "unadvertised-machine" {
				flow = "client_credentials"
			}
			p, err := New(Options{Namespace: "test", Store: newStore(), HTTPClient: server.Client(), CheckDestination: func(ctx context.Context, raw string, _ Purpose) error {
				u, _ := url.Parse(raw)
				if u.Scheme+"://"+u.Host != server.URL {
					return errors.New("secret-denial")
				}
				return nil
			}, SelectClient: func(_ context.Context, _ auth.Request, _ []string, resource string) (ClientConfig, error) {
				return ClientConfig{Issuer: server.URL, Resource: resource, ClientID: "client", Flow: flow, ClientSecret: "secret", RedirectURI: "https://client.example/callback"}, nil
			}, ValidateToken: func(context.Context, ClientConfig, *oauth2.Token) error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			r := auth.Request{BackendID: "x", Destination: server.URL + "/events", Purpose: auth.Event}
			result, err := p.Prepare(budget(t), r)
			if mode == "fallback" {
				if err != nil || result.Login == nil {
					t.Fatalf("fallback: %v", err)
				}
				if len(paths) < 2 || paths[0] != "/.well-known/oauth-protected-resource/events" || paths[1] != "/.well-known/oauth-protected-resource" {
					t.Fatal("incorrect RFC9728 discovery order")
				}
			} else if err == nil {
				t.Fatal("unsafe metadata accepted")
			}
		})
	}
}
func TestManagedChallengeScopesAreNotConsent(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	r.Binding = nil
	_, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer scope="admin", resource_metadata="` + f.server.URL + `/custom-resource"`}}})
	assertCode(t, err, auth.CodeAccessDenied)
	if f.tokenCalls.Load() != 0 {
		t.Fatal("server-selected scope reached token exchange")
	}
}
func TestManagedOriginalConsentCancellation(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	ctx, cancel := context.WithCancel(budget(t))
	state, err := p.Prepare(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	unbound := r
	unbound.Binding = nil
	if _, err := p.Credential(ctx, unbound); !errors.Is(err, context.Canceled) {
		t.Fatal("anonymous credential selection lost cancellation")
	}
	u, _ := url.Parse(state.Login.AuthorizationURL())
	_, err = p.Complete(budget(t), state.Login, "https://client.example/callback?"+url.Values{"state": {u.Query().Get("state")}, "code": {"code"}}.Encode())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("original cancellation lost: %v", err)
	}
	if f.tokenCalls.Load() != 0 {
		t.Fatal("cancelled login reached exchange")
	}
	repaired, err := p.Prepare(budget(t), r)
	if err != nil || repaired.Login == state.Login {
		t.Fatal("cancelled consent cannot be replaced")
	}
}
func TestResourceCoverageAndChallengeParsing(t *testing.T) {
	for _, test := range []struct {
		resource, endpoint string
		ok                 bool
	}{
		{"https://example.test/api", "https://example.test/api/events?x=1", true},
		{"https://example.test/api", "https://example.test/apiculture", false},
		{"https://example.test/api", "https://evil.test/api", false},
		{"https://example.test/api?x=1", "https://example.test/api", false},
		{"https://example.test/api%2Fchild", "https://example.test/api/child", false},
	} {
		if resourceCovers(test.resource, test.endpoint) != test.ok {
			t.Errorf("coverage mismatch for %q", test.resource)
		}
	}
	for _, header := range []string{`Bearer resource_metadata="http://evil.test/meta"`, `Bearer resource_metadata="https://example.test/a", resource_metadata="https://example.test/b"`, `Bearer realm="unterminated`, `Bearer scope="events", scope="admin"`} {
		if _, err := bearerParameter(header, func() string {
			if strings.Contains(header, "scope=") {
				return "scope"
			}
			return "resource_metadata"
		}()); err == nil {
			t.Error("ambiguous challenge accepted")
		}
	}
	value, err := resourceMetadataHint(`Basic realm="other", Bearer realm="quoted, realm", resource_metadata="https://example.test/meta"`)
	if err != nil || value != "https://example.test/meta" {
		t.Fatal("quoted challenge parsed incorrectly")
	}
}
