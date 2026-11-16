package oauth

import (
	"context"
	"net/url"
	"slices"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

func TestManagedTokenAuthenticationMethods(t *testing.T) {
	for _, method := range []string{"client_secret_basic", "client_secret_post", "none", "private_key_jwt"} {
		t.Run(method, func(t *testing.T) {
			flow := "client_credentials"
			if method == "none" {
				flow = "authorization_code_pkce"
			}
			f, p, r := setup(t, flow)
			options := p.options
			selectClient := options.SelectClient
			options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
				c, err := selectClient(ctx, r, issuers, resource)
				c.TokenAuthMethod = method
				if method == "none" {
					c.ClientSecret = ""
				}
				return c, err
			}
			provider, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			if method == "private_key_jwt" {
				_, err = provider.Prepare(budget(t), r)
				assertCode(t, err, auth.CodeUnsupportedBinding)
				if f.tokenCalls.Load() != 0 {
					t.Fatal("unsupported credential method attempted")
				}
				return
			}
			if method == "none" {
				finishLogin(t, provider, r)
			} else if _, err = provider.Prepare(budget(t), r); err != nil {
				t.Fatal(err)
			}
			f.grantsMu.Lock()
			form := f.grants[0]
			f.grantsMu.Unlock()
			if method == "client_secret_basic" && (form.Get("client_secret") != "" || form.Get("client_id") != "") {
				t.Fatal("basic credentials also sent in form")
			}
			if method == "none" && form.Get("client_secret") != "" {
				t.Fatal("public client sent secret")
			}
		})
	}
}
func TestManagedAdvertisedCallbackIssuerRequired(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	f.mode.Store("require-issuer")
	ctx := budget(t)
	state, err := p.Prepare(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(state.Login.AuthorizationURL())
	_, err = p.Complete(ctx, state.Login, "https://client.example/callback?"+url.Values{"state": {u.Query().Get("state")}, "code": {"code"}}.Encode())
	assertCode(t, err, auth.CodeAccessDenied)
	if f.tokenCalls.Load() != 0 {
		t.Fatal("missing advertised issuer reached exchange")
	}
}
func TestDiscoveryLocationsPreserveIssuerPath(t *testing.T) {
	got := discoveryLocations("https://issuer.example/tenant/", "oauth-authorization-server", false)
	want := []string{"https://issuer.example/.well-known/oauth-authorization-server/tenant", "https://issuer.example/.well-known/oauth-authorization-server"}
	if !slices.Equal(got, want) {
		t.Fatalf("RFC 8414 issuer lookup path changed: %v", got)
	}
	got = discoveryLocations("https://issuer.example/tenant/", "openid-configuration", true)
	if got[0] != "https://issuer.example/tenant/.well-known/openid-configuration" {
		t.Fatalf("OIDC append placement: %v", got)
	}
	if resourceCovers("https://resource.example/api//", "https://resource.example/api/child") {
		t.Fatal("distinct resource path collapsed")
	}
}
