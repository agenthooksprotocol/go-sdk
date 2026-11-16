package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

type failingLoadStore struct {
	Store
	err error
}

func (s failingLoadStore) Load(context.Context, string) (*Record, error) { return nil, s.err }

func TestManagedHostErrorCodeRedaction(t *testing.T) {
	const secret = "host-secret-must-not-escape"
	for _, operation := range []string{"prepare", "credential", "complete"} {
		for _, boundary := range []string{"client-policy", "store", "token-policy"} {
			t.Run(operation+"/"+boundary, func(t *testing.T) {
				flow := "client_credentials"
				if operation == "complete" {
					flow = "authorization_code_pkce"
				}
				_, p, r := setup(t, flow)
				var login *PendingLogin
				if operation == "complete" {
					prepared, err := p.Prepare(budget(t), r)
					if err != nil {
						t.Fatal(err)
					}
					login = prepared.Login
				}
				untrusted := &auth.Error{Code: auth.Code(secret)}
				switch boundary {
				case "client-policy":
					p.options.SelectClient = func(context.Context, auth.Request, []string, string) (ClientConfig, error) {
						return ClientConfig{}, untrusted
					}
				case "store":
					p.options.Store = failingLoadStore{Store: p.options.Store, err: untrusted}
				case "token-policy":
					p.options.ValidateToken = func(context.Context, ClientConfig, *oauth2.Token) error { return untrusted }
				}
				var err error
				switch operation {
				case "prepare":
					_, err = p.Prepare(budget(t), r)
				case "credential":
					_, err = p.Credential(budget(t), r)
				case "complete":
					u, _ := url.Parse(login.AuthorizationURL())
					callback := "https://client.example/callback?" + url.Values{"state": {u.Query().Get("state")}, "code": {"test-code"}}.Encode()
					_, err = p.Complete(budget(t), login, callback)
				}
				var classified *auth.Error
				if !errors.As(err, &classified) {
					t.Fatalf("missing classified error: %v", err)
				}
				if classified.Code != auth.CodeProviderFailed {
					t.Fatalf("untrusted exported code: %q", classified.Code)
				}
				for _, value := range []any{err, classified} {
					encoded, marshalErr := json.Marshal(value)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					if strings.Contains(string(encoded), secret) {
						t.Fatalf("secret escaped JSON: %s", encoded)
					}
					if !strings.Contains(string(encoded), string(auth.CodeProviderFailed)) {
						t.Fatalf("JSON lost safe classification: %s", encoded)
					}
				}
				if classified.Recovery() != auth.RecoveryRetry || !errors.Is(err, auth.ErrCredential) {
					t.Fatal("safe recovery or sentinel compatibility changed")
				}
			})
		}
	}
}
