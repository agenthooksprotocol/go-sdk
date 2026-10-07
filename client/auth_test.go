package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
)

type clientAuthProvider struct {
	credential func(context.Context, auth.Request) (auth.Credential, error)
	challenge  func(context.Context, auth.Request, auth.Challenge) (*auth.Credential, error)
}

func (p clientAuthProvider) Credential(c context.Context, r auth.Request) (auth.Credential, error) {
	return p.credential(c, r)
}
func (p clientAuthProvider) Challenge(c context.Context, r auth.Request, h auth.Challenge) (*auth.Credential, error) {
	return p.challenge(c, r, h)
}

func TestRegistrationAuthEventChallengeAndNotificationReplay(t *testing.T) {
	for _, notification := range []bool{false, true} {
		t.Run(map[bool]string{false: "request", true: "notification"}[notification], func(t *testing.T) {
			calls, gets, challenges := 0, 0, 0
			body := `{"jsonrpc":"2.0","id":"same","method":"intercept"}`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				data, _ := io.ReadAll(r.Body)
				if string(data) != body {
					t.Error("prepared body changed")
				}
				if calls == 1 {
					if r.Header.Get("Authorization") != "Bearer old" {
						t.Error("wrong credential")
					}
					w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
					w.WriteHeader(401)
					return
				}
				if r.Header.Get("Authorization") != "Bearer new" {
					t.Error("wrong recovery credential")
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"jsonrpc":"2.0","id":"same","result":{}}`)
			}))
			defer server.Close()
			identity := new(int)
			p := clientAuthProvider{credential: func(ctx context.Context, r auth.Request) (auth.Credential, error) {
				gets++
				if _, ok := ctx.Deadline(); !ok {
					t.Error("missing deadline")
				}
				if r.BackendID != "com.example.auth" || r.Destination != server.URL || r.Purpose != auth.Event {
					t.Errorf("wrong registration: %+v", r)
				}
				var binding map[string]any
				if json.Unmarshal(r.Binding, &binding) != nil || binding["issuer"] != "https://issuer.example" || binding["flow"] != "client_credentials" {
					t.Error("incomplete binding")
				}
				r.Binding[0] = 'x'
				return auth.Credential{Type: "bearer", Token: "old", Attempt: identity}, nil
			}, challenge: func(ctx context.Context, r auth.Request, c auth.Challenge) (*auth.Credential, error) {
				challenges++
				if c.Attempt != identity || c.Header.Get("WWW-Authenticate") == "" || !json.Valid(r.Binding) {
					t.Error("missing challenge context")
				}
				return &auth.Credential{Type: "bearer", Token: "new"}, nil
			}}
			tr, err := newAuthenticatedBackendTransport(resolverTestBackend(t, server.URL), server.Client(), func(context.Context, *ahp.Backend) (*http.Client, error) {
				t.Error("legacy resolver overrode provider")
				return nil, errors.New("legacy")
			}, p)
			if err != nil {
				t.Fatal(err)
			}
			defer tr.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = tr.Exchange(ctx, []byte(body), notification)
			if notification {
				if err == nil || calls != 1 {
					t.Fatalf("notification replayed: %d %v", calls, err)
				}
			} else if err != nil || calls != 2 {
				t.Fatalf("request recovery failed: %d %v", calls, err)
			}
			if gets != 1 || challenges != 1 {
				t.Fatalf("callbacks %d/%d", gets, challenges)
			}
		})
	}
}
func TestRegistrationAuthCancellationAndRedaction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	provider := clientAuthProvider{credential: func(c context.Context, _ auth.Request) (auth.Credential, error) {
		cancel()
		<-c.Done()
		return auth.Credential{}, errors.New("credential-secret")
	}}
	tr, err := newAuthenticatedBackendTransport(resolverTestBackend(t, "https://not-dispatched.example"), nil, nil, provider)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	_, err = tr.Exchange(ctx, []byte(`{}`), false)
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "credential-secret") {
		t.Fatalf("bad error: %v", err)
	}
}
