package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func routeRequest(destination, binding string, purpose Operation) (*http.Request, Request) {
	req, _ := http.NewRequest(http.MethodPost, destination, bytes.NewBufferString(`{"jsonrpc":"2.0","id":"stable","method":"hooks/intercept"}`))
	return req, Request{BackendID: "backend", Destination: destination, Purpose: purpose, Binding: json.RawMessage(binding)}
}

const oauthPreset = `{"type":"oauth","issuer":"https://issuer.example","resource":"https://resource.example","clientId":"client","flow":"client_credentials","scopes":["event"],"extension":true}`

func TestRouteMixedBearerOAuth(t *testing.T) {
	// parity: mixed-bearer-oauth, purpose-isolation
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		want := "Bearer event-token"
		if r.URL.Path == "/upload" {
			want = "Bearer upload-token"
		}
		if r.Header.Get("Authorization") != want {
			t.Errorf("wrong credential at %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	refs := 0
	provider := Route(Routes{Bearer: NewBearerProvider(BearerOptions{ResolveSecret: func(ctx context.Context, ref string) (string, error) {
		refs++
		if ref != "vault/event" {
			t.Error("wrong reference")
		}
		return "event-token", nil
	}}), OAuth: ProviderFuncs{CredentialFunc: func(ctx context.Context, r Request) (Credential, error) {
		if r.Purpose != Upload || !strings.Contains(string(r.Binding), `"extension":true`) {
			t.Error("lost upload binding")
		}
		return Credential{Type: "bearer", Token: "upload-token"}, nil
	}}})
	for _, tc := range []struct {
		path, binding string
		purpose       Operation
	}{
		{"/event", `{"type":"bearer","tokenRef":"vault/event"}`, Event}, {"/upload", oauthPreset, Upload},
	} {
		req, r := routeRequest(server.URL+tc.path, tc.binding, tc.purpose)
		resp, err := Do(server.Client(), req, r, provider)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if refs != 1 || calls != 2 {
		t.Fatalf("refs=%d requests=%d", refs, calls)
	}
}

func TestRouteFailuresNeverFallBack(t *testing.T) {
	// parity: missing-bearer-secret, oauth-no-credential, redaction
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) }))
	defer server.Close()
	for _, tc := range []struct {
		name, binding string
		options       Routes
		code          Code
	}{
		{"missing-bearer-secret", `{"type":"bearer","tokenRef":"missing"}`, Routes{Bearer: NewBearerProvider(BearerOptions{ResolveSecret: func(context.Context, string) (string, error) { return "", errors.New("secret token callback") }})}, CodeCredentialUnavailable},
		{"oauth-no-credential", oauthPreset, Routes{OAuth: ProviderFuncs{CredentialFunc: func(context.Context, Request) (Credential, error) { return Credential{}, nil }}}, CodeCredentialUnavailable},
		{"unsupported-oauth", oauthPreset, Routes{}, CodeUnsupportedBinding},
		{"provider-error", oauthPreset, Routes{OAuth: ProviderFuncs{CredentialFunc: func(context.Context, Request) (Credential, error) {
			return Credential{}, fmt.Errorf("secret callback: %w", &Error{Code: CodeAccessDenied})
		}}}, CodeAccessDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, r := routeRequest(server.URL, tc.binding, Event)
			_, err := Do(server.Client(), req, r, Route(tc.options))
			var classified *Error
			if !errors.As(err, &classified) || classified.Code != tc.code || !errors.Is(err, ErrCredential) {
				t.Fatalf("unexpected classification: %v", err)
			}
			if strings.Contains(fmt.Sprintf("%+v", err), "secret") || strings.Contains(fmt.Sprintf("%+v", err), "callback") {
				t.Fatal("error leaks")
			}
		})
	}
	if calls != 0 {
		t.Fatalf("sent %d unauthenticated requests", calls)
	}
}

func TestRouteExplicitAuthorization(t *testing.T) {
	// parity: explicit-authorization
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "custom" {
			t.Error("header changed")
		}
		w.WriteHeader(401)
	}))
	defer server.Close()
	provider := Route(Routes{OAuth: ProviderFuncs{CredentialFunc: func(context.Context, Request) (Credential, error) {
		t.Fatal("acquisition invoked")
		return Credential{}, nil
	}, ChallengeFunc: func(context.Context, Request, Challenge) (*Credential, error) {
		t.Fatal("challenge invoked")
		return nil, nil
	}}})
	req, r := routeRequest(server.URL, oauthPreset, Event)
	resp, err := DoWithHeaders(server.Client(), req, r, provider, http.Header{"authorization": {"custom"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestRouteUnconfiguredChallengeAndBoundedReplay(t *testing.T) {
	// parity: unconfigured-challenge, effectful-no-replay
	for _, purpose := range []Operation{Event, Upload} {
		t.Run(string(purpose), func(t *testing.T) {
			calls, challenges := 0, 0
			identity := &struct{}{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				body, _ := io.ReadAll(r.Body)
				if string(body) != `{"jsonrpc":"2.0","id":"stable","method":"hooks/intercept"}` {
					t.Error("replay body changed")
				}
				if calls == 1 && r.Header.Get("Authorization") != "" {
					t.Error("not initially anonymous")
				}
				if calls > 1 && r.Header.Get("Authorization") != "Bearer replacement" {
					t.Error("missing replacement")
				}
				w.Header().Set("Www-Authenticate", `Bearer resource_metadata="https://resource.example/metadata"`)
				w.WriteHeader(401)
			}))
			defer server.Close()
			provider := Route(Routes{OAuth: ProviderFuncs{ChallengeFunc: func(ctx context.Context, r Request, c Challenge) (*Credential, error) {
				challenges++
				if c.StatusCode != 401 {
					t.Error("not a real challenge")
				}
				if challenges == 1 && c.Attempt != nil {
					t.Error("unexpected initial attempt")
				}
				if challenges > 1 && c.Attempt != identity {
					t.Error("opaque attempt lost")
				}
				return &Credential{Type: "bearer", Token: "replacement", Attempt: identity}, nil
			}}})
			req, r := routeRequest(server.URL, "", purpose)
			resp, err := Do(server.Client(), req, r, provider)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			want := 2
			if purpose == Upload {
				want = 1
			}
			if calls != want || challenges != want {
				t.Fatalf("requests=%d challenges=%d", calls, challenges)
			}
		})
	}
}

func TestRouteAttemptOwnerAndTarget(t *testing.T) {
	identity := &struct{ generation int }{1}
	challenges := 0
	provider := Route(Routes{Bearer: ProviderFuncs{CredentialFunc: func(context.Context, Request) (Credential, error) {
		return Credential{Type: "bearer", Token: "token", Attempt: identity}, nil
	}, ChallengeFunc: func(ctx context.Context, r Request, c Challenge) (*Credential, error) {
		challenges++
		if c.Attempt != identity {
			t.Error("attempt changed")
		}
		return nil, nil
	}}})
	_, r := routeRequest("https://endpoint.example/event", `{"type":"bearer","tokenEnv":"TOKEN"}`, Event)
	c, err := provider.Credential(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Challenge(context.Background(), r, Challenge{StatusCode: 401, Attempt: c.Attempt})
	if err != nil {
		t.Fatal(err)
	}
	r.Purpose = Upload
	_, err = provider.Challenge(context.Background(), r, Challenge{StatusCode: 401, Attempt: c.Attempt})
	if !errors.Is(err, ErrConfig) || challenges != 1 {
		t.Fatal("cross-purpose attempt accepted")
	}
}

func TestRouteCancellationRedactsCause(t *testing.T) {
	// parity: deadline-cancel, redaction; reference resolver is the host store boundary.
	ctx, cancel := context.WithCancelCause(context.Background())
	provider := Route(Routes{Bearer: NewBearerProvider(BearerOptions{ResolveSecret: func(ctx context.Context, ref string) (string, error) {
		cancel(errors.New("secret callback token"))
		return "", errors.Join(ctx.Err(), context.Cause(ctx))
	}})})
	_, r := routeRequest("https://endpoint.example/event", `{"type":"bearer","tokenRef":"vault/token"}`, Event)
	_, err := provider.Credential(ctx, r)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrCredential) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe cancellation: %v", err)
	}
	if errors.Is(err, context.Cause(ctx)) {
		t.Fatal("raw cause retained")
	}
}

func TestProviderErrorCodesAreAllowlisted(t *testing.T) {
	_, r := routeRequest("https://endpoint.example/event", oauthPreset, Event)
	provider := Route(Routes{OAuth: ProviderFuncs{CredentialFunc: func(context.Context, Request) (Credential, error) {
		return Credential{}, errors.Join(&Error{Code: Code("secret-callback-url")}, context.DeadlineExceeded)
	}}})
	_, err := provider.Credential(context.Background(), r)
	var classified *Error
	if !errors.As(err, &classified) || classified.Code != CodeProviderFailed || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected safe error: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%#v", classified), "secret") {
		t.Fatal("untrusted code retained")
	}
}

func TestNormalizeTargetCopiesAndValidates(t *testing.T) {
	_, r := routeRequest("https://endpoint.example/event", oauthPreset, Event)
	target, err := NormalizeTarget(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Binding[0] = 'x'
	b, ok := target.OAuth()
	if !ok || target.Kind() != BindingOAuth || b.Resource == target.Destination() {
		t.Fatal("wrong target")
	}
	b.Scopes[0] = "changed"
	original, _ := target.OAuth()
	if original.Scopes[0] != "event" || target.Request().Binding[0] != '{' {
		t.Fatal("target mutated")
	}
	for _, binding := range []string{`null`, `{}`, `{"type":"other"}`, `{"type":"bearer","tokenEnv":"A","tokenRef":"B"}`, `{"type":"oauth","issuer":"http://localhost","resource":"https://resource.example","clientId":"client","flow":"client_credentials"}`} {
		r.Binding = json.RawMessage(binding)
		if _, err := NormalizeTarget(r); err == nil {
			t.Errorf("accepted %s", binding)
		}
	}
}
