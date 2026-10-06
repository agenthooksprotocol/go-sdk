package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

type registrationProvider struct {
	get       func(context.Context, Request) (Credential, error)
	challenge func(context.Context, Request, Challenge) (*Credential, error)
}

func (p registrationProvider) Credential(c context.Context, r Request) (Credential, error) {
	return p.get(c, r)
}
func (p registrationProvider) Challenge(c context.Context, r Request, h Challenge) (*Credential, error) {
	return p.challenge(c, r, h)
}

type providerRoundTrip func(*http.Request) (*http.Response, error)

func (f providerRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func providerRequest() (*http.Request, Request) {
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://backend.example/event", bytes.NewBufferString(`{"id":"stable"}`))
	return r, Request{Binding: json.RawMessage(`{"type":"oauth","flow":"client_credentials","issuer":"https://issuer.example","resource":"resource","clientId":"client","clientSecretRef":"ref","scopes":["event"],"extension":{"trusted":true}}`), BackendID: "example.backend", Destination: r.URL.String(), Purpose: Event}
}
func providerResponse(status int) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Www-Authenticate": {`Bearer error="invalid_token"`}}, Body: io.NopCloser(strings.NewReader(""))}
}

func TestProviderChallengePreservesBindingBodyAndOpaqueAttempt(t *testing.T) {
	req, scope := providerRequest()
	original := append([]byte(nil), scope.Binding...)
	identity := &struct{ generation int }{1}
	calls, challenges := 0, 0
	provider := registrationProvider{
		get: func(ctx context.Context, r Request) (Credential, error) {
			if !reflect.DeepEqual(r, scope) || ctx != req.Context() {
				t.Fatalf("wrong context: %+v", r)
			}
			r.Binding[0] = 'x'
			return Credential{Type: "bearer", Token: "first", Attempt: identity}, nil
		}, challenge: func(ctx context.Context, r Request, c Challenge) (*Credential, error) {
			challenges++
			if !bytes.Equal(r.Binding, original) || c.Attempt != identity || c.StatusCode != 401 || c.Header.Get("WWW-Authenticate") == "" {
				t.Fatalf("lost context: %+v %+v", r, c)
			}
			return &Credential{Type: "bearer", Token: "second", Attempt: identity}, nil
		}}
	client := &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		data, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if string(data) != `{"id":"stable"}` {
			t.Fatal("body changed")
		}
		want := "Bearer first"
		if calls == 2 {
			want = "Bearer second"
		}
		if r.Header.Get("Authorization") != want {
			t.Fatal("wrong credential")
		}
		return providerResponse(401), nil
	})}
	resp, err := Do(client, req, scope, provider, true)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if calls != 2 || challenges != 2 || req.Header.Get("Authorization") != "" || !bytes.Equal(scope.Binding, original) {
		t.Fatalf("calls=%d challenges=%d", calls, challenges)
	}
}
func TestProviderAbsentBindingAndUnsafeReplay(t *testing.T) {
	for _, safe := range []bool{false, true} {
		t.Run(map[bool]string{false: "unsafe", true: "safe"}[safe], func(t *testing.T) {
			req, scope := providerRequest()
			req.Header.Set("Authorization", "Bearer inherited-event-token")
			scope.Binding = nil
			if !safe {
				scope.Purpose = Upload
			}
			calls, challenges := 0, 0
			p := registrationProvider{get: func(context.Context, Request) (Credential, error) {
				t.Fatal("absent binding must start anonymously")
				return Credential{}, nil
			}, challenge: func(_ context.Context, r Request, c Challenge) (*Credential, error) {
				challenges++
				if r.Binding != nil || c.Attempt != nil {
					t.Fatal("unexpected identity")
				}
				return &Credential{Type: "bearer", Token: "discovered"}, nil
			}}
			client := &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					if r.Header.Get("Authorization") != "" {
						t.Fatal("not anonymous")
					}
					return providerResponse(401), nil
				}
				return providerResponse(200), nil
			})}
			resp, err := Do(client, req, scope, p, safe)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			want := 1
			if safe {
				want = 2
			}
			if calls != want || challenges != 1 {
				t.Fatalf("calls=%d challenges=%d", calls, challenges)
			}
		})
	}
}
func TestProviderFailsClosedAndRedacts(t *testing.T) {
	for _, test := range []struct {
		name, binding string
		credential    Credential
		err           error
	}{
		{name: "missing env", binding: `{"type":"bearer","tokenEnv":"AHP_TEST_MISSING_8675309"}`},
		{name: "unknown", binding: `{"type":"custom"}`},
		{name: "unsupported flow", binding: `{"type":"oauth","flow":"custom"}`},
		{name: "injection", binding: `{"type":"bearer","tokenRef":"ref"}`, credential: Credential{Type: "bearer", Token: "secret\r\nx:y"}},
		{name: "provider error", binding: `{"type":"bearer","tokenRef":"ref"}`, err: errors.New("super-secret")},
	} {
		t.Run(test.name, func(t *testing.T) {
			req, scope := providerRequest()
			scope.Binding = json.RawMessage(test.binding)
			p := registrationProvider{get: func(context.Context, Request) (Credential, error) { return test.credential, test.err }}
			var provider Provider = p
			if test.name == "missing env" {
				provider = nil
			}
			client := &http.Client{Transport: providerRoundTrip(func(*http.Request) (*http.Response, error) {
				t.Fatal("dispatched unauthorized request")
				return nil, nil
			})}
			_, err := Do(client, req, scope, provider, true)
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unredacted/missing error %v", err)
			}
		})
	}
}
func TestProviderCancellationAndRedirect(t *testing.T) {
	req, scope := providerRequest()
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	p := registrationProvider{get: func(ctx context.Context, r Request) (Credential, error) {
		cancel()
		return Credential{Type: "bearer", Token: "valid"}, nil
	}}
	_, err := Do(&http.Client{Transport: providerRoundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("dispatched canceled request"); return nil, nil })}, req, scope, p, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	req, scope = providerRequest()
	scope.Binding = nil
	calls := 0
	client := &http.Client{Transport: providerRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		r := providerResponse(307)
		r.Header.Set("Location", "https://other.example")
		return r, nil
	})}
	resp, err := Do(client, req, scope, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if calls != 1 || resp.StatusCode != 307 {
		t.Fatal("followed redirect")
	}
}
