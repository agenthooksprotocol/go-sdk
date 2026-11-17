package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/internal/authutil"
)

func TestRecoveryContractVectors(t *testing.T) {
	data, err := os.ReadFile("oauth/testdata/sdk-auth-lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Recovery []struct {
			Code     Code     `json:"code"`
			Recovery Recovery `json:"recovery"`
		} `json:"recovery"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Recovery) != 9 {
		t.Fatalf("expected nine recovery vectors, got %d", len(vectors.Recovery))
	}
	for _, v := range vectors.Recovery {
		if got := (&Error{Code: v.Code}).Recovery(); got != v.Recovery {
			t.Errorf("%s: got %s, want %s", v.Code, got, v.Recovery)
		}
	}
	if got := (&Error{Code: Code("secret")}).Recovery(); got != RecoveryRetry {
		t.Fatalf("unknown code recovery: %s", got)
	}
}

func TestPreemptiveFirstSend(t *testing.T) {
	for _, routed := range []bool{false, true} {
		for _, cached := range []bool{false, true} {
			for _, purpose := range []Operation{Event, Upload} {
				looked, acquired, sent, challenged := 0, 0, 0, 0
				identity := new(int)
				callbacks := ProviderFuncs{
					CredentialFunc: func(context.Context, Request) (Credential, error) { acquired++; return Credential{}, nil },
					PreemptiveCredentialFunc: func(_ context.Context, r Request) (*Credential, error) {
						looked++
						if len(r.Binding) != 0 || r.Purpose != purpose {
							t.Fatal("wrong lookup context")
						}
						if !cached {
							return nil, nil
						}
						return &Credential{Type: "bearer", Token: "cached", Attempt: identity}, nil
					},
					ChallengeFunc: func(_ context.Context, _ Request, c Challenge) (*Credential, error) {
						challenged++
						if cached && c.Attempt != identity {
							t.Fatal("lost issuing attempt")
						}
						return &Credential{Type: "bearer", Token: "replacement"}, nil
					},
				}
				var provider Provider = callbacks
				if routed {
					provider = Route(Routes{OAuth: callbacks})
				}
				req, _ := http.NewRequest(http.MethodPost, "https://resource.example/events", strings.NewReader("body"))
				client := &http.Client{Transport: headerCapture(func(r *http.Request) (*http.Response, error) {
					sent++
					want := ""
					if cached {
						want = "Bearer cached"
					}
					if got := r.Header.Get("Authorization"); got != want {
						t.Errorf("first send: %q, want %q", got, want)
					}
					return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
				})}
				response, err := Do(client, req, Request{Destination: req.URL.String(), Purpose: purpose}, provider)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if looked != 1 || acquired != 0 || sent != 1 || challenged != 1 {
					t.Fatalf("lookup/acquire/send/challenge = %d/%d/%d/%d", looked, acquired, sent, challenged)
				}
			}
		}
	}
}

func TestPreemptiveOverrideAndCancellation(t *testing.T) {
	for _, routed := range []bool{false, true} {
		for _, mode := range []string{"override", "cancel", "invalid", "error"} {
			ctx, cancel := context.WithCancel(context.Background())
			called, sent := 0, 0
			callbacks := ProviderFuncs{PreemptiveCredentialFunc: func(context.Context, Request) (*Credential, error) {
				called++
				switch mode {
				case "cancel":
					cancel()
					return nil, nil
				case "error":
					return nil, errors.New("private token")
				default:
					return &Credential{}, nil
				}
			}}
			var provider Provider = callbacks
			if routed {
				provider = Route(Routes{OAuth: callbacks})
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://resource.example/events", strings.NewReader("body"))
			client := &http.Client{Transport: headerCapture(func(r *http.Request) (*http.Response, error) {
				sent++
				if r.Header.Get("Authorization") != "Bearer override" {
					t.Error("override lost")
				}
				return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
			})}
			var headers http.Header
			if mode == "override" {
				headers = http.Header{"authorization": {"Bearer override"}}
			}
			response, err := DoWithHeaders(client, req, Request{Destination: req.URL.String(), Purpose: Event}, provider, headers)
			cancel()
			if mode == "override" {
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if called != 0 || sent != 1 {
					t.Fatal("override invoked provider")
				}
			} else {
				if err == nil || sent != 0 {
					t.Fatalf("%s dispatched: %v", mode, err)
				}
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal("lost cancellation")
				}
				if strings.Contains(err.Error(), "private") {
					t.Fatal("provider error leaked")
				}
			}
		}
	}
}

func TestInsufficientScopeTransport(t *testing.T) {
	for _, header := range []string{`Bearer error="insufficient_scope", scope="write"`, `NewScheme abc==, Bearer error=insufficient_scope`, `Bearer error="access_denied"`, `Basic realm="insufficient_scope"`, `Bearer error=insufficient_scope, error=invalid_token`, `Bearer error="insufficient_scope", Bearer error="insufficient_scope"`, `Bearer error="insufficient_scope" broken`} {
		for _, purpose := range []Operation{Event, Upload} {
			calls, challenges := 0, 0
			provider := ProviderFuncs{ChallengeFunc: func(_ context.Context, _ Request, c Challenge) (*Credential, error) {
				challenges++
				if c.StatusCode != 403 {
					t.Fatal("wrong challenge status")
				}
				return &Credential{Type: "bearer", Token: "new"}, nil
			}}
			req, _ := http.NewRequest(http.MethodPost, "https://resource.example/events", strings.NewReader("body"))
			client := &http.Client{Transport: headerCapture(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 403, Header: http.Header{"Www-Authenticate": {header}}, Body: io.NopCloser(strings.NewReader(""))}, nil
			})}
			response, err := Do(client, req, Request{Destination: req.URL.String(), Purpose: purpose}, provider)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			want := 0
			if header == `Bearer error="insufficient_scope", scope="write"` || header == `NewScheme abc==, Bearer error=insufficient_scope` {
				want = 1
			}
			if calls != 1 || challenges != want {
				t.Errorf("%q: calls %d challenges %d, want 1/%d", header, calls, challenges, want)
			}
		}
	}
}

func TestWWWAuthenticateToken68(t *testing.T) {
	for _, header := range []string{`New abc==`, `Negotiate YWJjZA==, Bearer error="insufficient_scope"`, `Bearer abc=`, `Other a/b+c_~-.==`, `Basic realm="a,b", Bearer error="insufficient_scope"`} {
		if _, ok := authutil.ParseWWWAuthenticate(header); !ok {
			t.Errorf("valid challenge rejected: %s", header)
		}
	}
	for _, header := range []string{`New ab=c=`, `Bearer error="x", error="y"`, `Bearer error="insufficient_scope" junk`, `Bearer realm="unterminated`, "Bearer error=x\r\nOther abc="} {
		if _, ok := authutil.ParseWWWAuthenticate(header); ok {
			t.Errorf("invalid challenge accepted: %s", header)
		}
	}
}

func TestInsufficientScopeSafeRetryBound(t *testing.T) {
	sent, challenged := 0, 0
	provider := Route(Routes{OAuth: ProviderFuncs{ChallengeFunc: func(context.Context, Request, Challenge) (*Credential, error) {
		challenged++
		return &Credential{Type: "bearer", Token: "approved"}, nil
	}}})
	req, _ := http.NewRequest(http.MethodPost, "https://resource.example/events", strings.NewReader(`{"jsonrpc":"2.0","id":"stable","method":"hooks/intercept"}`))
	client := &http.Client{Transport: headerCapture(func(r *http.Request) (*http.Response, error) {
		sent++
		if sent == 2 && r.Header.Get("Authorization") != "Bearer approved" {
			t.Error("replacement missing")
		}
		return &http.Response{StatusCode: 403, Header: http.Header{"Www-Authenticate": {`Bearer error="insufficient_scope"`}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	response, err := Do(client, req, Request{Destination: req.URL.String(), Purpose: Event}, provider)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if sent != 2 || challenged != 2 {
		t.Fatalf("sent/challenged = %d/%d, want 2/2", sent, challenged)
	}
}

func TestProviderCredentialStillRequiresBearer(t *testing.T) {
	for _, routed := range []bool{false, true} {
		var provider Provider = ProviderFuncs{CredentialFunc: func(context.Context, Request) (Credential, error) { return Credential{}, nil }}
		if routed {
			provider = Route(Routes{OAuth: provider})
		}
		req, _ := http.NewRequest(http.MethodPost, "https://resource.example/events", strings.NewReader("body"))
		client := &http.Client{Transport: headerCapture(func(*http.Request) (*http.Response, error) { t.Fatal("invalid credential dispatched"); return nil, nil })}
		_, err := Do(client, req, Request{Destination: req.URL.String(), Purpose: Event, Binding: []byte(`{"type":"oauth","flow":"client_credentials"}`)}, provider)
		if !errors.Is(err, ErrCredential) {
			t.Fatalf("empty credential accepted: %v", err)
		}
	}
}

func TestChallengedReplayMethods(t *testing.T) {
	for body, want := range map[string]bool{
		`{"jsonrpc":"2.0","id":1,"method":"hooks/intercept"}`:       true,
		`{"jsonrpc":"2.0","id":"x","method":"hooks/configuration"}`: true,
		`{"jsonrpc":"2.0","id":1,"method":"hooks/capabilities"}`:    true,
		`{"jsonrpc":"2.0","method":"hooks/intercept"}`:              false,
		`{"jsonrpc":"2.0","id":null,"method":"hooks/intercept"}`:    false,
		`{"jsonrpc":"2.0","method":"hooks/observe"}`:                false,
		`{"jsonrpc":"2.0","id":1,"method":"compaction/run"}`:        false,
		`not json`: false,
	} {
		if replayable([]byte(body)) != want {
			t.Errorf("replayable(%s) != %v", body, want)
		}
	}
}
