package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func goodToken(context.Context, TokenRequest) (Token, error) {
	return Token{Value: "secret", Audience: "receiver", Scopes: []string{"send"}, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func testScope() Scope {
	return Scope{Endpoint: "https://receiver.example/hooks?binding=1", Audience: "receiver", Scopes: []string{"send"}}
}
func response() *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody}
}

func TestCloneAndConcurrentUse(t *testing.T) {
	scope := testScope()
	var calls atomic.Int32
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if got := r.Header.Values("Authorization"); len(got) != 1 || got[0] != "Bearer secret" {
			t.Errorf("wrong authorization")
		}
		if _, ok := r.Header["authorization"]; ok {
			t.Error("duplicate casing")
		}
		r.Header.Set("X-Mutated", "true")
		return response(), nil
	})
	tr, err := NewEventTransport(base, scope, func(ctx context.Context, r TokenRequest) (Token, error) {
		if r.Operation != Event || r.Scopes[0] != "send" || r.Endpoint != testScope().Endpoint {
			t.Error("incorrect binding")
		}
		r.Scopes[0] = "mutated"
		return goodToken(ctx, r)
	})
	if err != nil {
		t.Fatal(err)
	}
	scope.Scopes[0] = "changed after construction"
	req, _ := http.NewRequest("POST", scope.Endpoint, nil)
	req.Header["authorization"] = []string{"old"}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := tr.RoundTrip(req)
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 32 || req.Header.Get("X-Mutated") != "" || req.Header["authorization"][0] != "old" {
		t.Fatal("request mutated or missing calls")
	}
}

func TestExactRequestScope(t *testing.T) {
	var calls atomic.Int32
	tr, err := NewEventTransport(roundTripFunc(func(*http.Request) (*http.Response, error) { calls.Add(1); return response(), nil }), testScope(), func(ctx context.Context, r TokenRequest) (Token, error) { calls.Add(1); return goodToken(ctx, r) })
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		change func(*http.Request)
	}{
		{"origin", func(r *http.Request) { r.URL.Host = "other.example" }},
		{"port", func(r *http.Request) { r.URL.Host += ":443" }},
		{"route", func(r *http.Request) { r.URL.Path = "/uploads" }},
		{"encoded route", func(r *http.Request) { r.URL.RawPath = "/%68ooks" }},
		{"query", func(r *http.Request) { r.URL.RawQuery = "binding=2" }},
		{"method", func(r *http.Request) { r.Method = "GET" }},
		{"host override", func(r *http.Request) { r.Host = "other.example" }},
		{"redirect", func(r *http.Request) { r.Response = response() }},
		{"downgrade", func(r *http.Request) { r.URL.Scheme = "http" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("POST", testScope().Endpoint, nil)
			tt.change(r)
			if _, err := tr.RoundTrip(r); err != ErrScope {
				t.Fatalf("got %v", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized request reached provider/base")
	}
}

func TestCredentialFailuresAreRedacted(t *testing.T) {
	for _, kind := range []string{"provider", "audience", "scope", "expiry", "value", "empty"} {
		t.Run(kind, func(t *testing.T) {
			tr, _ := NewUploadTransport(roundTripFunc(func(*http.Request) (*http.Response, error) { t.Error("base called"); return response(), nil }), testScope(), func(ctx context.Context, r TokenRequest) (Token, error) {
				if r.Operation != Upload {
					t.Error("upload operation missing")
				}
				tok, _ := goodToken(ctx, r)
				switch kind {
				case "provider":
					return Token{}, errors.New("secret")
				case "audience":
					tok.Audience = "other"
				case "scope":
					tok.Scopes = nil
				case "expiry":
					tok.ExpiresAt = time.Now().Add(-time.Second)
				case "value":
					tok.Value = "secret\r\nX: secret"
				case "empty":
					tok.Value = ""
				}
				return tok, nil
			})
			r, _ := http.NewRequest("POST", testScope().Endpoint, nil)
			_, err := tr.RoundTrip(r)
			if err != ErrCredential || strings.Contains(err.Error(), "secret") || errors.Unwrap(err) != nil {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
	tr, _ := NewEventTransport(roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("secret") }), testScope(), goodToken)
	r, _ := http.NewRequest("POST", testScope().Endpoint, nil)
	if _, err := tr.RoundTrip(r); err != ErrTransport {
		t.Fatal(err)
	}
}

func TestRedirectsNeverForwardCustomCredential(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var received atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
			defer target.Close()
			var first atomic.Int32
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				first.Add(1)
				if r.Header.Get("X-Secret") != "secret" {
					t.Error("missing credential")
				}
				http.Redirect(w, r, target.URL+"/upload", status)
			}))
			defer source.Close()
			scope := testScope()
			scope.Endpoint = source.URL + "/upload"
			scope.Header = "X-Secret"
			scope.AllowLocalHTTP = true
			tr, err := NewUploadTransport(nil, scope, goodToken)
			if err != nil {
				t.Fatal(err)
			}
			c := &http.Client{Transport: tr}
			req, _ := http.NewRequest("POST", scope.Endpoint, strings.NewReader("body"))
			req.Header.Set("X-Secret", "original-sensitive-header")
			resp, err := c.Do(req)
			if resp != nil {
				resp.Body.Close()
			}
			if !errors.Is(err, ErrScope) || first.Load() != 1 || received.Load() != 0 {
				t.Fatalf("redirect was not blocked: %v", err)
			}
		})
	}
}

type closeBody struct{ closed bool }

func (*closeBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *closeBody) Close() error           { b.closed = true; return nil }
func TestRejectedBodyClosedWithoutReading(t *testing.T) {
	tr, _ := NewEventTransport(nil, testScope(), goodToken)
	b := &closeBody{}
	r, _ := http.NewRequest("GET", testScope().Endpoint, b)
	_, _ = tr.RoundTrip(r)
	if !b.closed {
		t.Fatal("body not closed")
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, endpoint := range []string{"", "http://receiver.example/hooks", "http://127.0.0.1/hooks", "https://user:secret@receiver.example/hooks", "https://receiver.example/hooks#", "/hooks"} {
		s := testScope()
		s.Endpoint = endpoint
		if _, err := NewEventTransport(nil, s, goodToken); err != ErrConfig {
			t.Errorf("accepted %q", endpoint)
		}
	}
	for _, h := range []string{"Host", "Content-Length", "Connection", "X-Bad\r\n"} {
		s := testScope()
		s.Header = h
		if _, err := NewEventTransport(nil, s, goodToken); err != ErrConfig {
			t.Error("accepted unsafe header")
		}
	}
	s := testScope()
	s.Endpoint = "http://receiver.example/hooks"
	s.AllowLocalHTTP = true
	if _, err := NewEventTransport(nil, s, goodToken); err != ErrConfig {
		t.Error("allowed remote cleartext")
	}
	if _, err := NewEventTransport(nil, testScope(), nil); err != ErrConfig {
		t.Error("accepted nil provider")
	}
}

func TestSameEndpointRedirectIsRejected(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "/hooks")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	scope := testScope()
	scope.Endpoint = s.URL + "/hooks"
	scope.AllowLocalHTTP = true
	tr, err := NewEventTransport(nil, scope, goodToken)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", scope.Endpoint, nil)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, ErrScope) || calls.Load() != 1 {
		t.Fatalf("same-endpoint redirect not blocked: %v", err)
	}
}

func TestEventAndUploadCredentialsAreIndependent(t *testing.T) {
	for _, op := range []Operation{Event, Upload} {
		t.Run(string(op), func(t *testing.T) {
			s := testScope()
			s.Endpoint = "https://receiver.example/" + string(op)
			base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "Bearer "+string(op) {
					t.Error("wrong operation credential")
				}
				return response(), nil
			})
			provider := func(ctx context.Context, r TokenRequest) (Token, error) {
				if r.Operation != op {
					t.Error("incorrect operation")
				}
				tok, _ := goodToken(ctx, r)
				tok.Value = string(op)
				return tok, nil
			}
			constructor := NewEventTransport
			if op == Upload {
				constructor = NewUploadTransport
			}
			tr, err := constructor(base, s, provider)
			if err != nil {
				t.Fatal(err)
			}
			r, _ := http.NewRequest("POST", s.Endpoint, nil)
			if _, err := tr.RoundTrip(r); err != nil {
				t.Fatal(err)
			}
			r.URL.Path = "/other"
			if _, err := tr.RoundTrip(r); err != ErrScope {
				t.Fatal("accepted other endpoint")
			}
		})
	}
}

func TestCancellationErrorsPreserveOnlySafeIdentity(t *testing.T) {
	secret := errors.New("secret credential detail")
	for _, safe := range []error{context.Canceled, context.DeadlineExceeded} {
		for _, stage := range []string{"provider", "transport"} {
			t.Run(stage+"/"+safe.Error(), func(t *testing.T) {
				source := errors.Join(secret, safe)
				provider := goodToken
				want := ErrTransport
				base := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, source })
				if stage == "provider" {
					want = ErrCredential
					provider = func(context.Context, TokenRequest) (Token, error) { return Token{}, source }
					base = func(*http.Request) (*http.Response, error) {
						t.Error("base called after provider failure")
						return response(), nil
					}
				}
				tr, _ := NewEventTransport(base, testScope(), provider)
				r, _ := http.NewRequest("POST", testScope().Endpoint, nil)
				_, err := tr.RoundTrip(r)
				if !errors.Is(err, safe) || !errors.Is(err, want) {
					t.Fatalf("lost safe identity: %v", err)
				}
				if errors.Is(err, secret) || errors.Is(err, source) || strings.Contains(err.Error(), "secret") {
					t.Fatalf("exposed source error: %v", err)
				}
			})
		}
	}
}

func TestCanceledRequestNeverCallsDependencies(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		var ctx context.Context
		var cancel context.CancelFunc
		want := context.Canceled
		if deadline {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			want = context.DeadlineExceeded
		} else {
			ctx, cancel = context.WithCancel(context.Background())
		}
		cancel()
		tr, _ := NewEventTransport(roundTripFunc(func(*http.Request) (*http.Response, error) { t.Error("base called"); return response(), nil }), testScope(), func(context.Context, TokenRequest) (Token, error) { t.Error("provider called"); return Token{}, nil })
		body := &closeBody{}
		r, _ := http.NewRequestWithContext(ctx, "POST", testScope().Endpoint, body)
		_, err := tr.RoundTrip(r)
		if !errors.Is(err, want) || !body.closed {
			t.Fatalf("cancellation/ownership not honored: %v", err)
		}
	}
}

func TestProviderCancellationPreventsBaseCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr, _ := NewEventTransport(roundTripFunc(func(*http.Request) (*http.Response, error) { t.Error("base called"); return response(), nil }), testScope(), func(ctx context.Context, r TokenRequest) (Token, error) { cancel(); return goodToken(ctx, r) })
	r, _ := http.NewRequestWithContext(ctx, "POST", testScope().Endpoint, nil)
	_, err := tr.RoundTrip(r)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
