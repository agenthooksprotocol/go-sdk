package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
)

func TestTransportHelper(t *testing.T) {
	mode := ""
	for _, a := range os.Args {
		if strings.HasPrefix(a, "ahp-helper=") {
			mode = strings.TrimPrefix(a, "ahp-helper=")
		}
	}
	if mode == "" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		json.Unmarshal(scanner.Bytes(), &req)
		if mode == "hang" {
			time.Sleep(time.Minute)
			continue
		}
		if len(req.ID) == 0 {
			if mode == "stray" {
				fmt.Println(`{"id":"wrong","result":{}}`)
			}
			continue
		}
		if mode == "oversize" {
			fmt.Println(strings.Repeat("x", maxTransportMessage+1))
			continue
		}
		fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{}}\n", req.ID)
	}
	os.Exit(0)
}
func stdioForTest(t *testing.T, mode string, lifecycle ahp.StdioTransportLifecycle) backendTransport {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tr, err := newBackendTransport(&ahp.Backend{Transport: ahp.BackendTransport{StdioTransport: ahp.Some(&ahp.StdioTransport{Type: ahp.StdioTransportTypeStdio, Command: exe, Args: ahp.Some([]string{"-test.run=^TestTransportHelper$", "--", "ahp-helper=" + mode}), Lifecycle: lifecycle})}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })
	return tr
}
func TestStdioTransportLifecycles(t *testing.T) {
	for _, life := range []ahp.StdioTransportLifecycle{ahp.StdioTransportLifecyclePersistent, ahp.StdioTransportLifecyclePerEvent} {
		t.Run(string(life), func(t *testing.T) {
			tr := stdioForTest(t, "echo", life)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := tr.Exchange(ctx, []byte(`{"jsonrpc":"2.0","method":"notify"}`), true); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if _, err := tr.Exchange(ctx, []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"request"}`, i)), false); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
func TestStdioTransportCancellation(t *testing.T) {
	tr := stdioForTest(t, "hang", ahp.StdioTransportLifecyclePersistent)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := tr.Exchange(ctx, []byte(`{"id":1}`), false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	s := tr.(*stdioBackend)
	s.mu.Lock()
	n := len(s.processes)
	s.mu.Unlock()
	if n != 0 {
		t.Fatal("child retained")
	}
}
func TestStdioTransportRejectsStrayAndOversize(t *testing.T) {
	for _, mode := range []string{"stray", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			tr := stdioForTest(t, mode, ahp.StdioTransportLifecyclePersistent)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if mode == "stray" {
				if _, err := tr.Exchange(ctx, []byte(`{"method":"notify"}`), true); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tr.Exchange(ctx, []byte(`{"id":1}`), false); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
}
func TestStdioTransportCloseUnblocks(t *testing.T) {
	tr := stdioForTest(t, "hang", ahp.StdioTransportLifecyclePersistent)
	done := make(chan error, 1)
	go func() { _, err := tr.Exchange(context.Background(), []byte(`{"id":1}`), false); done <- err }()
	time.Sleep(30 * time.Millisecond)
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("exchange succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("exchange leaked")
	}
}
func TestHTTPTransportCanonicalPost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/registered" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("incorrect HTTP binding")
		}
		b, _ := io.ReadAll(r.Body)
		if bytes.Contains(b, []byte("notify")) {
			w.WriteHeader(204)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":1,"result":{}}`)
	}))
	defer srv.Close()
	tr, err := newBackendTransport(&ahp.Backend{Transport: ahp.BackendTransport{HttpTransport: ahp.Some(&ahp.HttpTransport{Type: ahp.HttpTransportTypeHTTP, URL: srv.URL + "/registered"})}}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	for _, notify := range []bool{false, true} {
		body := []byte(`{"id":1}`)
		if notify {
			body = []byte(`{"method":"notify"}`)
		}
		if _, err := tr.Exchange(context.Background(), body, notify); err != nil {
			t.Fatal(err)
		}
	}
}
func TestHTTPTransportBoundsRedirectsAndRedaction(t *testing.T) {
	for _, mode := range []string{"redirect", "oversize", "status"} {
		t.Run(mode, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					w.Header().Set("Location", "/secret")
					w.WriteHeader(302)
				case "oversize":
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, strings.Repeat("x", maxTransportMessage+1))
				case "status":
					w.WriteHeader(403)
					fmt.Fprint(w, "secret")
				}
			}))
			defer srv.Close()
			tr, err := newBackendTransport(&ahp.Backend{Transport: ahp.BackendTransport{HttpTransport: ahp.Some(&ahp.HttpTransport{Type: ahp.HttpTransportTypeHTTP, URL: srv.URL})}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tr.Close()
			if _, err := tr.Exchange(context.Background(), []byte(`{"id":1}`), false); err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("got %v", err)
			}
		})
	}
}
func TestTransportAuthenticationFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unauthenticated delivery") }))
	defer srv.Close()
	tr, err := newBackendTransport(&ahp.Backend{Authentication: ahp.Some(&ahp.Authentication{}), Transport: ahp.BackendTransport{HttpTransport: ahp.Some(&ahp.HttpTransport{Type: ahp.HttpTransportTypeHTTP, URL: srv.URL})}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if _, err := tr.Exchange(context.Background(), []byte(`{"id":1}`), false); err == nil {
		t.Fatal("authentication ignored")
	}
}
func TestTransportBearerResolvedAtExchange(t *testing.T) {
	t.Setenv("AHP_TRANSPORT_TEST_TOKEN", "")
	var authentication ahp.Authentication
	if err := json.Unmarshal([]byte(`{"type":"bearer","tokenEnv":"AHP_TRANSPORT_TEST_TOKEN"}`), &authentication); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fresh-token" {
			t.Error("wrong credential")
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	tr, err := newBackendTransport(&ahp.Backend{Authentication: ahp.Some(&authentication), Transport: ahp.BackendTransport{HttpTransport: ahp.Some(&ahp.HttpTransport{Type: ahp.HttpTransportTypeHTTP, URL: srv.URL})}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if _, err := tr.Exchange(context.Background(), []byte(`{"method":"notify"}`), true); err == nil {
		t.Fatal("missing credential accepted")
	}
	t.Setenv("AHP_TRANSPORT_TEST_TOKEN", "fresh-token")
	if _, err := tr.Exchange(context.Background(), []byte(`{"method":"notify"}`), true); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPTransportSerializesAndCancelsQueuedWork(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	tr, err := newBackendTransport(&ahp.Backend{Transport: ahp.BackendTransport{HttpTransport: ahp.Some(&ahp.HttpTransport{Type: ahp.HttpTransportTypeHTTP, URL: srv.URL})}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	first := make(chan error, 1)
	go func() { _, err := tr.Exchange(context.Background(), []byte(`{"method":"notify"}`), true); first <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := tr.Exchange(ctx, []byte(`{"method":"notify"}`), true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued request: %v", err)
	}
	select {
	case <-entered:
		t.Error("concurrent backend request")
	default:
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestStdioTransportQueueCancellationAndLazyStart(t *testing.T) {
	tr := stdioForTest(t, "hang", ahp.StdioTransportLifecyclePersistent)
	s := tr.(*stdioBackend)
	if len(s.processes) != 0 {
		t.Fatal("backend started eagerly")
	}
	s.gate <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := tr.Exchange(ctx, []byte(`{"id":1}`), false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued exchange: %v", err)
	}
	<-s.gate
	if len(s.processes) != 0 {
		t.Fatal("cancelled queue started backend")
	}
}

func resolverTestBackend(t *testing.T, endpoint string) *ahp.Backend {
	t.Helper()
	var backend ahp.Backend
	raw := fmt.Sprintf(`{"id":"com.example.auth","transport":{"type":"http","url":%q},"authentication":{"type":"oauth","issuer":"https://issuer.example","resource":"https://resource.example","clientId":"client","flow":"client_credentials","scopes":["intercept"]},"subscriptions":[]}`, endpoint)
	if err := json.Unmarshal([]byte(raw), &backend); err != nil {
		t.Fatal(err)
	}
	return &backend
}

func TestEventResolverOAuthScopeAndDetachedSnapshot(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/registered" || r.Header.Get("Authorization") != "Bearer scoped-token" {
			t.Error("incorrect authenticated delivery")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	endpoint := srv.URL + "/registered"
	wrapped, err := auth.NewEventTransport(srv.Client().Transport, auth.Scope{Endpoint: endpoint, Audience: "https://resource.example", Scopes: []string{"intercept"}, AllowLocalHTTP: true}, func(ctx context.Context, req auth.TokenRequest) (auth.Token, error) {
		if req.Operation != auth.Event || req.Endpoint != endpoint || req.Audience != "https://resource.example" {
			t.Error("wrong credential scope")
		}
		return auth.Token{Value: "scoped-token", Audience: req.Audience, Scopes: req.Scopes, ExpiresAt: time.Now().Add(time.Minute)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	supplied := &http.Client{Transport: wrapped}
	original := resolverTestBackend(t, endpoint)
	resolver := func(ctx context.Context, b *ahp.Backend) (*http.Client, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("resolver missing delivery deadline")
		}
		if b.Transport.HttpTransport.Value.URL != endpoint || b.Authentication.Value.Oauth.Value.Scopes.Value[0] != "intercept" {
			t.Error("resolver snapshot mutated")
		}
		b.Transport.HttpTransport.Value.URL = "https://untrusted.example"
		b.Authentication.Value.Oauth.Value.Scopes.Value[0] = "changed"
		return supplied, nil
	}
	tr, err := newBackendTransport(original, nil, resolver)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if calls != 0 {
		t.Fatal("resolved during construction")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		if _, err := tr.Exchange(ctx, []byte(`{"method":"notify"}`), true); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatal("resolver not called for each delivery")
	}
	if original.Transport.HttpTransport.Value.URL != endpoint || original.Authentication.Value.Oauth.Value.Scopes.Value[0] != "intercept" {
		t.Fatal("original backend mutated")
	}
	if supplied.CheckRedirect != nil {
		t.Fatal("supplied HTTP client mutated")
	}
	// The caller's scope-checking transport also rejects accidental upload reuse.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/upload", nil)
	if _, err := supplied.Do(req); err == nil {
		t.Fatal("event credential accepted outside registered scope")
	}
}

func TestEventResolverFailuresApplyPolicyWithoutFallback(t *testing.T) {
	for _, policy := range []string{"fail-open", "fail-closed"} {
		for _, failure := range []string{"error", "nil"} {
			t.Run(policy+"/"+failure, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unauthenticated fallback delivery") }))
				defer srv.Close()
				c, _ := testClient(t, policy)
				tr, err := newBackendTransport(resolverTestBackend(t, srv.URL), srv.Client(), func(context.Context, *ahp.Backend) (*http.Client, error) {
					if failure == "nil" {
						return nil, nil
					}
					return srv.Client(), errors.New("private-token-secret")
				})
				if err != nil {
					t.Fatal(err)
				}
				c.backends[0].transport = tr
				result, err := c.intercept(context.Background(), "tool.before", testInput())
				if err != nil {
					t.Fatal(err)
				}
				if len(result.Errors) != 1 || result.Errors[0].FailClosed != (policy == "fail-closed") {
					t.Fatalf("failure policy not applied: %+v", result.Errors)
				}
				if strings.Contains(result.Errors[0].Error(), "private-token-secret") {
					t.Fatal("resolver error leaked")
				}
				if (result.State.Permission == "deny") != (policy == "fail-closed") {
					t.Fatalf("unexpected permission %s", result.State.Permission)
				}
			})
		}
	}
}

func TestEventResolverHonorsCancellation(t *testing.T) {
	tr, err := newBackendTransport(resolverTestBackend(t, "http://127.0.0.1/registered"), nil, func(ctx context.Context, _ *ahp.Backend) (*http.Client, error) {
		<-ctx.Done()
		return nil, errors.New("private-token-secret")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := tr.Exchange(ctx, []byte(`{"method":"notify"}`), true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}
