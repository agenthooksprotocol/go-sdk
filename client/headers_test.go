package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
)

func headerBackend(t *testing.T, endpoint, headers string, client *http.Client) *httpBackend {
	t.Helper()
	cfg := &ahp.HttpTransport{Type: ahp.HttpTransportTypeHTTP, URL: endpoint, AdditionalProperties: map[string]json.RawMessage{"headers": json.RawMessage(headers)}}
	tr, err := newBackendTransport(&ahp.Backend{Transport: ahp.BackendTransport{HttpTransport: ahp.Some(cfg)}}, client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })
	return tr.(*httpBackend)
}

func TestRegistrationHeadersEmittedAndRotated(t *testing.T) {
	var received []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = append(received, r.Header.Clone())
		w.WriteHeader(204)
	}))
	defer srv.Close()
	tr := headerBackend(t, srv.URL+"/events", `{"X-Metadata":" ${LITERAL} ","X-Empty":"","X-Env":{"valueEnv":"AHP_HEADER_TEST"},"X-Ref":{"valueRef":"secret-id"}}`, srv.Client())
	tr.backendID = "test.backend"
	calls := 0
	tr.headerResolver = func(ctx context.Context, r HeaderRequest) (string, error) {
		calls++
		if r.BackendID != "test.backend" || r.Destination != srv.URL+"/events" || r.Purpose != auth.Event || r.ValueRef != "secret-id" {
			t.Error("incorrect resolution scope")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Error("missing deadline")
		}
		return "ref-value", nil
	}
	for _, v := range []string{"first", "rotated"} {
		t.Setenv("AHP_HEADER_TEST", v)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := tr.Exchange(ctx, []byte(`{}`), true)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 || len(received) != 2 {
		t.Fatalf("calls=%d requests=%d", calls, len(received))
	}
	for i, h := range received {
		// net/http trims wire whitespace; the pre-wire value is tested below.
		if h.Get("X-Metadata") != "${LITERAL}" || h.Get("X-Ref") != "ref-value" || h.Get("Content-Type") != "application/json" || h.Get("Authorization") != "" {
			t.Errorf("incorrect headers at request %d", i)
		}
	}
	if received[0].Get("X-Env") != "first" || received[1].Get("X-Env") != "rotated" {
		t.Error("environment was not rotated")
	}
	isolated := headerBackend(t, srv.URL+"/other", `{}`, srv.Client())
	if _, err := isolated.Exchange(context.Background(), []byte(`{}`), true); err != nil {
		t.Fatal(err)
	}
	if received[2].Get("X-Ref") != "" {
		t.Error("headers leaked to another backend")
	}
}

func TestRegistrationHeadersPublicRegistration(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-Secret") != "resolved" {
			t.Error("missing resolved public header")
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	reg := ahp.ParseRegistration(sdkJSON(map[string]any{"protocolVersion": "draft", "hooks": []any{map[string]any{
		"id": "com.example.headers", "transport": map[string]any{"type": "http", "url": srv.URL, "headers": map[string]any{"X-Secret": map[string]any{"valueRef": "secret"}}},
		"subscriptions": []any{map[string]any{"events": []any{"tool.before"}, "mode": "intercept", "timeoutMs": 1000, "failurePolicy": "fail-closed", "content": map[string]any{"default": "metadata"}}},
	}}}))
	if !reg.OK {
		t.Fatal(reg.Diagnostics)
	}
	cfg := reg.Value.Hooks[0].Transport.HttpTransport.Value
	if !cfg.Headers.Present || !cfg.Headers.Value["X-Secret"].HttpHeaderSource.Present {
		t.Fatal("missing generated header projection")
	}
	c, err := New(reg.Value, Options{Harness: ahp.Harness{Name: "test", Version: "1"}, Source: "urn:test:host", Events: testHost(), Metadata: testManifestMetadata(), EventClient: srv.Client(), HeaderResolver: func(ctx context.Context, r HeaderRequest) (string, error) {
		if r.BackendID != "com.example.headers" || r.Destination != srv.URL || r.Purpose != auth.Event {
			t.Error("incorrect public resolver scope")
		}
		return "resolved", nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.backends[0].transport.Exchange(context.Background(), []byte(`{}`), true); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("requests=%d", calls)
	}
}

func TestRegistrationHeadersInvalid(t *testing.T) {
	invalid := []string{`null`, `[]`, `{"Bad Name":"x"}`, `{"é":"x"}`, `{"X":"a","x":"a"}`, `{"X":"a","X":"b"}`, `{"X":null}`, `{"X":1}`, `{"X":[]}`, `{"X":"\t"}`, `{"X":"\r\n"}`, `{"X":"é"}`, `{"X":"\u007f"}`, `{"X":{}}`, `{"X":{"valueEnv":""}}`, `{"X":{"valueEnv":"BAD-NAME"}}`, `{"X":{"valueRef":""}}`, `{"X":{"valueEnv":"OK","valueRef":"ref"}}`}
	for _, name := range []string{"Authorization", "Proxy-Test", "Cookie", "Set-Cookie", "Host", "Content-Type", "Accept", "Content-Length", "Content-Encoding", "Connection", "Keep-Alive", "Transfer-Encoding", "TE", "Trailer", "Upgrade", "Expect", "Origin", "Referer", "Sec-Test", "AHP-Test"} {
		invalid = append(invalid, `{"`+strings.ToUpper(name)+`":"sensitive"}`)
	}
	for _, raw := range invalid {
		cfg := &ahp.HttpTransport{Type: ahp.HttpTransportTypeHTTP, URL: "http://localhost/events", AdditionalProperties: map[string]json.RawMessage{"headers": json.RawMessage(raw)}}
		if _, err := registrationHeaders(cfg); err == nil {
			t.Errorf("accepted invalid config %s", raw)
		} else if strings.Contains(err.Error(), "sensitive") {
			t.Error("value leaked")
		}
	}
}

func TestRegistrationHeadersFailClosed(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(204) }))
	defer srv.Close()
	for _, value := range []string{"", "bad\nvalue", "é", strings.Repeat("x", maxRegistrationHeaders)} {
		tr := headerBackend(t, srv.URL, `{"X":{"valueRef":"private-reference"}}`, srv.Client())
		tr.headerResolver = func(context.Context, HeaderRequest) (string, error) { return value, nil }
		if _, err := tr.Exchange(context.Background(), []byte(`{}`), true); err == nil {
			t.Error("accepted invalid resolved value")
		}
	}
	tr := headerBackend(t, srv.URL, `{"X":{"valueRef":"private-reference"}}`, srv.Client())
	if _, err := tr.Exchange(context.Background(), nil, true); err == nil {
		t.Error("missing resolver accepted")
	}
	tr.headerResolver = func(context.Context, HeaderRequest) (string, error) {
		return "", errors.New("private-reference secret")
	}
	if _, err := tr.Exchange(context.Background(), nil, true); err == nil || strings.Contains(err.Error(), "secret") {
		t.Error("resolution error not redacted")
	}
	tr.headerResolver = func(ctx context.Context, _ HeaderRequest) (string, error) { <-ctx.Done(); return "", ctx.Err() }
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := tr.Exchange(ctx, nil, true); err == nil {
		t.Error("cancelled resolver accepted")
	}
	t.Setenv("AHP_HEADER_EMPTY", "")
	env := headerBackend(t, srv.URL, `{"X":{"valueEnv":"AHP_HEADER_EMPTY"}}`, srv.Client())
	if _, err := env.Exchange(context.Background(), nil, true); err == nil {
		t.Error("empty environment accepted")
	}
	if requests != 0 {
		t.Fatalf("sent %d requests after failure", requests)
	}
}

type headerRetryProvider struct{}

func (headerRetryProvider) Credential(context.Context, auth.Request) (auth.Credential, error) {
	return auth.Credential{Type: "bearer", Token: "initial"}, nil
}
func (headerRetryProvider) Challenge(context.Context, auth.Request, auth.Challenge) (*auth.Credential, error) {
	return &auth.Credential{Type: "bearer", Token: "refreshed"}, nil
}

func TestRegistrationHeadersAuthRetryReusesResolution(t *testing.T) {
	requests, resolutions := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("X-Secret") != "resolved" {
			t.Error("missing configured header")
		}
		if requests == 1 {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("Authorization") != "Bearer refreshed" {
			t.Error("auth did not own authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":1,"result":{}}`))
	}))
	defer srv.Close()
	tr := headerBackend(t, srv.URL, `{"X-Secret":{"valueRef":"secret"}}`, srv.Client())
	tr.authRequest = &auth.Request{Destination: srv.URL, Purpose: auth.Event, Binding: json.RawMessage(`{"type":"bearer","tokenRef":"auth"}`)}
	tr.provider = headerRetryProvider{}
	tr.headerResolver = func(context.Context, HeaderRequest) (string, error) { resolutions++; return "resolved", nil }
	if _, err := tr.Exchange(context.Background(), []byte(`{"id":1}`), false); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || resolutions != 1 {
		t.Fatalf("requests=%d resolutions=%d", requests, resolutions)
	}
}

func TestRegistrationHeadersRedirectIsolation(t *testing.T) {
	targets := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targets++; w.WriteHeader(204) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events" {
			targets++
			w.WriteHeader(204)
			return
		}
		destination := target.URL
		if r.Header.Get("X-Route") == "same" {
			destination = "/other"
		}
		http.Redirect(w, r, destination, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
	for _, route := range []string{"same", "cross"} {
		tr := headerBackend(t, srv.URL+"/events", `{"X-Route":"`+route+`"}`, client)
		if _, err := tr.Exchange(context.Background(), []byte(`{}`), true); err == nil {
			t.Error("redirect accepted")
		}
	}
	if targets != 0 {
		t.Error("redirect leaked headers")
	}
}
