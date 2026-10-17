package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
)

func forbiddenHeaderAuth(t *testing.T) auth.Provider {
	return clientAuthProvider{
		credential: func(context.Context, auth.Request) (auth.Credential, error) {
			t.Error("explicit Authorization acquired credentials")
			return auth.Credential{}, nil
		},
		challenge: func(context.Context, auth.Request, auth.Challenge) (*auth.Credential, error) {
			t.Error("explicit Authorization triggered challenge/discovery")
			return nil, nil
		},
	}
}

func TestRegistrationHeadersOverrideAndSuppressOAuth(t *testing.T) {
	for _, source := range []string{`"Bearer abc123"`, `{"valueEnv":"HEADER_AUTHORIZATION"}`, `{"valueRef":"header-auth"}`} {
		t.Run(source, func(t *testing.T) {
			t.Setenv("HEADER_AUTHORIZATION", "Bearer abc123")
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				for key, want := range map[string]string{"Authorization": "Bearer abc123", "Content-Type": "text/plain", "X-Api-Key": "literal-api-key", "Cookie": "session=literal-cookie", "Origin": "https://example.com", "X-Unicode": "café", "X-Tab": "one\ttwo", "AHP-Test": "override"} {
					if r.Header.Get(key) != want {
						t.Errorf("incorrect %s header", key)
					}
				}
				w.WriteHeader(401)
			}))
			defer srv.Close()
			tr := headerBackend(t, srv.URL, `{"aUtHoRiZaTiOn":`+source+`,"Content-Type":"text/plain","X-Api-Key":"literal-api-key","Cookie":"session=literal-cookie","Origin":"https://example.com","X-Unicode":"café","X-Tab":"one\ttwo","AHP-Test":"override"}`, srv.Client())
			tr.authRequest = &auth.Request{Destination: srv.URL, Purpose: auth.Event, Binding: json.RawMessage(`{"type":"oauth","flow":"client_credentials"}`)}
			tr.provider = forbiddenHeaderAuth(t)
			tr.headerResolver = func(context.Context, HeaderRequest) (string, error) { return "Bearer abc123", nil }
			if _, err := tr.Exchange(context.Background(), []byte(`{}`), false); err == nil {
				t.Error("expected unsuccessful status")
			}
			if calls != 1 {
				t.Fatalf("requests=%d", calls)
			}
		})
	}
}

func TestRegistrationHeadersAuthorizationFailureDoesNotFallBack(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(204) }))
	defer srv.Close()
	tr := headerBackend(t, srv.URL, `{"Authorization":{"valueRef":"missing"}}`, srv.Client())
	tr.authRequest = &auth.Request{Destination: srv.URL, Purpose: auth.Event, Binding: json.RawMessage(`{"type":"oauth","flow":"client_credentials"}`)}
	tr.provider = forbiddenHeaderAuth(t)
	if _, err := tr.Exchange(context.Background(), nil, false); err == nil {
		t.Error("missing explicit authorization accepted")
	}
	if requests != 0 {
		t.Error("failed explicit authorization sent a request")
	}
}

func TestRegistrationHeaderDuplicatesLastWins(t *testing.T) {
	for _, raw := range []string{`{"X-Key":"first","x-key":"last"}`, `{"x-key":"first","X-Key":"last"}`, `{"X-Key":"first","X-Key":"last"}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Values("X-Key"); len(got) != 1 || got[0] != "last" {
				t.Errorf("duplicate values: %v", got)
			}
			w.WriteHeader(204)
		}))
		tr := headerBackend(t, srv.URL, raw, srv.Client())
		if _, err := tr.Exchange(context.Background(), nil, true); err != nil {
			t.Fatal(err)
		}
		srv.Close()
	}
}

func TestRegistrationHeadersApplyToBackendUploads(t *testing.T) {
	for _, explicitAuth := range []bool{false, true} {
		t.Run(map[bool]string{false: "auth-default", true: "explicit-auth"}[explicitAuth], func(t *testing.T) {
			requests, resolutions := 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.URL.Path != "/upload" {
					t.Error("wrong upload path")
				}
				for key, want := range map[string]string{"X-Upload-Secret": "resolved", "Content-Type": "application/custom", "AHP-Content-SHA256": "configured"} {
					if r.Header.Get(key) != want {
						t.Errorf("missing upload override %s", key)
					}
				}
				wantAuth := "Bearer initial"
				if explicitAuth {
					wantAuth = "Bearer abc123"
				}
				if r.Header.Get("Authorization") != wantAuth {
					t.Error("incorrect upload authorization")
				}
				w.WriteHeader(401)
			}))
			defer srv.Close()
			raw := `{"X-Upload-Secret":{"valueRef":"upload-secret"},"Content-Type":"application/custom","AHP-Content-SHA256":"configured"`
			if explicitAuth {
				raw += `,"Authorization":"Bearer abc123"`
			}
			raw += `}`
			tr := headerBackend(t, srv.URL+"/events", raw, srv.Client())
			provider := auth.Provider(headerRetryProvider{})
			if explicitAuth {
				provider = forbiddenHeaderAuth(t)
			}
			hooks := &Hooks{opts: Options{UploadClient: srv.Client(), AuthProvider: provider, Content: ContentOptions{AllowLoopbackHTTP: true}, HeaderResolver: func(ctx context.Context, r HeaderRequest) (string, error) {
				resolutions++
				if r.BackendID != "com.example.upload" || r.Destination != srv.URL+"/upload" || r.Purpose != auth.Upload || r.ValueRef != "upload-secret" {
					t.Error("incorrect upload resolver scope")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Error("missing upload deadline")
				}
				return "resolved", nil
			}}, backends: []registeredBackend{{id: "com.example.upload", transport: tr}}}
			config := map[string]any{"endpoint": srv.URL + "/upload", "timeoutMs": 1000, "auth": map[string]any{"type": "oauth", "flow": "client_credentials"}}
			if _, err := hooks.uploadContent(context.Background(), config, []byte("payload"), "com.example.upload"); err == nil {
				t.Error("expected unsuccessful upload status")
			}
			if requests != 1 || resolutions != 1 {
				t.Fatalf("requests=%d resolutions=%d", requests, resolutions)
			}
		})
	}
}

func TestRegistrationHeaderNamesNotReserved(t *testing.T) {
	for _, name := range []string{"Authorization", "Proxy-Test", "Cookie", "Set-Cookie", "Host", "Content-Type", "Accept", "Content-Length", "Content-Encoding", "Connection", "Keep-Alive", "Transfer-Encoding", "TE", "Trailer", "Upgrade", "Expect", "Origin", "Referer", "Sec-Test", "AHP-Test"} {
		cfg := &ahp.HttpTransport{Type: ahp.HttpTransportTypeHTTP, URL: "http://localhost", AdditionalProperties: map[string]json.RawMessage{"headers": json.RawMessage(`{"` + name + `":"value"}`)}}
		if _, err := registrationHeaders(cfg); err != nil {
			t.Errorf("valid field %s rejected", name)
		}
	}
}
