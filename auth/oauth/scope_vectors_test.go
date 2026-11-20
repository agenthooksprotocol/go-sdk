package oauth

// Native runners for the shared scope_decisions and completions vectors.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

type scopeVectors struct {
	ScopeDecisions []struct {
		ID       string   `json:"id"`
		Requires []string `json:"requires"`
		Input    struct {
			Flow         string   `json:"flow"`
			Path         string   `json:"path"`
			Binding      string   `json:"binding"`
			Requested    []string `json:"requested"`
			PresetScopes []string `json:"preset_scopes"`
			Ceiling      []string `json:"ceiling"`
			HostRequired []string `json:"host_required"`
			Explicit     []string `json:"explicit"`
			Granted      []string `json:"granted"`
			Challenge    *struct {
				Status          int    `json:"status"`
				WWWAuthenticate string `json:"www_authenticate"`
			} `json:"challenge"`
			HostError *struct {
				Callback string   `json:"callback"`
				Target   string   `json:"target"`
				Code     string   `json:"code"`
				Scopes   []string `json:"scopes"`
			} `json:"host_error"`
		} `json:"input"`
		Expect vectorExpect `json:"expect"`
	} `json:"scope_decisions"`
	Completions []struct {
		ID       string   `json:"id"`
		Requires []string `json:"requires"`
		Input    struct {
			Pending        string   `json:"pending"`
			Handle         string   `json:"handle"`
			ClientSource   string   `json:"client_source"`
			Callback       string   `json:"callback"`
			Exchange       string   `json:"exchange"`
			StoredRequired []string `json:"stored_required"`
			Granted        []string `json:"granted"`
			Ceiling        []string `json:"ceiling"`
			HostError      *struct {
				Callback string   `json:"callback"`
				Code     string   `json:"code"`
				Scopes   []string `json:"scopes"`
			} `json:"host_error"`
		} `json:"input"`
		Expect vectorExpect `json:"expect"`
	} `json:"completions"`
}

type vectorExpect struct {
	Code                        *string   `json:"code"`
	Scopes                      *[]string `json:"scopes"`
	Action                      string    `json:"action"`
	Required                    []string  `json:"required"`
	AcquisitionScopes           []string  `json:"acquisition_scopes"`
	NetworkCalls                *int32    `json:"network_calls"`
	AuthorizationServerRequests *int32    `json:"authorization_server_requests"`
	Retired                     *bool     `json:"retired"`
	LoginEnded                  *bool     `json:"login_ended"`
	GrantPersisted              *bool     `json:"grant_persisted"`
}

// goFeatures are the optional SDK features this SDK has. Go's Complete takes
// no pending-login handle: a callback names its login only by state.
var goFeatures = map[string]bool{"token_validation_callback": true, "complete_handle": false}

// requireFeatures skips a vector needing an optional feature Go lacks and
// fails on a feature this runner does not know.
func requireFeatures(t *testing.T, requires []string) {
	t.Helper()
	for _, feature := range requires {
		has, known := goFeatures[feature]
		if !known {
			t.Fatalf("unknown SDK feature %q", feature)
		}
		if !has {
			t.Skipf("requires %s, which the Go SDK does not have", feature)
		}
	}
}

func readScopeVectors(t *testing.T) scopeVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/sdk-auth-lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(data, &sections); err != nil {
		t.Fatal(err)
	}
	var vectors scopeVectors
	// Every field a vector defines is asserted: an unknown field fails.
	for name, target := range map[string]any{"scope_decisions": &vectors.ScopeDecisions, "completions": &vectors.Completions} {
		decoder := json.NewDecoder(bytes.NewReader(sections[name]))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(target); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if len(vectors.ScopeDecisions) == 0 || len(vectors.Completions) == 0 {
		t.Fatal("fixture has no scope or completion vectors")
	}
	return vectors
}

// vectorServer is a TLS protected resource and authorization server that
// counts every request. The token endpoint grants the requested scopes unless
// granted or a failure mode is set.
type vectorServer struct {
	server   *httptest.Server
	resource string
	// cimd advertises Client ID Metadata Document support.
	cimd bool

	mu      sync.Mutex
	granted []string
	mode    string
	scopes  [][]string

	prm, authorizationServer atomic.Int32
}

func newVectorServer(t *testing.T) *vectorServer {
	s := &vectorServer{}
	s.server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.server.Close)
	s.resource = s.server.URL + "/events"
	return s
}

func (s *vectorServer) network() int32 { return s.prm.Load() + s.authorizationServer.Load() }

func (s *vectorServer) metadata() metadata {
	return metadata{Issuer: s.server.URL, AuthorizationEndpoint: s.server.URL + "/authorize", TokenEndpoint: s.server.URL + "/token", RegistrationEndpoint: s.server.URL + "/register", GrantTypes: []string{"authorization_code", "client_credentials", "refresh_token"}, ChallengeMethods: []string{"S256"}, TokenAuthMethods: []string{"none", "client_secret_basic", "client_secret_post"}, CIMDSupported: jsonTrue(s.cimd)}
}

func (s *vectorServer) lastScopes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.scopes) == 0 {
		return nil
	}
	return s.scopes[len(s.scopes)-1]
}

func (s *vectorServer) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource") {
		s.prm.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"resource": s.resource, "authorization_servers": []string{s.server.URL}})
		return
	}
	s.authorizationServer.Add(1)
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server":
		json.NewEncoder(w).Encode(s.metadata())
	case "/register":
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		response := map[string]any{"client_id": "dcr-client", "redirect_uris": body["redirect_uris"], "grant_types": body["grant_types"], "token_endpoint_auth_method": body["token_endpoint_auth_method"]}
		if body["token_endpoint_auth_method"] != "none" {
			response["client_secret"] = "dcr-secret"
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(response)
	case "/token":
		r.ParseForm()
		s.mu.Lock()
		requested := strings.Fields(r.PostForm.Get("scope"))
		s.scopes = append(s.scopes, merge(requested))
		mode, granted := s.mode, s.granted
		s.mu.Unlock()
		switch mode {
		case "invalid_grant":
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		case "invalid_client":
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"invalid_client"}`)
			return
		case "token_endpoint_failure":
			w.WriteHeader(503)
			fmt.Fprint(w, `{"error":"temporarily_unavailable"}`)
			return
		}
		response := map[string]any{"access_token": "vector-access", "refresh_token": "vector-refresh", "token_type": "Bearer", "expires_in": 3600}
		if granted != nil {
			response["scope"] = strings.Join(granted, " ")
		} else if len(requested) > 0 {
			response["scope"] = strings.Join(requested, " ")
		}
		if mode == "invalid_response" {
			delete(response, "token_type")
		}
		json.NewEncoder(w).Encode(response)
	default:
		w.WriteHeader(404)
	}
}

// vectorError asserts an expected code, exact scope set and login-ended flag.
func vectorError(t *testing.T, err error, expect vectorExpect) *auth.Error {
	t.Helper()
	assertCode(t, err, auth.Code(*expect.Code))
	var classified *auth.Error
	errors.As(err, &classified)
	var scopes []string
	if expect.Scopes != nil {
		scopes = *expect.Scopes
	}
	if !slices.Equal(classified.Scopes, scopes) || (len(scopes) == 0 && classified.Scopes != nil) {
		t.Fatalf("scopes = %#v; want %#v", classified.Scopes, scopes)
	}
	if expect.LoginEnded != nil && (classified.LoginEnded == nil || *classified.LoginEnded != *expect.LoginEnded) {
		t.Fatalf("LoginEnded = %v; want %v", classified.LoginEnded, *expect.LoginEnded)
	}
	return classified
}

func TestCanonicalScopeDecisions(t *testing.T) {
	for _, vector := range readScopeVectors(t).ScopeDecisions {
		t.Run(vector.ID, func(t *testing.T) {
			requireFeatures(t, vector.Requires)
			in, expect := vector.Input, vector.Expect
			s := newVectorServer(t)
			config := ClientConfig{Issuer: s.server.URL, Resource: s.resource, ClientID: "client", Flow: in.Flow, Scopes: in.Requested, AllowedScopes: in.Ceiling, RequiredScopes: in.HostRequired, RedirectURI: "https://client.example/callback"}
			if in.Flow == "client_credentials" {
				config.ClientSecret = "vector-secret"
			}
			var hostErr error
			callback, refused := "", Purpose("")
			if in.HostError != nil {
				hostErr = &auth.Error{Code: auth.Code(in.HostError.Code), Scopes: in.HostError.Scopes}
				callback = in.HostError.Callback
				switch {
				case callback == "destination":
					targets := map[string]Purpose{"registration_endpoint": Registration, "token_endpoint": TokenEndpoint, "authorization_endpoint": Authorization, "metadata": Metadata}
					var known bool
					if refused, known = targets[in.HostError.Target]; !known {
						t.Fatalf("unknown destination target %q", in.HostError.Target)
					}
					if refused == Registration {
						config.ClientID, config.ClientSecret, config.Registration = "", "", &RegistrationPolicy{ClientName: "Vector Adapter"}
					}
				case callback != "token_validation" && callback != "client_selection":
					t.Fatalf("unknown host callback %q", callback)
				case in.HostError.Target != "":
					t.Fatalf("target %q on host callback %q", in.HostError.Target, callback)
				}
			}
			store := newStore()
			p, err := New(Options{Namespace: "vectors", Store: store, Secrets: newSecrets(), HTTPClient: s.server.Client(), CheckDestination: func(ctx context.Context, raw string, purpose Purpose) error {
				if callback == "destination" && purpose == refused {
					return hostErr
				}
				if !strings.HasPrefix(raw, s.server.URL+"/") {
					return errors.New("untrusted")
				}
				return ctx.Err()
			}, SelectClient: func(ctx context.Context, _ auth.Request, _ []string, _ string) (ClientConfig, error) {
				if callback == "client_selection" {
					return ClientConfig{}, hostErr
				}
				return cloneConfig(config), ctx.Err()
			}, ValidateToken: func(ctx context.Context, _ ClientConfig, _ *oauth2.Token) error {
				if callback == "token_validation" {
					return hostErr
				}
				return ctx.Err()
			}})
			if err != nil {
				t.Fatal(err)
			}
			var decided []decision
			p.trace = func(_ operation, d decision) { decided = append(decided, d) }
			r := auth.Request{BackendID: "backend", Purpose: auth.Event, Destination: s.resource}
			if in.Binding == "preset" {
				r.Binding, _ = json.Marshal(map[string]any{"type": "oauth", "issuer": config.Issuer, "resource": config.Resource, "clientId": config.ClientID, "flow": config.Flow, "scopes": in.PresetScopes})
			}
			selected := cloneConfig(config)
			selected.source = sourcePreregistered
			if selected.ClientID == "" {
				selected.source = sourceDCR
			}
			if in.Binding == "stored" {
				public := cloneConfig(selected)
				public.ClientSecret, public.RequiredScopes = "", nil
				if ok, err := store.CompareAndSwap(budget(t), p.bindingKey(r), "", &Record{Generation: randomID(), Binding: &BindingMetadata{Config: public, IssuerMetadata: s.metadata(), Source: selected.source}}); !ok || err != nil {
					t.Fatalf("seed binding: %v", err)
				}
			}
			key := p.key(r, selected)
			var seeded *Record
			if in.Granted != nil {
				seeded = &Record{AccessToken: "seed-access", ExpiresAt: time.Now().Add(time.Hour), Scopes: in.Granted, ClientID: config.ClientID, Generation: randomID()}
				if callback == "token_validation" {
					// Validation runs on a token response: the grant needs a refresh.
					seeded.ExpiresAt, seeded.RefreshToken = time.Now().Add(-time.Hour), "seed-refresh"
				}
				if ok, err := store.CompareAndSwap(budget(t), key, "", cloneRecord(seeded)); !ok || err != nil {
					t.Fatalf("seed grant: %v", err)
				}
			}

			var credential *auth.Credential
			var login *PendingLogin
			switch in.Path {
			case "cached", "fresh":
				var prepared Preparation
				prepared, err = p.Prepare(budget(t), r)
				credential, login = prepared.Credential, prepared.Login
			case "prepare":
				var prepared Preparation
				prepared, err = p.PrepareWith(budget(t), r, PrepareOptions{RequiredScopes: in.Explicit})
				credential, login = prepared.Credential, prepared.Login
			case "credential":
				var c auth.Credential
				if c, err = p.Credential(budget(t), r); err == nil {
					credential = &c
				}
			case "preemptive":
				credential, err = p.PreemptiveCredential(budget(t), r)
			case "challenge":
				challenge := auth.Challenge{StatusCode: in.Challenge.Status, Header: http.Header{"Www-Authenticate": {in.Challenge.WWWAuthenticate}}}
				if seeded != nil {
					challenge.Attempt = p.credential(r, key, seeded).Attempt
				}
				credential, err = p.Challenge(budget(t), r, challenge)
			default:
				t.Fatalf("unknown path %q", in.Path)
			}

			if expect.NetworkCalls != nil && s.network() != *expect.NetworkCalls {
				t.Fatalf("network calls = %d; want %d", s.network(), *expect.NetworkCalls)
			}
			if expect.AuthorizationServerRequests != nil && s.authorizationServer.Load() != *expect.AuthorizationServerRequests {
				t.Fatalf("authorization-server requests = %d; want %d", s.authorizationServer.Load(), *expect.AuthorizationServerRequests)
			}
			if len(decided) == 0 && callback != "client_selection" {
				// Only a host client-selection failure precedes the decision.
				t.Fatal("the entry point made no scope decision")
			}
			if expect.Required != nil && len(decided) > 0 {
				if got := decided[len(decided)-1].required; !slices.Equal(got, merge(expect.Required)) || (len(expect.Required) == 0 && got != nil) {
					t.Fatalf("decided R = %v; want %v", got, expect.Required)
				}
			}
			if expect.Retired != nil {
				record, _ := store.Load(budget(t), key)
				if retired := record == nil || record.AccessToken != "seed-access"; retired != *expect.Retired {
					t.Fatalf("retired = %v; want %v", retired, *expect.Retired)
				}
			}
			if expect.Code == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				switch expect.Action {
				case "use":
					if credential == nil || credential.Token != "seed-access" {
						t.Fatal("stored grant not used")
					}
				case "acquire":
					if credential == nil || credential.Token != "vector-access" {
						t.Fatal("no new grant acquired")
					}
					if got := s.lastScopes(); !slices.Equal(got, merge(expect.AcquisitionScopes)) {
						t.Fatalf("acquisition requested %v; want %v", got, expect.AcquisitionScopes)
					}
				case "login":
					if login == nil {
						t.Fatal("no login created")
					}
				default:
					t.Fatalf("unknown action %q", expect.Action)
				}
			} else {
				classified := vectorError(t, err, expect)
				if credential != nil || login != nil {
					t.Fatal("failed operation returned a credential or login")
				}
				if classified.Code == auth.CodeInteractionRequired && expect.AcquisitionScopes != nil {
					// The host passes the error's scopes back to prepare.
					prepared, err := p.Prepare(budget(t), r, classified.Scopes...)
					if err != nil || prepared.Login == nil {
						t.Fatalf("follow-up prepare: %v", err)
					}
					login = prepared.Login
				}
			}
			if login != nil {
				if got := merge(loginScopes(login)); expect.AcquisitionScopes != nil && !slices.Equal(got, merge(expect.AcquisitionScopes)) {
					t.Fatalf("sign-in requested %v; want %v", got, expect.AcquisitionScopes)
				}
				if record := pendingRecord(t, p, r); expect.Required != nil && !slices.Equal(record.Required, merge(expect.Required)) {
					t.Fatalf("login stored R = %v; want %v", record.Required, expect.Required)
				}
			}
		})
	}
}

func TestCanonicalCompletions(t *testing.T) {
	for _, vector := range readScopeVectors(t).Completions {
		t.Run(vector.ID, func(t *testing.T) {
			requireFeatures(t, vector.Requires)
			in, expect := vector.Input, vector.Expect
			// Without complete_handle, handle matching means none is passed.
			s := newVectorServer(t)
			redirect := "https://client.example/callback"
			config := ClientConfig{Issuer: s.server.URL, Resource: s.resource, Flow: pkceFlow, Scopes: in.Ceiling, AllowedScopes: merge(in.Ceiling, in.StoredRequired...), RedirectURI: redirect}
			switch in.ClientSource {
			case "preregistered":
				config.ClientID = "client"
			case "cimd":
				s.cimd = true
				config.ClientIDMetadataDocument = &MetadataDocument{URL: "https://client.example/client.json", RedirectURIs: []string{redirect}}
			case "dcr":
				config.Registration = &RegistrationPolicy{ClientName: "Vector Adapter"}
			default:
				t.Fatalf("unknown client source %q", in.ClientSource)
			}
			var mu sync.Mutex
			var hostErr error
			store := newStore()
			p, err := New(Options{Namespace: "vectors", Store: store, HTTPClient: s.server.Client(), CheckDestination: func(ctx context.Context, raw string, _ Purpose) error {
				if !strings.HasPrefix(raw, s.server.URL+"/") {
					return errors.New("untrusted")
				}
				return ctx.Err()
			}, SelectClient: func(ctx context.Context, _ auth.Request, _ []string, _ string) (ClientConfig, error) {
				mu.Lock()
				defer mu.Unlock()
				if hostErr != nil {
					return ClientConfig{}, hostErr
				}
				return cloneConfig(config), ctx.Err()
			}, ValidateToken: func(ctx context.Context, _ ClientConfig, _ *oauth2.Token) error { return ctx.Err() }})
			if err != nil {
				t.Fatal(err)
			}
			if in.HostError != nil && in.HostError.Callback != "client_selection" {
				t.Fatalf("unknown host callback %q", in.HostError.Callback)
			}
			r := auth.Request{BackendID: "backend", Purpose: auth.Event, Destination: s.resource}
			prepared, err := p.PrepareWith(budget(t), r, PrepareOptions{RequiredScopes: in.StoredRequired})
			if err != nil || prepared.Login == nil {
				t.Fatalf("prepare: %v", err)
			}
			if record := pendingRecord(t, p, r); !slices.Equal(record.Required, merge(in.StoredRequired)) {
				t.Fatalf("login stored R = %v; want %v", record.Required, in.StoredRequired)
			}
			mu.Lock()
			config.AllowedScopes = in.Ceiling
			mu.Unlock()
			key := p.key(r, mustConfig(t, p, r))
			if in.HostError != nil {
				// The host callback fails before the claim.
				mu.Lock()
				hostErr = &auth.Error{Code: auth.Code(in.HostError.Code), Scopes: in.HostError.Scopes}
				mu.Unlock()
			}
			switch in.Pending {
			case "pending", "unknown":
			case "expired":
				logins := p.logins.(*processLogins)
				logins.mu.Lock()
				for i := range logins.values[pendingKey(key)].Pending {
					logins.values[pendingKey(key)].Pending[i].ExpiresAt = time.Now().Add(-time.Minute)
				}
				logins.mu.Unlock()
			case "ended":
				if err := p.Cancel(budget(t), r, prepared.Login); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("unknown pending state %q", in.Pending)
			}
			switch in.Exchange {
			case "ok", "invalid_grant", "invalid_client", "token_endpoint_failure", "invalid_response":
			default:
				t.Fatalf("unknown exchange %q", in.Exchange)
			}
			s.mu.Lock()
			s.mode, s.granted = in.Exchange, in.Granted
			s.mu.Unlock()

			authorization, _ := url.Parse(prepared.Login.AuthorizationURL())
			state := authorization.Query().Get("state")
			if in.Pending == "unknown" {
				state = "unknown-state"
			}
			query := url.Values{"state": {state}, "code": {"vector-code"}, "iss": {s.server.URL}}
			base, suffix := redirect, ""
			switch in.Callback {
			case "valid":
			case "denied":
				query.Del("code")
				query.Set("error", "access_denied")
			case "redirect_mismatch":
				base = "https://elsewhere.example/callback"
			case "iss_mismatch":
				query.Set("iss", "https://elsewhere.example")
			case "fragment":
				suffix = "#fragment"
			case "userinfo":
				base = "https://user@client.example/callback"
			case "missing_code":
				query.Del("code")
			case "duplicate_param":
				query.Add("code", "other-code")
			case "missing_state":
				query.Del("state")
			default:
				t.Fatalf("unknown callback %q", in.Callback)
			}
			callback := base + "?" + query.Encode() + suffix
			_, err = p.Complete(budget(t), r, callback)
			if expect.Code == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				vectorError(t, err, expect)
			}
			if expect.GrantPersisted != nil {
				record, _ := store.Load(budget(t), key)
				if persisted := record != nil && record.AccessToken == "vector-access"; persisted != *expect.GrantPersisted {
					t.Fatalf("grant persisted = %v; want %v", persisted, *expect.GrantPersisted)
				}
			}
			if in.HostError != nil {
				// The login stayed pending: once the host recovers it completes.
				mu.Lock()
				hostErr = nil
				mu.Unlock()
				if _, err := p.Complete(budget(t), r, callback); err != nil {
					t.Fatalf("login did not complete after the host failure: %v", err)
				}
			}
		})
	}
}
