package oauth

// Native table-driven runners for the shared scope_decisions and completions
// vectors (spec: SDK auth lifecycle, Executable coverage). Every field a
// vector defines is asserted; an unknown field fails the run.

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

type vectorHostError struct {
	Callback string   `json:"callback"`
	Target   string   `json:"target"`
	Code     string   `json:"code"`
	Scopes   []string `json:"scopes"`
}

type vectorGrant struct {
	Generation int      `json:"generation"`
	Granted    []string `json:"granted"`
	Token      string   `json:"token"`
	Refresh    bool     `json:"refresh"`
}

type scopeDecisionVector struct {
	ID       string   `json:"id"`
	Requires []string `json:"requires"`
	Input    struct {
		Flow         string          `json:"flow"`
		Path         string          `json:"path"`
		Binding      string          `json:"binding"`
		Requested    []string        `json:"requested"`
		PresetScopes *[]string       `json:"preset_scopes"`
		Ceiling      []string        `json:"ceiling"`
		HostRequired []string        `json:"host_required"`
		Explicit     []string        `json:"explicit"`
		Grant        *vectorGrant    `json:"grant"`
		Sent         json.RawMessage `json:"sent"`
		Challenge    *struct {
			Status          int    `json:"status"`
			WWWAuthenticate string `json:"www_authenticate"`
		} `json:"challenge"`
		Prior401Hint []string         `json:"prior_401_hint"`
		HostError    *vectorHostError `json:"host_error"`
	} `json:"input"`
	Expect struct {
		Code                        *string   `json:"code"`
		Scopes                      *[]string `json:"scopes"`
		Required                    *[]string `json:"required"`
		Action                      string    `json:"action"`
		AcquisitionScopes           *[]string `json:"acquisition_scopes"`
		Retired                     *bool     `json:"retired"`
		AuthorizationServerRequests *int32    `json:"authorization_server_requests"`
		NetworkCalls                *int32    `json:"network_calls"`
		NetworkCallsMax             *int32    `json:"network_calls_max"`
	} `json:"expect"`
}

type completionVector struct {
	ID       string   `json:"id"`
	Requires []string `json:"requires"`
	Input    struct {
		Pending                 string           `json:"pending"`
		Handle                  string           `json:"handle"`
		ClientSource            string           `json:"client_source"`
		SourcePermitted         bool             `json:"source_permitted"`
		Callback                string           `json:"callback"`
		HostError               *vectorHostError `json:"host_error"`
		Claim                   json.RawMessage  `json:"claim"`
		Exchange                string           `json:"exchange"`
		StoredRequired          *[]string        `json:"stored_required"`
		PrepareTimeHostRequired *[]string        `json:"prepare_time_host_required"`
		CurrentHostRequired     []string         `json:"current_host_required"`
		Granted                 []string         `json:"granted"`
		Ceiling                 []string         `json:"ceiling"`
	} `json:"input"`
	Expect struct {
		Code           *string   `json:"code"`
		Scopes         *[]string `json:"scopes"`
		LoginEnded     *bool     `json:"login_ended"`
		GrantPersisted bool      `json:"grant_persisted"`
	} `json:"expect"`
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

func readScopeVectors(t *testing.T) ([]scopeDecisionVector, []completionVector) {
	t.Helper()
	data, err := os.ReadFile("testdata/sdk-auth-lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(data, &sections); err != nil {
		t.Fatal(err)
	}
	var decisions []scopeDecisionVector
	var completions []completionVector
	for name, target := range map[string]any{"scope_decisions": &decisions, "completions": &completions} {
		decoder := json.NewDecoder(bytes.NewReader(sections[name]))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(target); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if len(decisions) == 0 || len(completions) == 0 {
		t.Fatal("fixture has no scope or completion vectors")
	}
	return decisions, completions
}

// vectorServer is a TLS protected resource and authorization server that
// counts every request. The token endpoint grants the requested scopes (or
// granted), unless a failure mode is set.
type vectorServer struct {
	server   *httptest.Server
	resource string
	cimd     bool

	mu      sync.Mutex
	granted []string
	mode    string
	scopes  [][]string
	grants  []string

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

// last returns the newest token request's grant type and requested scopes.
func (s *vectorServer) last() (string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.scopes) == 0 {
		return "", nil
	}
	return s.grants[len(s.grants)-1], s.scopes[len(s.scopes)-1]
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
		s.grants = append(s.grants, r.PostForm.Get("grant_type"))
		mode, granted := s.mode, s.granted
		s.mu.Unlock()
		switch mode {
		case "invalid_grant", "invalid_client", "unauthorized_client", "access_denied", "invalid_scope", "server_error":
			status := 400
			if mode == "invalid_client" {
				status = 401
			}
			if mode == "server_error" {
				status = 500
			}
			w.WriteHeader(status)
			fmt.Fprintf(w, `{"error":%q}`, mode)
			return
		case "not_found":
			w.WriteHeader(404)
			return
		case "unreachable":
			// The connection drops before any response.
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				conn.Close()
			}
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
func vectorError(t *testing.T, err error, code string, scopes *[]string, ended *bool) *auth.Error {
	t.Helper()
	assertCode(t, err, auth.Code(code))
	var classified *auth.Error
	errors.As(err, &classified)
	var want []string
	if scopes != nil {
		want = *scopes
	}
	if !slices.Equal(classified.Scopes, want) || (len(want) == 0 && classified.Scopes != nil) {
		t.Fatalf("scopes = %#v; want %#v", classified.Scopes, want)
	}
	if (ended == nil) != (classified.LoginEnded == nil) || (ended != nil && *ended != *classified.LoginEnded) {
		t.Fatalf("LoginEnded = %v; want %v", classified.LoginEnded, ended)
	}
	return classified
}

// writesStore records grant writes, to observe a retirement.
type writesStore struct {
	*memoryStore
	mu     sync.Mutex
	writes []struct {
		key, expected string
		value         *Record
	}
}

func (s *writesStore) CompareAndSwap(ctx context.Context, key, expected string, value *Record) (bool, error) {
	ok, err := s.memoryStore.CompareAndSwap(ctx, key, expected, value)
	if ok && err == nil {
		s.mu.Lock()
		s.writes = append(s.writes, struct {
			key, expected string
			value         *Record
		}{key, expected, cloneRecord(value)})
		s.mu.Unlock()
	}
	return ok, err
}

// retired reports a write that dropped generation's access token.
func (s *writesStore) retired(key, generation string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, write := range s.writes {
		if write.key == key && write.expected == generation && write.value != nil && write.value.AccessToken == "" {
			return true
		}
	}
	return false
}

func vectorGeneration(n int) string { return fmt.Sprintf("generation-%d", n) }

func TestCanonicalScopeDecisions(t *testing.T) {
	decisions, _ := readScopeVectors(t)
	for _, vector := range decisions {
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
					targets := map[string]Purpose{"registration_endpoint": Registration, "issuer_metadata": Metadata}
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
			store := &writesStore{memoryStore: newStore()}
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
			// A stored binding and unbound requests; a preset rides on the request.
			r := auth.Request{BackendID: "backend", Purpose: auth.Event, Destination: s.resource}
			switch in.Binding {
			case "preset":
				preset := map[string]any{"type": "oauth", "issuer": config.Issuer, "resource": config.Resource, "clientId": config.ClientID, "flow": config.Flow}
				if in.PresetScopes != nil {
					preset["scopes"] = *in.PresetScopes
				}
				r.Binding, _ = json.Marshal(preset)
			case "stored", "unbound":
			default:
				t.Fatalf("unknown binding %q", in.Binding)
			}
			selected := cloneConfig(config)
			selected.source = sourcePreregistered
			if selected.ClientID == "" {
				selected.source = sourceDCR
			}
			if in.Binding == "stored" || in.Path == "cached" {
				public := cloneConfig(selected)
				public.ClientSecret, public.RequiredScopes = "", nil
				if ok, err := store.CompareAndSwap(budget(t), p.bindingKey(r), "", &Record{Generation: randomID(), Binding: &BindingMetadata{Config: public, IssuerMetadata: s.metadata(), Source: selected.source}}); !ok || err != nil {
					t.Fatalf("seed binding: %v", err)
				}
			}
			key := p.key(r, selected)
			var seeded *Record
			if in.Grant != nil {
				g := in.Grant
				seeded = &Record{AccessToken: "seed-access", ExpiresAt: time.Now().Add(time.Hour), Scopes: g.Granted, ClientID: config.ClientID, Generation: vectorGeneration(g.Generation)}
				switch g.Token {
				case "valid":
				case "expired":
					seeded.ExpiresAt = time.Now().Add(-time.Hour)
				default:
					t.Fatalf("unknown token %q", g.Token)
				}
				if g.Refresh {
					seeded.RefreshToken = "seed-refresh"
				}
				if callback == "token_validation" {
					// Go validates tokens as the token endpoint issues them: the
					// stored token is renewed so the host callback runs.
					seeded.ExpiresAt, seeded.RefreshToken = time.Now().Add(-time.Hour), "seed-refresh"
				}
				if ok, err := store.CompareAndSwap(budget(t), key, "", cloneRecord(seeded)); !ok || err != nil {
					t.Fatalf("seed grant: %v", err)
				}
			}
			var sent string
			hasSent := len(in.Sent) > 0
			if hasSent && string(in.Sent) != "null" {
				var n int
				if err := json.Unmarshal(in.Sent, &n); err != nil {
					t.Fatalf("sent: %v", err)
				}
				sent = vectorGeneration(n)
			}
			if hasSent != (in.Challenge != nil) {
				t.Fatal("sent is present exactly with challenge")
			}
			if in.Prior401Hint != nil {
				// An earlier operation's 401 carried the hint; its acquisition
				// failed, so only a remembered hint could reach this operation.
				s.mu.Lock()
				s.mode = "server_error"
				s.mu.Unlock()
				p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer scope="` + strings.Join(in.Prior401Hint, " ") + `"`}}})
				s.mu.Lock()
				s.mode, s.scopes, s.grants = "", nil, nil
				s.mu.Unlock()
				decided = nil
			}
			s.prm.Store(0)
			s.authorizationServer.Store(0)

			var credential *auth.Credential
			var login *PendingLogin
			switch in.Path {
			case "cached", "credential":
				var c auth.Credential
				if c, err = p.Credential(budget(t), r); err == nil {
					credential = &c
				}
			case "fresh":
				if in.Binding == "unbound" {
					// The first use of an unbound target is anonymous; its 401
					// is the only way to reach OAuth.
					credential, err = p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{}})
				} else {
					var c auth.Credential
					if c, err = p.Credential(budget(t), r); err == nil {
						credential = &c
					}
				}
			case "prepare":
				var prepared Preparation
				prepared, err = p.PrepareWith(budget(t), r, PrepareOptions{RequiredScopes: in.Explicit})
				credential, login = prepared.Credential, prepared.Login
			case "preemptive":
				credential, err = p.PreemptiveCredential(budget(t), r)
			case "challenge":
				challenge := auth.Challenge{StatusCode: in.Challenge.Status, Header: http.Header{"Www-Authenticate": {in.Challenge.WWWAuthenticate}}}
				if sent != "" {
					challenge.Attempt = attempted{p, key, sent, requestIdentity(r)}
				}
				credential, err = p.Challenge(budget(t), r, challenge)
			default:
				t.Fatalf("unknown path %q", in.Path)
			}
			if in.Path != "prepare" && len(in.Explicit) != 0 {
				t.Fatal("explicit scopes only apply to prepare")
			}

			if expect.AuthorizationServerRequests != nil && s.authorizationServer.Load() != *expect.AuthorizationServerRequests {
				t.Fatalf("authorization-server requests = %d; want %d", s.authorizationServer.Load(), *expect.AuthorizationServerRequests)
			}
			if expect.NetworkCalls != nil && s.network() != *expect.NetworkCalls {
				t.Fatalf("network calls = %d; want %d", s.network(), *expect.NetworkCalls)
			}
			if expect.NetworkCallsMax != nil && s.network() > *expect.NetworkCallsMax {
				t.Fatalf("network calls = %d; want at most %d", s.network(), *expect.NetworkCallsMax)
			}
			if (expect.Retired != nil) != (in.Challenge != nil && in.Challenge.Status == 401) {
				t.Fatal("retired is present exactly for a 401")
			}
			if expect.Retired != nil {
				if got := store.retired(key, sent); got != *expect.Retired {
					t.Fatalf("retired = %v; want %v", got, *expect.Retired)
				}
			}
			if expect.Required != nil {
				if len(decided) == 0 {
					t.Fatal("no decision reached the ceiling step")
				}
				if got := decided[len(decided)-1].required; !slices.Equal(got, merge(*expect.Required)) || (len(*expect.Required) == 0 && got != nil) {
					t.Fatalf("decided R = %v; want %v", got, *expect.Required)
				}
			} else if n := len(decided); callback == "" && n > 0 && !(decided[n-1].outcome == outcomeFail && decided[n-1].early && decided[n-1].required == nil) {
				t.Fatalf("a decision reached the ceiling step: %+v", decided[n-1])
			} else if n == 0 && callback != "client_selection" {
				t.Fatal("the entry point made no scope decision")
			}
			grantType, wire := s.last()
			if expect.Code == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				switch expect.Action {
				case "use":
					if credential == nil || credential.Token != "seed-access" || s.authorizationServer.Load() != 0 {
						t.Fatal("stored grant not used")
					}
				case "refresh":
					if credential == nil || credential.Token != "vector-access" || grantType != "refresh_token" {
						t.Fatal("grant not refreshed")
					}
				case "acquire":
					if credential == nil || credential.Token != "vector-access" || grantType != "client_credentials" {
						t.Fatal("no client-credentials grant acquired")
					}
					if expect.AcquisitionScopes == nil || !slices.Equal(wire, merge(*expect.AcquisitionScopes)) {
						t.Fatalf("acquisition requested %v; want %v", wire, expect.AcquisitionScopes)
					}
				case "login":
					if login == nil || credential != nil {
						t.Fatal("no login created")
					}
					if expect.AcquisitionScopes == nil || !slices.Equal(merge(loginScopes(login)), merge(*expect.AcquisitionScopes)) {
						t.Fatalf("sign-in requested %v; want %v", loginScopes(login), expect.AcquisitionScopes)
					}
					if record := pendingRecord(t, p, r); expect.Required == nil || !slices.Equal(record.Required, merge(*expect.Required)) {
						t.Fatalf("login stored R = %v; want %v", record.Required, expect.Required)
					}
				default:
					t.Fatalf("unknown action %q", expect.Action)
				}
				if expect.AcquisitionScopes != nil && expect.Action != "acquire" && expect.Action != "login" {
					t.Fatal("acquisition_scopes without an acquisition")
				}
			} else {
				if expect.Action != "" || expect.AcquisitionScopes != nil {
					t.Fatal("action on a failure")
				}
				vectorError(t, err, *expect.Code, expect.Scopes, nil)
				if credential != nil || login != nil || anyPending(p) {
					t.Fatal("failed operation returned a credential or login")
				}
			}
		})
	}
}

// uncertainStore fails pending-login claims as set by mode: gone (the write
// lands but reports an error) or pending (it does not land).
type uncertainStore struct {
	*memoryStore
	mode atomic.Value
}

func (s *uncertainStore) current() string { mode, _ := s.mode.Load().(string); return mode }

func (s *uncertainStore) CompareAndSwap(ctx context.Context, key, expected string, value *Record) (bool, error) {
	if strings.HasPrefix(key, "ahp.oauth.pending:") {
		switch s.current() {
		case "gone":
			s.memoryStore.CompareAndSwap(ctx, key, expected, value)
			return false, &auth.Error{Code: auth.CodeProviderFailed}
		case "pending":
			return false, &auth.Error{Code: auth.CodeProviderFailed}
		}
	}
	return s.memoryStore.CompareAndSwap(ctx, key, expected, value)
}

func TestCanonicalCompletions(t *testing.T) {
	_, completions := readScopeVectors(t)
	for _, vector := range completions {
		t.Run(vector.ID, func(t *testing.T) {
			requireFeatures(t, vector.Requires)
			in, expect := vector.Input, vector.Expect
			// Without complete_handle, handle matching means none is passed.
			if in.Handle != "matching" && in.Handle != "none" {
				t.Fatalf("handle %q needs complete_handle", in.Handle)
			}
			s := newVectorServer(t)
			redirect := "https://client.example/callback?tenant=vector"
			preparedRequired := []string{}
			if in.StoredRequired != nil {
				preparedRequired = *in.StoredRequired
			}
			config := ClientConfig{Issuer: s.server.URL, Resource: s.resource, Flow: pkceFlow, Scopes: in.Ceiling, AllowedScopes: merge(in.Ceiling, preparedRequired...), RedirectURI: redirect}
			if in.PrepareTimeHostRequired != nil {
				config.AllowedScopes = merge(config.AllowedScopes, *in.PrepareTimeHostRequired...)
			}
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
			store := &uncertainStore{memoryStore: newStore()}
			p, err := New(Options{Namespace: "vectors", Store: store, PersistLogins: true, HTTPClient: s.server.Client(), CheckDestination: func(ctx context.Context, raw string, _ Purpose) error {
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
			prepared, err := p.PrepareWith(budget(t), r, PrepareOptions{RequiredScopes: preparedRequired})
			if err != nil || prepared.Login == nil {
				t.Fatalf("prepare: %v", err)
			}
			key := p.key(r, mustConfig(t, p, r))
			// The login's stored required set, or a record from an older release.
			editPending := func(edit func(*PendingRecord)) {
				record, _ := store.memoryStore.Load(budget(t), pendingKey(key))
				for i := range record.Pending {
					edit(&record.Pending[i])
				}
				next := cloneRecord(record)
				next.Generation = randomID()
				if ok, err := store.memoryStore.CompareAndSwap(budget(t), pendingKey(key), record.Generation, next); !ok || err != nil {
					t.Fatalf("edit pending: %v", err)
				}
			}
			if in.StoredRequired == nil {
				editPending(func(login *PendingRecord) {
					login.Required, login.HasRequired, login.HostRequired = nil, false, nil
					if in.PrepareTimeHostRequired != nil {
						login.HostRequired = append([]string{}, *in.PrepareTimeHostRequired...)
					}
				})
			} else if in.PrepareTimeHostRequired != nil || in.CurrentHostRequired != nil {
				t.Fatal("host required sets apply only to an older record")
			}
			mu.Lock()
			config.AllowedScopes, config.RequiredScopes = in.Ceiling, in.CurrentHostRequired
			if !in.SourcePermitted {
				if in.ClientSource != "dcr" {
					t.Fatalf("source_permitted false for %s", in.ClientSource)
				}
				config.Registration, config.ClientID = nil, "replacement-client"
			}
			mu.Unlock()
			switch in.Pending {
			case "pending", "unknown", "absent":
			case "expired":
				editPending(func(login *PendingRecord) { login.ExpiresAt = time.Now().Add(-time.Minute) })
			case "ended":
				if err := p.Cancel(budget(t), r, prepared.Login); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("unknown pending state %q", in.Pending)
			}
			if in.HostError != nil {
				mu.Lock()
				hostErr = &auth.Error{Code: auth.Code(in.HostError.Code), Scopes: in.HostError.Scopes}
				mu.Unlock()
			}
			var claim struct {
				Outcome   string `json:"outcome"`
				ErrorCode string `json:"error_code"`
				Reread    string `json:"reread"`
			}
			if string(in.Claim) != `"ok"` {
				decoder := json.NewDecoder(bytes.NewReader(in.Claim))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&claim); err != nil || claim.Outcome != "uncertain" || claim.ErrorCode != string(auth.CodeProviderFailed) {
					t.Fatalf("claim %s: %v", in.Claim, err)
				}
				switch claim.Reread {
				case "gone", "pending":
					store.mode.Store(claim.Reread)
				case "undetermined":
				default:
					t.Fatalf("unknown reread %q", claim.Reread)
				}
			}
			switch in.Exchange {
			case "ok", "invalid_grant", "invalid_client", "unauthorized_client", "access_denied", "invalid_scope", "server_error", "unreachable", "not_found", "invalid_response":
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
			query := url.Values{"state": {state}, "code": {"vector-code"}, "iss": {s.server.URL}, "tenant": {"vector"}}
			if in.Pending == "absent" {
				query.Del("state")
			}
			base, suffix := "https://client.example/callback", ""
			switch in.Callback {
			case "valid":
			case "valid_with_server_params":
				query.Set("session_state", "server-session")
			case "denied":
				query.Del("code")
				query.Set("error", "access_denied")
			case "denied_invalid_client":
				query.Del("code")
				query.Set("error", "invalid_client")
			case "redirect_mismatch":
				base = "https://elsewhere.example/callback"
			case "redirect_query_mismatch":
				query.Set("tenant", "other")
			case "state_duplicated":
				query.Add("state", state)
			case "iss_mismatch":
				query.Set("iss", "https://elsewhere.example")
			case "fragment":
				suffix = "#fragment"
			case "userinfo":
				base = "https://user@client.example/callback"
			case "missing_code":
				query.Del("code")
			case "code_and_error":
				query.Set("error", "access_denied")
			case "duplicate_param":
				query.Add("code", "other-code")
			case "unparseable":
				suffix = "&%zz"
			default:
				t.Fatalf("unknown callback %q", in.Callback)
			}
			callback := base + "?" + query.Encode() + suffix
			if claim.Reread == "undetermined" {
				// The claim fails, then the re-read fails too.
				p.logins = &rereadFailingStore{uncertainStore: store}
			}
			_, err = p.Complete(budget(t), r, callback)
			if expect.Code == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if expect.LoginEnded != nil {
					t.Fatal("login_ended on success")
				}
			} else {
				if expect.LoginEnded == nil {
					t.Fatal("login_ended is present on every failure")
				}
				vectorError(t, err, *expect.Code, expect.Scopes, expect.LoginEnded)
			}
			record, _ := store.memoryStore.Load(budget(t), key)
			if persisted := record != nil && record.AccessToken == "vector-access"; persisted != expect.GrantPersisted {
				t.Fatalf("grant persisted = %v; want %v", persisted, expect.GrantPersisted)
			}
			if in.HostError != nil && expect.LoginEnded != nil && !*expect.LoginEnded {
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

// rereadFailingStore fails the claim's write and every later pending read.
type rereadFailingStore struct {
	*uncertainStore
	claimed atomic.Bool
}

func (s *rereadFailingStore) CompareAndSwap(ctx context.Context, key, expected string, value *Record) (bool, error) {
	s.claimed.Store(true)
	return false, &auth.Error{Code: auth.CodeProviderFailed}
}

func (s *rereadFailingStore) Load(ctx context.Context, key string) (*Record, error) {
	if s.claimed.Load() {
		return nil, errors.New("store unavailable")
	}
	return s.uncertainStore.memoryStore.Load(ctx, key)
}
