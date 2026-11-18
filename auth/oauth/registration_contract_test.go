package oauth

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

type registrationFixture struct {
	RegistrationKeys []struct {
		ID    string `json:"id"`
		Input struct {
			Namespace, Issuer string
		} `json:"input"`
		RegistrationKey string `json:"registration_key"`
	} `json:"registration_keys"`
	Selection []struct {
		ID    string `json:"id"`
		Input struct {
			Flow       string  `json:"flow"`
			Registered *string `json:"preregistered_client_id"`
			CIMD       *struct {
				URL          string   `json:"url"`
				RedirectURIs []string `json:"redirect_uris"`
			} `json:"cimd"`
			Redirect   *string        `json:"redirect"`
			Metadata   map[string]any `json:"as_metadata"`
			Permitted  bool           `json:"dcr_permitted"`
			SecretHook bool           `json:"secret_hook"`
		} `json:"input"`
		Expect struct {
			Source, Error string
			ClientID      string `json:"client_id"`
			Method        string `json:"token_endpoint_auth_method"`
			Identity      string `json:"client_identity"`
		} `json:"expect"`
	} `json:"client_selection"`
	Responses []struct {
		ID       string          `json:"id"`
		Flow     string          `json:"flow"`
		Request  map[string]any  `json:"request"`
		Now      int64           `json:"now"`
		Status   int             `json:"status"`
		Response json.RawMessage `json:"response"`
		Expect   struct {
			Accepted bool   `json:"accepted"`
			Error    string `json:"error"`
			Expiry   string `json:"expiry"`
			Record   struct {
				ClientID  string `json:"client_id"`
				SecretRef bool   `json:"secret_ref"`
			} `json:"record"`
		} `json:"expect"`
	} `json:"registration_responses"`
}

func readRegistrationContract(t *testing.T) registrationFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/sdk-auth-lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture registrationFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestCanonicalRegistrationKeys(t *testing.T) {
	for _, vector := range readRegistrationContract(t).RegistrationKeys {
		i := vector.Input
		p := &Provider{options: Options{Namespace: i.Namespace}}
		for _, flow := range []string{ccFlow, pkceFlow} {
			if got := p.registrationKey(ClientConfig{Issuer: i.Issuer, Flow: flow, RedirectURI: "http://127.0.0.1:8765/callback"}); got != vector.RegistrationKey {
				t.Errorf("%s: registration key = %q; want %q", vector.ID, got, vector.RegistrationKey)
			}
		}
	}
}

// Client selection vectors run through Prepare against a real TLS issuer.
func TestCanonicalClientSelection(t *testing.T) {
	for _, vector := range readRegistrationContract(t).Selection {
		t.Run(vector.ID, func(t *testing.T) {
			in := vector.Input
			f := dcrSetup(t, in.Flow)
			host := strings.TrimPrefix(f.server.URL, "https://")
			rewrite := func(raw string) string {
				return strings.Replace(strings.Replace(raw, "issuer.example", host, 1), "adapter.example", host, 1)
			}
			f.set(func(f *dcrFixture) {
				f.metadata = map[string]any{"registration_endpoint": nil}
				for k, v := range in.Metadata {
					if s, ok := v.(string); ok && k == "registration_endpoint" {
						v = rewrite(s)
					}
					f.metadata[k] = v
				}
				if in.Registered != nil {
					f.config.ClientID = *in.Registered
					if in.Flow != pkceFlow {
						f.config.ClientSecret = "test-secret"
					}
				}
				if in.CIMD != nil {
					f.config.ClientIDMetadataDocument = &MetadataDocument{URL: rewrite(in.CIMD.URL), RedirectURIs: in.CIMD.RedirectURIs}
				}
				if in.Redirect != nil {
					f.config.RedirectURI = *in.Redirect
				}
				if !in.Permitted {
					f.config.Registration = nil
				}
			})
			p := f.provider(func(o *Options) {
				if !in.SecretHook {
					o.Secrets = nil
				}
			})
			r := f.request("backend")
			prepared, err := p.Prepare(budget(t), r)
			if vector.Expect.Error != "" {
				assertCode(t, err, auth.Code(vector.Expect.Error))
				if f.registerCalls.Load() != 0 || anyPending(p) {
					t.Fatal("failed selection registered or created a login")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if f.documentCalls.Load() != 0 {
				t.Fatal("SDK fetched the client ID metadata document")
			}
			config, _, cached, err := p.cachedBinding(budget(t), r)
			if err != nil || !cached || identity(config) != rewrite(vector.Expect.Identity) {
				t.Fatalf("client identity = %q; want %q (%v)", identity(config), vector.Expect.Identity, err)
			}
			switch vector.Expect.Source {
			case sourcePreregistered, sourceCIMD:
				if got := loginClientID(t, prepared.Login); got != rewrite(vector.Expect.ClientID) {
					t.Fatalf("client_id = %q; want %q", got, vector.Expect.ClientID)
				}
				if f.registerCalls.Load() != 0 || f.registration(t, f.config) != nil {
					t.Fatal("no registration expected")
				}
			case sourceDCR:
				if f.registerCalls.Load() != 1 || f.registrations[0].Body["token_endpoint_auth_method"] != vector.Expect.Method {
					t.Fatalf("registration %+v", f.registrations)
				}
				if in.Flow == pkceFlow {
					if got := loginClientID(t, prepared.Login); got != "dcr-1" {
						t.Fatalf("client_id = %q", got)
					}
				} else if prepared.Credential == nil || f.lastTokenClient() != "dcr-1" {
					t.Fatal("registered client not used")
				}
			default:
				t.Fatalf("unknown source %q", vector.Expect.Source)
			}
		})
	}
}

// Registration response vectors cross the real HTTP response parser and store.
func TestCanonicalRegistrationResponses(t *testing.T) {
	for _, vector := range readRegistrationContract(t).Responses {
		t.Run(vector.ID, func(t *testing.T) {
			f := dcrSetup(t, vector.Flow)
			var response map[string]json.RawMessage
			json.Unmarshal(vector.Response, &response)
			if raw, ok := response["client_secret_expires_at"]; ok {
				// Shift the vector's clock onto ours, keeping its type.
				var at int64
				if json.Unmarshal(raw, &at) == nil && at > 0 {
					shifted, _ := json.Marshal(at - vector.Now + time.Now().Unix())
					response["client_secret_expires_at"] = shifted
				}
			}
			body, _ := json.Marshal(response)
			if response == nil {
				body = []byte("not json")
			}
			f.set(func(f *dcrFixture) {
				f.respond = func(w http.ResponseWriter, _ int) {
					if vector.Status >= 300 && vector.Status < 400 {
						w.Header().Set("Location", f.server.URL+"/elsewhere")
					}
					w.WriteHeader(vector.Status)
					w.Write(body)
				}
				var id, secret string
				json.Unmarshal(response["client_id"], &id)
				json.Unmarshal(response["client_secret"], &secret)
				f.issued[id] = secret
			})
			p := f.provider()
			prepared, err := p.Prepare(budget(t), f.request("backend"))
			sent, _ := json.Marshal(f.registrations[0].Body)
			want, _ := json.Marshal(vector.Request)
			if string(sent) != string(want) {
				t.Fatalf("request = %s; want %s", sent, want)
			}
			record := f.registration(t, f.config)
			if !vector.Expect.Accepted {
				assertCode(t, err, auth.Code(vector.Expect.Error))
				if record != nil && record.Registration != nil {
					t.Fatal("rejected registration persisted")
				}
				// Only client credentials keep a registration backoff.
				if (record != nil && record.RegistrationFailure != nil) != (vector.Flow == ccFlow) || anyPending(p) {
					t.Fatalf("failed registration persisted %+v", record)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if vector.Flow == pkceFlow {
				// A PKCE client lives in its login, never in a registration record.
				if record != nil || loginClientID(t, prepared.Login) != vector.Expect.Record.ClientID || vector.Expect.Record.SecretRef || f.secrets.count() != 0 {
					t.Fatalf("record = %+v", record)
				}
			} else if reg := record.Registration; reg == nil || reg.ClientID != vector.Expect.Record.ClientID || (reg.SecretRef != "") != vector.Expect.Record.SecretRef || reg.SecretExpiresAt.IsZero() != (vector.Expect.Expiry == "none") || reg.RequestDigest != requestDigest(f.config.Registration) {
				t.Fatalf("record = %+v", reg)
			}
			dump := f.dump(t)
			for _, leaked := range []string{"not-a-real-secret", "registration_client_uri", "RegistrationClientURI", "/register/"} {
				if strings.Contains(dump, leaked) {
					t.Fatalf("stored %q", leaked)
				}
			}
			if !slices.Contains([]int{0, 1}, int(f.tokenCalls.Load())) {
				t.Fatal("unexpected token traffic")
			}
		})
	}
}
