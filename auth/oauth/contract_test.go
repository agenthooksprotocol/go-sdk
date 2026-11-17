package oauth

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

type contractFixture struct {
	Keys []struct {
		ID    string `json:"id"`
		Input struct {
			Namespace      string   `json:"namespace"`
			BackendID      string   `json:"backend_id"`
			Purpose        string   `json:"purpose"`
			Destination    string   `json:"destination"`
			Issuer         string   `json:"issuer"`
			Resource       string   `json:"resource"`
			ClientID       string   `json:"client_id"`
			Flow           string   `json:"flow"`
			AllowedScopes  []string `json:"allowed_scopes"`
			GrantPartition string   `json:"grant_partition"`
			ClientSecret   string   `json:"client_secret"`
		} `json:"input"`
		BindingKey string `json:"binding_key"`
		GrantKey   string `json:"grant_key"`
	} `json:"keys"`
	Tokens []struct {
		ID               string          `json:"id"`
		Exchange         string          `json:"exchange"`
		PreviousGranted  []string        `json:"previous_granted"`
		Requested        []string        `json:"requested"`
		Allowed          []string        `json:"allowed"`
		Required         []string        `json:"required"`
		Response         json.RawMessage `json:"response"`
		Error            string          `json:"error"`
		Accepted         bool            `json:"accepted"`
		Usable           bool            `json:"usable"`
		Expiry           string          `json:"expiry"`
		Granted          []string        `json:"granted"`
		Effective        []string        `json:"effective"`
		WireRequest      []string        `json:"wire_request"`
		RefreshPreserved bool            `json:"refresh_preserved"`
	} `json:"token_responses"`
}

func readContract(t *testing.T) contractFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/sdk-auth-lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture contractFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestCanonicalGrantKeys(t *testing.T) {
	for _, vector := range readContract(t).Keys {
		t.Run(vector.ID, func(t *testing.T) {
			i := vector.Input
			p := &Provider{options: Options{Namespace: i.Namespace}}
			r := auth.Request{BackendID: i.BackendID, Purpose: auth.Operation(i.Purpose), Destination: i.Destination}
			c := ClientConfig{Issuer: i.Issuer, Resource: i.Resource, ClientID: i.ClientID, Flow: i.Flow, AllowedScopes: i.AllowedScopes, GrantPartition: i.GrantPartition, ClientSecret: i.ClientSecret}
			if got := p.bindingKey(r); got != vector.BindingKey {
				t.Fatalf("binding key = %q; want %q", got, vector.BindingKey)
			}
			if got := p.key(r, c); got != vector.GrantKey {
				t.Fatalf("grant key = %q; want %q", got, vector.GrantKey)
			}
		})
	}
}

// The canonical token vectors cross the real HTTP parser and coordinated host
// store, rather than reconstructing token semantics in a fixture-only helper.
func TestCanonicalTokenResponses(t *testing.T) {
	for _, vector := range readContract(t).Tokens {
		t.Run(vector.ID, func(t *testing.T) {
			var responseFields struct {
				RefreshToken string `json:"refresh_token"`
			}
			if err := json.Unmarshal(vector.Response, &responseFields); err != nil {
				t.Fatal(err)
			}
			var issuer string
			var tokenCalls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/.well-known/oauth-authorization-server":
					json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "token_endpoint": issuer + "/token", "authorization_endpoint": issuer + "/authorize", "code_challenge_methods_supported": []string{"S256"}, "grant_types_supported": []string{"client_credentials", "authorization_code", "refresh_token"}, "token_endpoint_auth_methods_supported": []string{"client_secret_post"}})
				case "/token":
					call := tokenCalls.Add(1)
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					expectedGrant := "client_credentials"
					if vector.Exchange == "refresh" {
						expectedGrant = "refresh_token"
						expectedRefresh := "previous-refresh"
						if call > 1 {
							expectedRefresh = responseFields.RefreshToken
						}
						if r.Form.Get("refresh_token") != expectedRefresh {
							t.Error("refresh material not used")
						}
					}
					if vector.Exchange == "reacquire" && (!slices.Equal(merge(strings.Fields(r.Form.Get("scope"))), merge(vector.WireRequest)) || !slices.Equal(merge(vector.WireRequest), merge(vector.PreviousGranted, intersect(merge(vector.Requested, vector.Required...), vector.Allowed)...))) {
						t.Errorf("re-acquisition requested %q", r.Form.Get("scope"))
					}
					if r.Form.Get("resource") != issuer+"/events" || r.Form.Get("grant_type") != expectedGrant {
						t.Error("unbound token grant")
					}
					w.Write(vector.Response)
				default:
					t.Errorf("unexpected discovery: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			issuer = server.URL
			config := ClientConfig{Issuer: issuer, Resource: issuer + "/events", ClientID: "client", Flow: "client_credentials", ClientSecret: "fixture-secret", Scopes: vector.Requested, AllowedScopes: vector.Allowed, RequiredScopes: vector.Required}
			if vector.Exchange == "refresh" {
				config.Flow = "authorization_code_pkce"
				config.RedirectURI = "https://client.example/callback"
			}
			store := newStore()
			p, err := New(Options{Namespace: "contract", Store: store, HTTPClient: server.Client(), CheckDestination: func(ctx context.Context, raw string, _ Purpose) error {
				if !strings.HasPrefix(raw, issuer+"/") && raw != issuer {
					return &auth.Error{Code: auth.CodeUntrustedDestination}
				}
				return ctx.Err()
			}, SelectClient: func(context.Context, auth.Request, []string, string) (ClientConfig, error) { return config, nil }, ValidateToken: func(context.Context, ClientConfig, *oauth2.Token) error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			binding, _ := json.Marshal(map[string]any{"type": "oauth", "issuer": issuer, "resource": config.Resource, "clientId": "client", "flow": config.Flow, "scopes": vector.Requested})
			request := auth.Request{BackendID: "backend", Purpose: auth.Event, Destination: config.Resource, Binding: binding}
			if vector.Exchange == "reacquire" {
				// An expired client-credentials grant without refresh material.
				prior := &Record{AccessToken: "prior-access", Generation: "prior-generation", ExpiresAt: time.Now().Add(-time.Hour), Scopes: vector.PreviousGranted}
				if ok, err := store.CompareAndSwap(budget(t), p.key(request, config), "", prior); err != nil || !ok {
					t.Fatalf("seed prior grant: %v", err)
				}
			}
			if vector.Exchange == "refresh" {
				prior := &Record{AccessToken: "prior-access", RefreshToken: "previous-refresh", Generation: "prior-generation", ExpiresAt: time.Now().Add(-time.Hour), Scopes: vector.PreviousGranted}
				if ok, err := store.CompareAndSwap(budget(t), p.key(request, config), "", prior); err != nil || !ok {
					t.Fatalf("seed prior grant: %v", err)
				}
			}
			prepared, err := p.Prepare(budget(t), request)
			if vector.Usable {
				if err != nil || prepared.Credential == nil {
					t.Fatalf("usable token rejected: %v", err)
				}
			} else if err == nil {
				t.Fatal("unusable token accepted")
			}
			if vector.Error != "" {
				assertCode(t, err, auth.Code(vector.Error))
			}
			record, loadErr := store.Load(budget(t), p.key(request, config))
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if vector.RefreshPreserved && (record == nil || record.RefreshToken != responseFields.RefreshToken) {
				t.Fatal("returned refresh credential not retained")
			}
			if !vector.Accepted && vector.Exchange != "refresh" && record != nil {
				t.Fatal("invalid initial response persisted a record")
			}
			if record != nil && usable(record) != vector.Accepted {
				t.Fatal("stored access token usability mismatch")
			}
			if vector.Accepted {
				if record == nil {
					t.Fatal("accepted grant not persisted")
				}
				if !slices.Equal(merge(record.Scopes), merge(vector.Granted)) {
					t.Fatalf("granted scopes = %v; want %v", record.Scopes, vector.Granted)
				}
				if vector.Effective != nil && !slices.Equal(intersect(record.Scopes, vector.Allowed), merge(vector.Effective)) {
					t.Fatalf("effective scopes = %v; want %v", intersect(record.Scopes, vector.Allowed), vector.Effective)
				}
				if (vector.Expiry == "unknown") != record.ExpiresAt.IsZero() {
					t.Fatal("expiry classification mismatch")
				}

				if vector.Exchange == "refresh" {
					if cached, err := p.Prepare(budget(t), request); err != nil || cached.Credential == nil {
						t.Fatalf("reuse unknown-expiry token: %v", err)
					}
					if tokenCalls.Load() != 1 {
						t.Fatal("unknown expiry caused eager refresh")
					}
					expected := record.Generation
					record.Generation = "expire-rotated"
					record.ExpiresAt = time.Now().Add(-time.Hour)
					if ok, err := store.CompareAndSwap(budget(t), p.key(request, config), expected, record); err != nil || !ok {
						t.Fatalf("expire rotated grant: %v", err)
					}
					if renewed, err := p.Prepare(budget(t), request); err != nil || renewed.Credential == nil {
						t.Fatalf("reuse rotated refresh: %v", err)
					}
					if tokenCalls.Load() != 2 {
						t.Fatal("rotated refresh was not reused")
					}
				}
			}
		})
	}
}

// lifecycleCoverage maps every lifecycle id in the vendored fixture to the
// native tests exercising it at real store, network and transport boundaries.
var lifecycleCoverage = map[string][]string{
	"cached-token-metadata-outage":                     {"TestCachedUnboundUnsafeDeliveryAfterProviderRecreation"},
	"unbound-preemptive-unsafe-delivery":               {"TestCachedUnboundUnsafeDeliveryAfterProviderRecreation"},
	"unbound-lookup-anonymous-fallback":                {"TestUnboundLookupAnonymousFallback", "TestUnboundLookupFailuresAreNotAnonymous", "TestUnboundLookupStaleBindingIdentity"},
	"unbound-lookup-refreshes-expired-token":           {"TestUnboundLookupRefreshesExpiredToken"},
	"refresh-unknown-expiry-rotation":                  {"TestLifecycleRefreshUnknownExpiryRotation", "TestCanonicalTokenResponses", "TestLifecycleRotationPersistsPastCancellation"},
	"transient-refresh-failure":                        {"TestManagedTemporaryRefreshRetainsAndDefinitiveRejectionRepairs", "TestLifecycleNonOAuthRefreshFailureRetainsRetry", "TestManagedCancellationLeavesAmbiguityAndReleasesCoordination"},
	"refresh-invalid-grant-drops-tokens":               {"TestLifecycleRefreshInvalidGrant"},
	"refresh-invalid-grant-stale-does-not-wipe":        {"TestLifecycleRefreshInvalidGrant"},
	"token-validation-failure-clears-in-flight":        {"TestLifecycleTokenValidationFailureClearsInFlight", "TestLifecycleTokenValidity"},
	"client-credentials-transient-reissue":             {"TestClientCredentialsTransientReissueWithoutLogin", "TestLifecycleClientCredentialsTransientReissue"},
	"delivery-never-creates-pending-login":             {"TestLifecycleDeliveryNeverCreatesPendingLogin"},
	"pending-login-fixed-lifetime":                     {"TestPendingLoginFixedLifetime"},
	"pending-login-cross-process-completion":           {"TestPendingLoginCrossProcessCompletion"},
	"pending-login-reuse":                              {"TestPendingLoginReuse", "TestPendingLoginReuseAcrossCeilings"},
	"pending-login-supersede":                          {"TestPendingLoginSupersede"},
	"pending-login-supersede-scope-union":              {"TestPendingLoginSupersedeScopeUnion", "TestPendingLoginSupersedeCeilingUnion"},
	"pending-login-end-states":                         {"TestPendingLoginEndStates"},
	"metadata-and-secret-rotation":                     {"TestMetadataCapabilityAndRuntimeSecretRotation", "TestLifecycleCompletionUsesCurrentSecretAndPolicy"},
	"scope-ceiling-widening-keeps-grant":               {"TestLifecycleScopeCeilingWideningKeepsGrant", "TestCanonicalGrantKeys"},
	"insufficient-scope-step-up":                       {"TestLifecycleStepUpRoundTrip", "TestInsufficientScopeTransport", "TestLifecycleInsufficientScopeKeepsToken"},
	"step-up-requirement-operation-scoped":             {"TestLifecycleStepUpRequirementOperationScoped"},
	"step-up-required-scopes-round-trip":               {"TestLifecycleStepUpRoundTrip"},
	"challenged-replay-once":                           {"TestManagedChallengedReplayOnce", "TestChallengedReplayMethods"},
	"configured-preset-no-protected-resource-metadata": {"TestMetadataCapabilityAndRuntimeSecretRotation", "TestCanonicalTokenResponses"},
	"explicit-shared-grant":                            {"TestGrantSharingRequiresPartitionAndIndependentApproval"},
	"invalid-callback-does-not-consume":                {"TestManagedCallbackBindingAndNoImplicitConsent"},
	"loopback-redirect":                                {"TestLifecycleLiteralLoopbackRedirect"},
	"narrowed-refresh-scope-inheritance":               {"TestLifecycleRefreshUsesPreviousGrant", "TestCanonicalTokenResponses"},
	"scope-challenge-without-required-scope":           {"TestLifecycleNoScopeChallengeUsesOnlyHostRequirement"},
	"refresh-broadening-scope-ignored":                 {"TestLifecycleRefreshUsesPreviousGrant", "TestCanonicalTokenResponses"},
	"scope-ceiling-narrowing-keeps-grant":              {"TestLifecycleScopeCeilingNarrowingKeepsGrant", "TestCanonicalTokenResponses"},
	"unreplayed-challenge-prepares-next-attempt":       {"TestUnreplayedChallengePreparesNextAttempt"},
	"up-front-refresh-failure-no-anonymous-fallback":   {"TestUpFrontRefreshFailureNoAnonymousFallback"},
	"prepare-required-outside-ceiling-denied":          {"TestLifecyclePrepareRequiredOutsideCeilingDenied"},
	"up-front-client-credentials-reacquire":            {"TestUpFrontClientCredentialsReacquire"},
	"up-front-lookup-issuer-metadata-only":             {"TestUpFrontLookupIssuerMetadataOnly", "TestChangedIssuerRepairedByDiscovery"},
	"known-binding-without-token-requires-login":       {"TestKnownBindingWithoutTokenRequiresLogin"},
	"challenge-renews-rejected-unexpired-token":        {"TestChallengeRenewsRejectedUnexpiredToken", "TestManagedResourceBoundRefreshAndStaleRejection", "TestRejectedTokenPersistedBeforeFailedRenewal"},
	"step-up-keeps-previous-grant":                     {"TestLifecycleStepUpKeepsPreviousGrant", "TestCanonicalTokenResponses"},
	"stale-metadata-refetch-once":                      {"TestStaleMetadataRefetchOnce"},
	"ambiguous-renewal-failure-no-refetch":             {"TestAmbiguousRenewalFailureNoRefetch"},
	"extra-granted-scope-ignored":                      {"TestLifecycleExtraGrantedScopeIgnored", "TestCanonicalTokenResponses"},
}

func TestLifecycleCoverageManifest(t *testing.T) {
	data, err := os.ReadFile("testdata/sdk-auth-lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Lifecycle []struct {
			ID string `json:"id"`
		} `json:"lifecycle"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	tests := map[string]bool{}
	for _, dir := range []string{".", ".."} {
		files, _ := filepath.Glob(filepath.Join(dir, "*_test.go"))
		for _, file := range files {
			parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			for _, decl := range parsed.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
					tests[fn.Name.Name] = true
				}
			}
		}
	}
	ids := map[string]bool{}
	for _, entry := range fixture.Lifecycle {
		ids[entry.ID] = true
		names := lifecycleCoverage[entry.ID]
		if len(names) == 0 {
			t.Errorf("lifecycle id %q has no native test", entry.ID)
		}
		for _, name := range names {
			if !tests[name] {
				t.Errorf("lifecycle id %q maps to missing test %s", entry.ID, name)
			}
		}
	}
	for id := range lifecycleCoverage {
		if !ids[id] {
			t.Errorf("coverage maps unknown lifecycle id %q", id)
		}
	}
}
