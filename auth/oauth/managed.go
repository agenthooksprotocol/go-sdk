package oauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"github.com/agenthooksprotocol/go-sdk/internal/authutil"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var _ auth.Provider = (*Provider)(nil)
var _ auth.PreemptiveProvider = (*Provider)(nil)

const maxLoginLifetime = 10 * time.Minute

// lookupBudget bounds an up-front renewal whose context has no deadline.
const lookupBudget = 30 * time.Second

// New requires explicit host network, identity, persistence and token-validation
// policy. No default HTTP client, store, issuer or background task is installed.
func New(options Options) (*Provider, error) {
	if options.Namespace == "" || options.Store == nil || options.HTTPClient == nil || options.HTTPClient.Transport == nil || options.CheckDestination == nil || options.SelectClient == nil || options.ValidateToken == nil || options.LoginLifetime < 0 || options.LoginLifetime > maxLoginLifetime {
		return nil, fail(auth.CodeInvalidConfiguration)
	}
	if options.LoginLifetime == 0 {
		options.LoginLifetime = maxLoginLifetime
	}
	client := *options.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	return &Provider{options: options, client: client}, nil
}

// fail builds an SDK error from an SDK-chosen code and optional required scopes.
func fail(code auth.Code, required ...string) error {
	return &auth.Error{Code: code, Scopes: merge(nil, required...)}
}

// safe is the error-copy boundary for host callbacks: only an allowlisted
// auth.Error code survives, never the host's error chain.
func safe(ctx context.Context, err error, fallback auth.Code) error {
	if ctx.Err() != nil {
		return errors.Join(fail(fallback), ctx.Err())
	}
	if classified := auth.Classify(err); classified != nil {
		return classified
	}
	return fail(fallback)
}
func bounded(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		return fail(auth.CodeInvalidConfiguration)
	}
	return nil
}
func (p *Provider) check(ctx context.Context, raw string, purpose Purpose) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !discoveryHTTPS(raw) {
		return fail(auth.CodeUntrustedDestination)
	}
	if err := p.options.CheckDestination(ctx, raw, purpose); err != nil {
		return safe(ctx, err, auth.CodeUntrustedDestination)
	}
	return ctx.Err()
}
func contains(values []string, value string) bool { return slices.Contains(values, value) }

// merge returns the sorted, deduplicated union of scope sets.
func merge(scopes []string, more ...string) []string {
	result := append(append([]string(nil), scopes...), more...)
	slices.Sort(result)
	return slices.Compact(result)
}
func intersect(scopes, ceiling []string) []string {
	var result []string
	for _, scope := range merge(scopes) {
		if contains(ceiling, scope) {
			result = append(result, scope)
		}
	}
	return result
}

// requested is what the SDK asks for: requested and required scopes within the ceiling.
func requested(c ClientConfig) []string {
	return intersect(merge(c.Scopes, c.RequiredScopes...), allowedScopes(c))
}
func sameScopes(a, b []string) bool { return slices.Equal(merge(a), merge(b)) }
func scopeSubset(scopes, ceiling []string) bool {
	for _, s := range scopes {
		if !contains(ceiling, s) {
			return false
		}
	}
	return true
}
func allowedScopes(c ClientConfig) []string {
	if c.AllowedScopes != nil {
		return c.AllowedScopes
	}
	return c.Scopes
}
func validConfig(c ClientConfig) bool {
	if !discoveryIssuer(c.Issuer) || !discoveryHTTPS(c.Resource) || c.ClientID == "" || (c.Flow != "authorization_code_pkce" && c.Flow != "client_credentials") {
		return false
	}
	for _, scope := range merge(merge(c.Scopes, allowedScopes(c)...), c.RequiredScopes...) {
		if !authutil.ValidScope(scope) {
			return false
		}
	}
	if c.Flow == "client_credentials" {
		return c.ClientSecret != ""
	}
	redirect, err := url.Parse(c.RedirectURI)
	if err != nil || !authutil.ValidURL(c.RedirectURI, true) || redirect.RawQuery != "" || redirect.ForceQuery {
		return false
	}
	return redirect.Scheme == "https" || (redirect.Scheme == "http" && net.ParseIP(redirect.Hostname()) != nil && net.ParseIP(redirect.Hostname()).IsLoopback())
}
func cloneRequest(r auth.Request) auth.Request {
	r.Binding = append(json.RawMessage(nil), r.Binding...)
	return r
}
func cloneRecord(r *Record) *Record {
	if r == nil {
		return nil
	}
	copy := *r
	copy.Scopes = append([]string(nil), r.Scopes...)
	if r.Binding != nil {
		b := *r.Binding
		b.Config = cloneConfig(b.Config)
		b.IssuerMetadata.GrantTypes = append([]string(nil), b.IssuerMetadata.GrantTypes...)
		b.IssuerMetadata.ChallengeMethods = append([]string(nil), b.IssuerMetadata.ChallengeMethods...)
		b.IssuerMetadata.TokenAuthMethods = append([]string(nil), b.IssuerMetadata.TokenAuthMethods...)
		copy.Binding = &b
	}
	if r.Pending != nil {
		pending := *r.Pending
		pending.Scopes = append([]string(nil), pending.Scopes...)
		pending.Ceiling = append([]string(nil), pending.Ceiling...)
		copy.Pending = &pending
	}
	return &copy
}
func randomID() string {
	var b [32]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic("crypto/rand failed")
	}
	return hex.EncodeToString(b[:])
}
func requestIdentity(r auth.Request) string {
	target, err := auth.NormalizeTarget(r)
	if err != nil {
		return ""
	}
	binding, _ := target.OAuth()
	binding.Scopes = merge(binding.Scopes)
	encoded, _ := json.Marshal([]any{r.BackendID, r.Purpose, r.Destination, target.Kind(), binding})
	return string(encoded)
}
func cloneConfig(c ClientConfig) ClientConfig {
	c.Scopes = append([]string(nil), c.Scopes...)
	if c.AllowedScopes != nil {
		c.AllowedScopes = append([]string{}, c.AllowedScopes...)
	}
	c.RequiredScopes = append([]string(nil), c.RequiredScopes...)
	return c
}
func frame(prefix string, fields ...string) string {
	for _, field := range fields {
		prefix += strconv.Itoa(len(field)) + ":" + field
	}
	return prefix
}
func (p *Provider) bindingKey(r auth.Request) string {
	return frame("ahp.oauth.binding:", p.options.Namespace, r.BackendID, string(r.Purpose), r.Destination)
}

// key is the grant identity. The allowed ceiling is re-intersected at use, so
// changing it never orphans a grant.
func (p *Provider) key(r auth.Request, c ClientConfig) string {
	partition := "binding:" + p.bindingKey(r)
	if c.GrantPartition != "" {
		partition = "shared:" + c.GrantPartition
	}
	return frame("ahp.oauth.grant:", p.options.Namespace, c.Issuer, c.Resource, c.ClientID, c.Flow, partition)
}
func usable(record *Record) bool {
	return record != nil && authutil.ValidBearer(record.AccessToken) && (record.ExpiresAt.IsZero() || record.ExpiresAt.After(time.Now().Add(10*time.Second)))
}

// satisfies reports whether a record can serve c: a live token whose recorded
// grant, within the current ceiling, covers every required scope.
func satisfies(record *Record, c ClientConfig) bool {
	return usable(record) && scopeSubset(c.RequiredScopes, intersect(record.Scopes, allowedScopes(c)))
}

// errStaleBinding marks a stored binding whose grant identity no longer
// matches current policy. Discovery (prepare, challenge) rebuilds it.
var errStaleBinding = &auth.Error{Code: auth.CodeDiscoveryFailed}

// refusal marks a host SelectClient refusal of a stored binding.
type refusal struct{ error }

func (r refusal) Unwrap() error { return r.error }

// cachedBinding revalidates stored binding metadata against current local policy.
func (p *Provider) cachedBinding(ctx context.Context, r auth.Request) (ClientConfig, metadata, bool, error) {
	stored, err := p.options.Store.Load(ctx, p.bindingKey(r))
	if err != nil {
		return ClientConfig{}, metadata{}, false, safe(ctx, err, auth.CodeProviderFailed)
	}
	if stored == nil || stored.Binding == nil {
		return ClientConfig{}, metadata{}, false, nil
	}
	b := stored.Binding
	c, err := p.options.SelectClient(ctx, cloneRequest(r), []string{b.Config.Issuer}, b.Config.Resource)
	if err != nil {
		return ClientConfig{}, metadata{}, false, refusal{safe(ctx, err, auth.CodeUntrustedDestination)}
	}
	c = cloneConfig(c)
	if !validConfig(c) {
		return ClientConfig{}, metadata{}, false, fail(auth.CodeInvalidConfiguration)
	}
	target, err := auth.NormalizeTarget(r)
	if err != nil {
		return ClientConfig{}, metadata{}, false, err
	}
	if target.Kind() == auth.BindingBearer {
		return ClientConfig{}, metadata{}, false, fail(auth.CodeUnsupportedBinding)
	}
	if preset, explicit := target.OAuth(); explicit && (c.Issuer != preset.Issuer || c.Resource != preset.Resource || c.ClientID != preset.ClientID || c.Flow != preset.Flow || !sameScopes(c.Scopes, preset.Scopes)) {
		return ClientConfig{}, metadata{}, false, fail(auth.CodeInvalidConfiguration)
	}
	if p.key(r, c) != p.key(r, b.Config) {
		// Policy now selects another client, flow or partition: the stored
		// binding is stale until discovery rebuilds it.
		return ClientConfig{}, metadata{}, false, errStaleBinding
	}
	return c, b.IssuerMetadata, true, nil
}

// persistBinding records freshly discovered, secret-free binding metadata.
// Operation requirements are never persisted. A lost race keeps the other
// writer's equally fresh metadata.
func (p *Provider) persistBinding(ctx context.Context, r auth.Request, c ClientConfig, m metadata) error {
	key := p.bindingKey(r)
	old, err := p.options.Store.Load(ctx, key)
	if err != nil {
		return safe(ctx, err, auth.CodeProviderFailed)
	}
	public := cloneConfig(c)
	public.ClientSecret, public.RequiredScopes = "", nil
	_, err = p.options.Store.CompareAndSwap(ctx, key, generation(old), &Record{Generation: randomID(), Binding: &BindingMetadata{Config: public, IssuerMetadata: m}})
	if err != nil {
		return safe(ctx, err, auth.CodeProviderFailed)
	}
	return nil
}

type attempted struct {
	owner                *Provider
	key, token, identity string
}

func (attempted) String() string   { return "oauth.attempt{redacted}" }
func (attempted) GoString() string { return "oauth.attempt{redacted}" }
func (p *Provider) credential(r auth.Request, key string, record *Record) *auth.Credential {
	return &auth.Credential{Type: "bearer", Token: record.AccessToken, Attempt: attempted{p, key, record.AccessToken, requestIdentity(r)}}
}

// challengeScopes returns the validated scope requirement of a Bearer challenge.
func challengeScopes(challenge string) ([]string, error) {
	required, err := bearerParameter(challenge, "scope")
	if err != nil {
		return nil, fail(auth.CodeDiscoveryFailed)
	}
	if required != "" && !authutil.ValidScopeList(required) {
		return nil, fail(auth.CodeAccessDenied)
	}
	return strings.Fields(required), nil
}

// Prepare is the host-controlled interaction entrypoint. The context MUST carry
// a deadline for its network work; a created login outlives it. A Login never
// starts a listener or browser. Required scopes are explicit operation
// requirements, typically the Scopes of an interaction_required error after a
// step-up challenge; they must be within the allowed ceiling.
func (p *Provider) Prepare(ctx context.Context, r auth.Request, required ...string) (Preparation, error) {
	for _, scope := range required {
		if !authutil.ValidScope(scope) {
			return Preparation{}, fail(auth.CodeInvalidConfiguration)
		}
	}
	return p.prepare(ctx, cloneRequest(r), "", required, false, true)
}

// prepare serves a cached grant, refreshes or reissues it, or (only when
// interactive) creates a stored login. A step-up challenge requirement applies
// to this call alone.
func (p *Provider) prepare(ctx context.Context, r auth.Request, challenge string, explicit []string, stepUp, interactive bool) (Preparation, error) {
	if err := bounded(ctx); err != nil {
		return Preparation{}, err
	}
	challenged, err := challengeScopes(challenge)
	if err != nil {
		return Preparation{}, err
	}
	require := func(c ClientConfig) (ClientConfig, error) {
		// Without a challenged scope, only an explicit host requirement justifies step-up.
		if stepUp && len(challenged) == 0 && len(c.RequiredScopes) == 0 {
			return c, fail(auth.CodeAccessDenied)
		}
		c.RequiredScopes = merge(merge(c.RequiredScopes, explicit...), challenged...)
		if !scopeSubset(c.RequiredScopes, allowedScopes(c)) {
			return c, fail(auth.CodeAccessDenied, c.RequiredScopes...)
		}
		return c, nil
	}
	config, m, cached, err := p.cachedBinding(ctx, r)
	if err != nil && err != errStaleBinding {
		return Preparation{}, safe(ctx, err, auth.CodeDiscoveryFailed)
	}
	if cached {
		// A usable grant requires no remote metadata or store write.
		if config, err = require(config); err != nil {
			return Preparation{}, err
		}
		key := p.key(r, config)
		current, err := p.options.Store.Load(ctx, key)
		if err != nil {
			return Preparation{}, safe(ctx, err, auth.CodeProviderFailed)
		}
		if satisfies(current, config) {
			return Preparation{Credential: p.credential(r, key, current)}, nil
		}
		// Renewal refreshes the stored issuer's capabilities; if that fails
		// (e.g. the issuer changed), full discovery repairs the binding.
		if config, m, err = p.resolveMetadata(ctx, config); err != nil {
			if ctx.Err() != nil {
				return Preparation{}, safe(ctx, err, auth.CodeDiscoveryFailed)
			}
			cached = false
		}
	}
	if !cached {
		if config, m, err = p.resolve(ctx, r, challenge); err != nil {
			return Preparation{}, safe(ctx, err, auth.CodeDiscoveryFailed)
		}
		if config, err = require(config); err != nil {
			return Preparation{}, err
		}
	}
	if err = p.persistBinding(ctx, r, config, m); err != nil {
		return Preparation{}, err
	}
	return p.acquire(ctx, r, p.key(r, config), config, m, stepUp, interactive)
}

// acquire runs under the grant lock: it rechecks the stored grant, then
// refreshes, reissues client credentials or (only when interactive) creates a
// stored login.
func (p *Provider) acquire(ctx context.Context, r auth.Request, key string, config ClientConfig, m metadata, stepUp, interactive bool) (Preparation, error) {
	result, err, _ := p.acquireOnce(ctx, r, key, config, m, stepUp, interactive)
	return result, err
}

// acquireOnce also reports whether the token endpoint failed without an
// OAuth error response, i.e. the metadata used may be stale.
func (p *Provider) acquireOnce(ctx context.Context, r auth.Request, key string, config ClientConfig, m metadata, stepUp, interactive bool) (Preparation, error, bool) {
	var result Preparation
	err := p.options.Store.Coordinate(ctx, key, func(ctx context.Context) error {
		record, err := p.options.Store.Load(ctx, key)
		if err != nil {
			return safe(ctx, err, auth.CodeProviderFailed)
		}
		record = cloneRecord(record)
		if satisfies(record, config) {
			result.Credential = p.credential(r, key, record)
			return nil
		}
		next := record
		switch {
		case config.Flow == "client_credentials":
			next, err = p.machine(ctx, key, config, m, record)
		case record != nil && record.RefreshToken != "" && !usable(record):
			next, err = p.refresh(ctx, key, config, m, record)
		}
		if err != nil {
			return err
		}
		if satisfies(next, config) {
			result.Credential = p.credential(r, key, next)
			return nil
		}
		if config.Flow == "client_credentials" || (!stepUp && !interactive && usable(next)) {
			// A live grant lacks an explicit requirement: refresh cannot broaden it.
			return fail(auth.CodeAccessDenied, config.RequiredScopes...)
		}
		if !interactive {
			return fail(auth.CodeInteractionRequired, config.RequiredScopes...)
		}
		result.Login, err = p.login(ctx, key, next, config, m)
		return err
	})
	if err != nil {
		return Preparation{}, safe(ctx, err, auth.CodeProviderFailed), errors.Is(err, errEndpoint)
	}
	return result, nil, false
}
func generation(r *Record) string {
	if r == nil {
		return ""
	}
	return r.Generation
}
func (p *Provider) save(ctx context.Context, key, expected string, next *Record) error {
	ok, err := p.options.Store.CompareAndSwap(ctx, key, expected, cloneRecord(next))
	if err != nil {
		return safe(ctx, err, auth.CodeProviderFailed)
	}
	if !ok {
		return fail(auth.CodeProviderFailed)
	}
	return nil
}

// validExpiry accepts an absent expires_in (unknown expiry), a positive JSON
// integer, or a string of ASCII digits with a positive value.
func validExpiry(token *oauth2.Token) bool {
	if token.Extra(invalidExpiry) != nil || (!token.Expiry.IsZero() && !token.Expiry.After(time.Now())) {
		return false
	}
	switch value := token.Extra("expires_in").(type) {
	case nil:
		return true
	case float64:
		return value > 0 && value == math.Trunc(value) && !math.IsInf(value, 0)
	case string:
		digits := value != "" && strings.Trim(value, "0123456789") == ""
		return digits && strings.Trim(value, "0") != ""
	}
	return false
}

// validRefresh checks RFC 6749 refresh-token grammar (VSCHAR).
func validRefresh(token string) bool {
	for _, c := range token {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return token != ""
}

// grant converts a token response after a code or refresh token was spent.
// Granted scopes are response scopes within the acquisition ceiling: the
// pending login's or client-credentials caller's ceiling initially, the
// previous grant on refresh. Others are ignored; the current caller's ceiling
// applies only at use. An invalid initial response yields no
// record, so nothing is persisted. An invalid refresh response yields the
// previous record without its access token, keeping a valid rotated refresh
// token, so the caller never leaves in-flight state behind.
func (p *Provider) grant(ctx context.Context, c ClientConfig, ceiling []string, token *oauth2.Token, previous *Record) (*Record, error) {
	response := c.Scopes
	if previous != nil {
		response = previous.Scopes
	}
	valid := strings.EqualFold(token.TokenType, "Bearer") && authutil.ValidBearer(token.AccessToken) && validExpiry(token)
	if extra := token.Extra("scope"); extra != nil {
		value, ok := extra.(string)
		if !ok || (value != "" && !authutil.ValidScopeList(value)) {
			valid = false
		} else {
			response = strings.Fields(value)
		}
	}
	var err error
	if !valid {
		err = fail(auth.CodeProviderFailed)
	} else if hostErr := p.options.ValidateToken(ctx, c, token); hostErr != nil {
		err = safe(ctx, hostErr, auth.CodeAccessDenied)
	}
	if err != nil {
		if previous == nil {
			return nil, err
		}
		kept := cloneRecord(previous)
		kept.AccessToken, kept.ExpiresAt, kept.Generation = "", time.Time{}, randomID()
		if validRefresh(token.RefreshToken) {
			kept.RefreshToken = token.RefreshToken
		}
		return kept, err
	}
	next := &Record{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ExpiresAt: token.Expiry, Scopes: intersect(response, ceiling), Generation: randomID()}
	if previous != nil {
		next.Pending = previous.Pending
	}
	if !validRefresh(next.RefreshToken) {
		next.RefreshToken = ""
		if previous != nil {
			next.RefreshToken = previous.RefreshToken
		}
	}
	return next, nil
}

// persistBudget bounds persisting a spent exchange's outcome.
const persistBudget = time.Minute

// persisting detaches a store write from caller cancellation: once a code or
// refresh token is spent, losing its outcome would lose the rotated token.
func persisting(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), persistBudget)
}

// commit persists a spent exchange's outcome, then reports its validation error.
func (p *Provider) commit(ctx context.Context, key, expected string, next *Record, err error) (*Record, error) {
	if next == nil {
		return nil, err
	}
	ctx, cancel := persisting(ctx)
	defer cancel()
	if saveErr := p.save(ctx, key, expected, next); saveErr != nil {
		return nil, saveErr
	}
	return next, err
}

func authStyle(c ClientConfig) oauth2.AuthStyle {
	if c.TokenAuthMethod == "client_secret_basic" {
		return oauth2.AuthStyleInHeader
	}
	return oauth2.AuthStyleInParams
}
func oauthConfig(c ClientConfig, m metadata) *oauth2.Config {
	return &oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: c.RedirectURI, Scopes: append([]string(nil), c.Scopes...), Endpoint: oauth2.Endpoint{AuthURL: m.AuthorizationEndpoint, TokenURL: m.TokenEndpoint, AuthStyle: authStyle(c)}}
}

// machine issues a client-credentials grant. Re-acquisition for an existing
// grant also requests and keeps its previously granted scopes.
func (p *Provider) machine(ctx context.Context, key string, c ClientConfig, m metadata, previous *Record) (*Record, error) {
	var granted []string
	if previous != nil {
		granted = previous.Scopes
	}
	c.Scopes = merge(granted, requested(c)...)
	conf := clientcredentials.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, TokenURL: m.TokenEndpoint, Scopes: c.Scopes, AuthStyle: authStyle(c), EndpointParams: url.Values{"resource": {c.Resource}}}
	token, err := conf.Token(context.WithValue(ctx, oauth2.HTTPClient, p.tokenClient(c, m, nil)))
	if err != nil {
		return nil, acquisitionError(ctx, err, false)
	}
	next, err := p.grant(ctx, c, merge(granted, allowedScopes(c)...), token, nil)
	return p.commit(ctx, key, generation(previous), next, err)
}

// errEndpoint marks a token request the endpoint provably did not process
// (DNS, TCP connect or TLS handshake failure, or HTTP 404/410): persisted
// metadata may be stale, and a retry cannot replay a spent refresh token.
// It never reaches callers; acquireOnce reports it as a flag.
var errEndpoint = &auth.Error{Code: auth.CodeProviderFailed}

// unsent reports a transport failure before the request reached the endpoint.
func unsent(err error) bool {
	var dns *net.DNSError
	var op *net.OpError
	var verify *tls.CertificateVerificationError
	var header tls.RecordHeaderError
	var alert tls.AlertError
	return errors.As(err, &dns) || (errors.As(err, &op) && op.Op == "dial") || errors.As(err, &verify) || errors.As(err, &header) || errors.As(err, &alert)
}

func acquisitionError(ctx context.Context, err error, interactive bool) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var rejected *oauth2.RetrieveError
	if errors.Is(err, errEndpoint) || (errors.As(err, &rejected) && rejected.Response != nil && (rejected.Response.StatusCode == http.StatusNotFound || rejected.Response.StatusCode == http.StatusGone)) {
		return errEndpoint
	}
	// Anything else may have been processed: no refetch, no immediate retry.
	if rejected == nil {
		return fail(auth.CodeProviderFailed)
	}
	switch rejected.ErrorCode {
	case "invalid_grant":
		if interactive {
			return fail(auth.CodeInteractionRequired)
		}
		return fail(auth.CodeCredentialUnavailable)
	case "invalid_client", "unauthorized_client", "unsupported_grant_type":
		return fail(auth.CodeInvalidConfiguration)
	case "access_denied", "invalid_scope":
		return fail(auth.CodeAccessDenied)
	}
	return fail(auth.CodeProviderFailed)
}

// refresh never broadens the previous grant. Transient failures keep the
// record untouched; a definitive invalid_grant drops both tokens.
func (p *Provider) refresh(ctx context.Context, key string, c ClientConfig, m metadata, previous *Record) (*Record, error) {
	conf := oauthConfig(c, m)
	var rotated string
	token, err := conf.TokenSource(context.WithValue(ctx, oauth2.HTTPClient, p.tokenClient(c, m, &rotated)), &oauth2.Token{RefreshToken: previous.RefreshToken, Expiry: time.Now().Add(-time.Minute)}).Token()
	var rejected *oauth2.RetrieveError
	if err != nil && ctx.Err() == nil && !errors.As(err, &rejected) && validRefresh(rotated) {
		// x/oauth2 rejected a 2xx response it could not decode: keep its
		// rotated refresh token and report the invalid response.
		kept := cloneRecord(previous)
		kept.AccessToken, kept.RefreshToken, kept.ExpiresAt, kept.Generation = "", rotated, time.Time{}, randomID()
		_, err = p.commit(ctx, key, previous.Generation, kept, fail(auth.CodeProviderFailed))
		return nil, err
	}
	if err != nil {
		if ctx.Err() == nil && rejected != nil && rejected.ErrorCode == "invalid_grant" {
			// Compare-and-delete: a newer record (lost CAS) is kept.
			dropped := cloneRecord(previous)
			dropped.AccessToken, dropped.RefreshToken, dropped.ExpiresAt, dropped.Generation = "", "", time.Time{}, randomID()
			persist, cancel := persisting(ctx)
			defer cancel()
			if _, saveErr := p.options.Store.CompareAndSwap(persist, key, previous.Generation, dropped); saveErr != nil {
				return nil, safe(ctx, saveErr, auth.CodeProviderFailed)
			}
			return nil, fail(auth.CodeRefreshRejected)
		}
		return nil, acquisitionError(ctx, err, false)
	}
	next, err := p.grant(ctx, c, previous.Scopes, token, previous)
	return p.commit(ctx, key, previous.Generation, next, err)
}

// login reuses an unexpired stored login whose scopes cover the new request.
// Otherwise it creates one requesting any previously granted scopes, any
// superseded login's scopes and the new ceiling-filtered request; its stored
// ceiling (bounding the grant recorded on completion) is the union of both
// callers' ceilings. Both sets only grow, so alternating callers converge. Its lifetime is fixed here and
// does not depend on the caller's context.
func (p *Provider) login(ctx context.Context, key string, record *Record, c ClientConfig, m metadata) (*PendingLogin, error) {
	wanted := requested(c)
	ceiling := merge(allowedScopes(c))
	c.Scopes = wanted
	if record != nil {
		c.Scopes = merge(record.Scopes, wanted...)
	}
	now := time.Now()
	if record != nil && record.Pending != nil && record.Pending.ExpiresAt.After(now) {
		pending := record.Pending
		if pending.RedirectURI == c.RedirectURI {
			if scopeSubset(wanted, pending.Scopes) {
				return &PendingLogin{authorizationURL: pending.AuthorizationURL, deadline: pending.ExpiresAt}, nil
			}
			// Same grant and redirect: only the scopes differ, so merge.
			c.Scopes = merge(c.Scopes, pending.Scopes...)
			ceiling = merge(ceiling, pending.Ceiling...)
		}
	}
	verifier := oauth2.GenerateVerifier()
	state := randomID()
	loginURL := oauthConfig(c, m).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("resource", c.Resource))
	if err := p.check(ctx, loginURL, Authorization); err != nil {
		return nil, err
	}
	next := cloneRecord(record)
	if next == nil {
		next = &Record{}
	}
	next.Generation = randomID()
	next.Pending = &PendingRecord{State: state, Verifier: verifier, RedirectURI: c.RedirectURI, AuthorizationURL: loginURL, Scopes: c.Scopes, Ceiling: ceiling, ExpiresAt: now.Add(p.options.LoginLifetime)}
	if err := p.save(ctx, key, generation(record), next); err != nil {
		return nil, err
	}
	return &PendingLogin{authorizationURL: loginURL, deadline: next.Pending.ExpiresAt}, nil
}

// Cancel abandons the stored pending login for r. It never changes stored tokens.
func (p *Provider) Cancel(ctx context.Context, r auth.Request) error {
	r = cloneRequest(r)
	config, _, cached, err := p.cachedBinding(ctx, r)
	if err == errStaleBinding {
		return nil
	}
	if err != nil {
		return safe(ctx, err, auth.CodeProviderFailed)
	}
	if !cached {
		return nil
	}
	key := p.key(r, config)
	return p.options.Store.Coordinate(ctx, key, func(ctx context.Context) error {
		record, err := p.options.Store.Load(ctx, key)
		if err != nil {
			return safe(ctx, err, auth.CodeProviderFailed)
		}
		if record == nil || record.Pending == nil {
			return nil
		}
		next := cloneRecord(record)
		next.Pending, next.Generation = nil, randomID()
		return p.save(ctx, key, record.Generation, next)
	})
}

// Complete validates one callback against the stored login for r and performs
// a single bounded code exchange. Any process sharing the Store may complete it.
// An invalid callback never consumes the login; a superseded, cancelled,
// expired or already used login fails with interaction_required.
func (p *Provider) Complete(ctx context.Context, r auth.Request, callback string) (auth.Credential, error) {
	if err := bounded(ctx); err != nil {
		return auth.Credential{}, err
	}
	r = cloneRequest(r)
	value, err := url.Parse(callback)
	if err != nil || value.User != nil || strings.Contains(callback, "#") {
		return auth.Credential{}, fail(auth.CodeAccessDenied)
	}
	query, err := url.ParseQuery(value.RawQuery)
	if err != nil || len(query["state"]) != 1 || len(query["error"]) > 1 || (query.Get("error") == "" && (len(query["code"]) != 1 || query.Get("code") == "")) {
		return auth.Credential{}, fail(auth.CodeAccessDenied)
	}
	// Resolve current secrets, policy and capabilities: the stored login never
	// makes a captured runtime secret authoritative.
	config, m, cached, err := p.cachedBinding(ctx, r)
	if err == nil && !cached {
		err = fail(auth.CodeInteractionRequired)
	}
	if err == nil {
		config, m, err = p.resolveMetadata(ctx, config)
	}
	if err != nil {
		return auth.Credential{}, safe(ctx, err, auth.CodeDiscoveryFailed)
	}
	key := p.key(r, config)
	var credential *auth.Credential
	err = p.options.Store.Coordinate(ctx, key, func(ctx context.Context) error {
		record, err := p.options.Store.Load(ctx, key)
		if err != nil {
			return safe(ctx, err, auth.CodeProviderFailed)
		}
		var pending *PendingRecord
		if record != nil {
			pending = record.Pending
		}
		if pending == nil || !pending.ExpiresAt.After(time.Now()) || subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(pending.State)) != 1 {
			return fail(auth.CodeInteractionRequired)
		}
		redirect, _ := url.Parse(pending.RedirectURI)
		if value.Scheme != redirect.Scheme || value.Host != redirect.Host || value.EscapedPath() != redirect.EscapedPath() {
			return fail(auth.CodeAccessDenied)
		}
		if issuer := query["iss"]; len(issuer) > 1 || (len(issuer) == 1 && issuer[0] != config.Issuer) || (m.ResponseIssuer && len(issuer) != 1) {
			return fail(auth.CodeAccessDenied)
		}
		// Claim the valid callback once before the exchange.
		claimed := cloneRecord(record)
		claimed.Pending, claimed.Generation = nil, randomID()
		if err := p.save(ctx, key, record.Generation, claimed); err != nil {
			return err
		}
		if query.Get("error") != "" {
			return fail(auth.CodeAccessDenied)
		}
		exchange := cloneConfig(config)
		exchange.Scopes, exchange.RedirectURI = pending.Scopes, pending.RedirectURI
		token, err := oauthConfig(exchange, m).Exchange(context.WithValue(ctx, oauth2.HTTPClient, p.tokenClient(exchange, m, nil)), query.Get("code"), oauth2.VerifierOption(pending.Verifier), oauth2.SetAuthURLParam("resource", exchange.Resource))
		if err != nil {
			return acquisitionError(ctx, err, true)
		}
		next, err := p.grant(ctx, exchange, merge(pending.Ceiling, record.Scopes...), token, nil)
		if next, err = p.commit(ctx, key, claimed.Generation, next, err); err != nil {
			return err
		}
		if !satisfies(next, config) {
			return fail(auth.CodeAccessDenied)
		}
		credential = p.credential(r, key, next)
		return nil
	})
	if err != nil {
		return auth.Credential{}, safe(ctx, err, auth.CodeProviderFailed)
	}
	return *credential, nil
}

func (p *Provider) Credential(ctx context.Context, r auth.Request) (auth.Credential, error) {
	if err := ctx.Err(); err != nil {
		return auth.Credential{}, err
	}
	if len(r.Binding) == 0 {
		stored, err := p.options.Store.Load(ctx, p.bindingKey(r))
		if err != nil {
			return auth.Credential{}, safe(ctx, err, auth.CodeProviderFailed)
		}
		if stored == nil || stored.Binding == nil {
			return auth.Credential{}, fail(auth.CodeCredentialUnavailable)
		}
	}
	result, err := p.prepare(ctx, cloneRequest(r), "", nil, false, false)
	if err != nil {
		return auth.Credential{}, err
	}
	return *result.Credential, nil
}

// Challenge drops the rejected token, then recovers without creating a login.
func (p *Provider) Challenge(ctx context.Context, r auth.Request, c auth.Challenge) (*auth.Credential, error) {
	if err := bounded(ctx); err != nil {
		return nil, err
	}
	header := strings.Join(c.Header.Values("WWW-Authenticate"), ", ")
	if c.StatusCode != http.StatusUnauthorized {
		value, err := bearerParameter(header, "error")
		if c.StatusCode != http.StatusForbidden || err != nil || value != "insufficient_scope" {
			return nil, fail(auth.CodeAccessDenied)
		}
	}
	if c.Attempt != nil {
		owner, ok := c.Attempt.(attempted)
		if !ok || owner.owner != p || owner.identity != requestIdentity(r) {
			return nil, fail(auth.CodeInvalidConfiguration)
		}
	} else if len(r.Binding) != 0 {
		return nil, fail(auth.CodeInvalidConfiguration)
	}
	// A 401 makes the rejected token stale; a 403 keeps it and the scope
	// requirement drives step-up.
	if owner, ok := c.Attempt.(attempted); ok && c.StatusCode == http.StatusUnauthorized {
		err := p.options.Store.Coordinate(ctx, owner.key, func(ctx context.Context) error {
			current, err := p.options.Store.Load(ctx, owner.key)
			if err != nil {
				return safe(ctx, err, auth.CodeProviderFailed)
			}
			if current == nil || current.AccessToken != owner.token {
				return nil
			}
			next := cloneRecord(current)
			next.AccessToken, next.Generation = "", randomID()
			return p.save(ctx, owner.key, current.Generation, next)
		})
		if err != nil {
			return nil, safe(ctx, err, auth.CodeProviderFailed)
		}
	}
	result, err := p.prepare(ctx, cloneRequest(r), header, nil, c.StatusCode == http.StatusForbidden, false)
	if err != nil {
		return nil, err
	}
	return result.Credential, nil
}

// PreemptiveCredential is the up-front lookup for a known binding. It serves a
// usable stored grant, or renews it non-interactively (refresh or client
// credentials) with persisted issuer metadata, fetching only the stored
// issuer's metadata when none is persisted. It never runs protected-resource
// discovery or creates a login. Only a store miss or host policy refusal
// yields nil, an anonymous attempt; a known binding whose grant cannot be
// renewed (including one needing consent) fails the operation.
func (p *Provider) PreemptiveCredential(ctx context.Context, r auth.Request) (*auth.Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := auth.NormalizeTarget(r); err != nil {
		return nil, err
	}
	r = cloneRequest(r)
	// Only a store miss or a host policy refusal is anonymous.
	config, m, cached, err := p.cachedBinding(ctx, r)
	if err != nil {
		if ctx.Err() != nil || !errors.As(err, new(refusal)) {
			return nil, safe(ctx, err, auth.CodeProviderFailed)
		}
		return nil, nil
	}
	if !cached {
		return nil, nil
	}
	key := p.key(r, config)
	record, err := p.options.Store.Load(ctx, key)
	if err != nil {
		return nil, safe(ctx, err, auth.CodeProviderFailed)
	}
	if satisfies(record, config) {
		return p.credential(r, key, record), nil
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, lookupBudget)
		defer cancel()
	}
	if m.TokenEndpoint == "" {
		// Only the stored issuer's metadata; never protected-resource discovery.
		if config, m, err = p.resolveMetadata(ctx, config); err != nil {
			return nil, safe(ctx, err, auth.CodeDiscoveryFailed)
		}
	} else if config.TokenAuthMethod, err = tokenMethod(config, m); err != nil {
		return nil, err
	}
	result, err, stale := p.acquireOnce(ctx, r, key, config, m, false, false)
	if stale {
		// Refetch only the stored issuer's metadata once, persist it and retry.
		if config, m, err = p.resolveMetadata(ctx, config); err != nil {
			return nil, safe(ctx, err, auth.CodeDiscoveryFailed)
		}
		if err = p.persistBinding(ctx, r, config, m); err != nil {
			return nil, err
		}
		result, err = p.acquire(ctx, r, key, config, m, false, false)
	}
	return result.Credential, err
}
