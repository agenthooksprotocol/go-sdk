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
	"net/http/httptrace"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	if options.RegistrationBackoff < 0 || options.RegistrationBackoffMax < 0 || options.MaxPendingLogins < 0 {
		return nil, fail(auth.CodeInvalidConfiguration)
	}
	if options.LoginLifetime == 0 {
		options.LoginLifetime = maxLoginLifetime
	}
	if options.MaxPendingLogins == 0 {
		options.MaxPendingLogins = 5
	}
	if options.RegistrationBackoff == 0 {
		options.RegistrationBackoff = time.Minute
	}
	if options.RegistrationBackoffMax == 0 {
		options.RegistrationBackoffMax = time.Hour
	}
	client := *options.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	var logins Store = &processLogins{guard: make(chan struct{}, 1), values: map[string]*Record{}}
	if options.PersistLogins {
		logins = options.Store
	}
	return &Provider{options: options, client: client, logins: logins}, nil
}

// fail builds an SDK error from an SDK-chosen code and optional required scopes.
func fail(code auth.Code, required ...string) error {
	return &auth.Error{Code: code, Scopes: merge(nil, required...)}
}

// safe is the error-copy boundary for host callbacks: only an allowlisted
// auth.Error code survives, never the host's error chain. Host errors never
// carry scopes or a login state: only the SDK's own checks attach them.
func safe(ctx context.Context, err error, fallback auth.Code) error {
	if ctx.Err() != nil {
		return errors.Join(fail(fallback), ctx.Err())
	}
	if classified := auth.Classify(err); classified != nil {
		return &auth.Error{Code: classified.Code}
	}
	return fail(fallback)
}

// keep copies an SDK-produced error, keeping the scopes its own checks attached.
func keep(ctx context.Context, err error, fallback auth.Code) error {
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

// requested is what the SDK asks for: requested and required scopes, both
// within the ceiling (validConfig and the ceiling check enforce it), plus any
// 401 hint, which is already ceiling-filtered.
func requested(c ClientConfig, hint []string) []string {
	return merge(merge(c.Scopes, c.RequiredScopes...), hint...)
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
	if !discoveryIssuer(c.Issuer) || !discoveryHTTPS(c.Resource) || (c.Flow != "authorization_code_pkce" && c.Flow != "client_credentials") {
		return false
	}
	scopes := merge(merge(c.Scopes, allowedScopes(c)...), c.RequiredScopes...)
	if c.Registration != nil {
		if c.Registration.ClientName == "" {
			return false
		}
		scopes = merge(scopes, c.Registration.Scopes...)
	}
	for _, scope := range scopes {
		if !authutil.ValidScope(scope) {
			return false
		}
	}
	// Requested scopes outside the ceiling are a configuration error, never
	// silently dropped. Required scopes outside it are an access_denied refusal.
	if !scopeSubset(c.Scopes, allowedScopes(c)) {
		return false
	}
	if c.Flow == "client_credentials" {
		// An empty ClientID selects a dynamically registered client.
		return (c.ClientSecret != "") == (c.ClientID != "")
	}
	// A redirect is required only when a login is created; one given is
	// checked here, before client selection.
	return c.RedirectURI == "" || validRedirect(c.RedirectURI)
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
	if r.Registration != nil {
		reg := *r.Registration
		copy.Registration = &reg
	}
	if r.RegistrationFailure != nil {
		failure := *r.RegistrationFailure
		copy.RegistrationFailure = &failure
	}
	copy.Pending = nil
	for _, pending := range r.Pending {
		pending.Scopes = append([]string(nil), pending.Scopes...)
		pending.Ceiling = append([]string(nil), pending.Ceiling...)
		pending.Required = append([]string(nil), pending.Required...)
		copy.Pending = append(copy.Pending, pending)
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
	if c.ClientIDMetadataDocument != nil {
		document := *c.ClientIDMetadataDocument
		document.RedirectURIs = append([]string(nil), document.RedirectURIs...)
		c.ClientIDMetadataDocument = &document
	}
	if c.Registration != nil {
		policy := *c.Registration
		policy.Scopes = append([]string(nil), policy.Scopes...)
		c.Registration = &policy
	}
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

// key is the grant identity, keyed by the configured client source. The
// allowed ceiling is re-intersected at use, so changing it never orphans a grant.
func (p *Provider) key(r auth.Request, c ClientConfig) string {
	partition := "binding:" + p.bindingKey(r)
	if c.GrantPartition != "" {
		partition = "shared:" + c.GrantPartition
	}
	return frame("ahp.oauth.grant:", p.options.Namespace, c.Issuer, c.Resource, identity(c), c.Flow, partition)
}

// pendingKey holds a grant's pending logins.
func pendingKey(grant string) string { return "ahp.oauth.pending:" + grant }
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
	// Keep the recorded CIMD/DCR client while current policy permits it.
	c = recorded(c, b)
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
	previous := b.Config
	previous.source = b.Source
	if p.key(r, c) != p.key(r, previous) {
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
	public.ClientSecret, public.RequiredScopes, public.registered = "", nil, ""
	if c.source == sourceDCR {
		// An issued client lives with its grant or registration, not here.
		public.ClientID = ""
	}
	binding := &BindingMetadata{Config: public, IssuerMetadata: m, Source: c.source}
	_, err = p.options.Store.CompareAndSwap(ctx, key, generation(old), &Record{Generation: randomID(), Binding: binding})
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

// challengeScopes returns the validated, sorted scope parameter of a Bearer
// challenge. A malformed value (empty, repeated, leading or trailing spaces,
// an invalid character, or a duplicated parameter) or a challenge that cannot
// be parsed fails closed with access_denied and no scopes.
func challengeScopes(challenge string) ([]string, error) {
	value, err := bearerParameter(challenge, "scope")
	if err != nil || (value != "" && !authutil.ValidScopeList(value)) {
		return nil, fail(auth.CodeAccessDenied)
	}
	return merge(strings.Fields(value)), nil
}

// alreadyGranted reports a step-up whose required set the stored grant
// already records within the current ceiling: the server and the record
// disagree, so the operation is refused rather than replaying a token or
// requesting consent. rejected is empty when no token was sent.
func alreadyGranted(record *Record, c ClientConfig, rejected string) bool {
	return rejected != "" && record != nil && scopeSubset(c.RequiredScopes, intersect(record.Scopes, allowedScopes(c)))
}

// remember records 401 challenge scopes, already ceiling-filtered, to request
// in the grant's next acquisition or login. They are never a requirement.
func (p *Provider) remember(key string, scopes []string) {
	if len(scopes) == 0 {
		return
	}
	p.hintsMu.Lock()
	defer p.hintsMu.Unlock()
	if p.hints == nil {
		p.hints = map[string][]string{}
	}
	p.hints[key] = merge(p.hints[key], scopes...)
}

// hint returns the 401 scopes remembered for a grant.
func (p *Provider) hint(key string) []string {
	p.hintsMu.Lock()
	defer p.hintsMu.Unlock()
	return append([]string(nil), p.hints[key]...)
}

// forget drops a grant's remembered 401 scopes once they were requested.
func (p *Provider) forget(key string) {
	p.hintsMu.Lock()
	defer p.hintsMu.Unlock()
	delete(p.hints, key)
}

// Prepare is the host-controlled interaction entrypoint. The context MUST carry
// a deadline for its network work; a created login outlives it. A Login never
// starts a listener or browser. Required scopes are explicit operation
// requirements, typically the Scopes of an interaction_required error after a
// step-up challenge; with the host RequiredScopes they must be within the
// allowed ceiling, or Prepare fails with access_denied before any request.
func (p *Provider) Prepare(ctx context.Context, r auth.Request, required ...string) (Preparation, error) {
	return p.PrepareWith(ctx, r, PrepareOptions{RequiredScopes: required})
}

// PrepareWith is Prepare with explicit host options, including the redirect
// of a login it creates.
func (p *Provider) PrepareWith(ctx context.Context, r auth.Request, options PrepareOptions) (Preparation, error) {
	for _, scope := range options.RequiredScopes {
		if !authutil.ValidScope(scope) {
			return Preparation{}, fail(auth.CodeInvalidConfiguration)
		}
	}
	if options.RedirectURI != "" && !validRedirect(options.RedirectURI) {
		return Preparation{}, fail(auth.CodeInvalidConfiguration)
	}
	preparation, err := p.prepare(ctx, cloneRequest(r), "", options.RequiredScopes, options.RedirectURI, false, true, options.ForceRegistration, "")
	if err == nil && preparation.Credential != nil {
		p.markPrepared(r)
	}
	return preparation, err
}

var _ auth.PreparationTracker = (*Provider)(nil)

// Preparations implements auth.PreparationTracker: it counts this Provider's
// Prepare or PrepareWith calls that returned a credential and Complete calls
// that succeeded, for r's backend, purpose and destination. A Prepare that
// only creates a login is not counted until the login completes.
func (p *Provider) Preparations(r auth.Request) uint64 {
	if counter, ok := p.prepared.Load(preparedKey(r)); ok {
		return counter.(*atomic.Uint64).Load()
	}
	return 0
}

func (p *Provider) markPrepared(r auth.Request) {
	counter, _ := p.prepared.LoadOrStore(preparedKey(r), new(atomic.Uint64))
	counter.(*atomic.Uint64).Add(1)
}

func preparedKey(r auth.Request) string {
	encoded, _ := json.Marshal([]any{r.BackendID, r.Purpose, authutil.NormalizeEndpoint(r.Destination)})
	return string(encoded)
}

// prepare serves a cached grant, refreshes or reissues it, or (only when
// interactive) creates a pending login. Its required set R is the host
// RequiredScopes, the explicit scopes and, on a step-up (403), the challenged
// scopes; it applies to this call alone. A 401 challenge's scopes are only
// requested by the next acquisition. The ceiling decision on R is local and
// precedes issuer metadata, token and registration requests. rejected is the
// access token a step-up challenge rejected, if known.
func (p *Provider) prepare(ctx context.Context, r auth.Request, challenge string, explicit []string, redirect string, stepUp, interactive, force bool, rejected string) (Preparation, error) {
	if err := bounded(ctx); err != nil {
		return Preparation{}, err
	}
	challenged, err := challengeScopes(challenge)
	if err != nil {
		return Preparation{}, err
	}
	var hint []string
	if !stepUp {
		// A 401 scope is a hint for the next request, never a requirement.
		hint, challenged = challenged, nil
	}
	require := func(c ClientConfig) (ClientConfig, error) {
		// Without a challenged scope, only a host or explicit requirement justifies step-up.
		if stepUp && len(challenged) == 0 && len(c.RequiredScopes) == 0 && len(explicit) == 0 {
			return c, fail(auth.CodeAccessDenied)
		}
		c.RequiredScopes = merge(merge(c.RequiredScopes, explicit...), challenged...)
		if !scopeSubset(c.RequiredScopes, allowedScopes(c)) {
			return c, fail(auth.CodeAccessDenied, c.RequiredScopes...)
		}
		return c, nil
	}
	note := func(key string, c ClientConfig) {
		// Out-of-ceiling 401 scopes are simply not requested.
		p.remember(key, intersect(hint, allowedScopes(c)))
	}
	// A stale or policy-refused stored binding is rebuilt by discovery, which
	// applies current policy to the discovered issuers.
	config, m, cached, err := p.cachedBinding(ctx, r)
	if err != nil && err != errStaleBinding && (ctx.Err() != nil || !errors.As(err, new(refusal))) {
		return Preparation{}, safe(ctx, err, auth.CodeDiscoveryFailed)
	}
	if cached && !(force && config.Flow != pkceFlow) {
		// A usable grant requires no remote metadata or store write.
		if config, err = require(config); err != nil {
			return Preparation{}, err
		}
		key := p.key(r, config)
		note(key, config)
		if interactive {
			p.sweep(ctx, key)
		}
		current, err := p.options.Store.Load(ctx, key)
		if err != nil {
			return Preparation{}, safe(ctx, err, auth.CodeProviderFailed)
		}
		if stepUp && alreadyGranted(current, config, rejected) {
			return Preparation{}, fail(auth.CodeAccessDenied, config.RequiredScopes...)
		}
		if satisfies(current, config) {
			return Preparation{Credential: p.credential(r, key, current)}, nil
		}
	}
	// An exchange or login needs current metadata: full discovery, honouring a
	// challenge's resource_metadata hint, rebuilds the binding. Client selection
	// precedes the ceiling decision, which precedes issuer metadata.
	if config, err = p.discover(ctx, r, challenge); err != nil {
		return Preparation{}, safe(ctx, err, auth.CodeDiscoveryFailed)
	}
	if config, err = require(config); err != nil {
		return Preparation{}, err
	}
	if config, m, err = p.resolveMetadata(ctx, config); err != nil {
		return Preparation{}, safe(ctx, err, auth.CodeDiscoveryFailed)
	}
	if redirect != "" && config.Flow == pkceFlow {
		config.RedirectURI = redirect
	}
	if config, err = p.choose(ctx, r, config, m); err != nil {
		return Preparation{}, err
	}
	note(p.key(r, config), config)
	result, err, _ := p.obtain(ctx, r, config, m, true, stepUp, interactive, force, rejected)
	return result, err
}

// obtain persists the binding when asked, resolves a client-credentials
// registration when the client needs one, then runs the coordinated
// acquisition and, when interactive and consent is needed, creates a login.
// A token-endpoint invalid_client for a registered client-credentials client
// compare-and-deletes that registration, then re-registers and re-acquires
// once. It also reports whether the token endpoint failed without processing
// the request (stale metadata).
func (p *Provider) obtain(ctx context.Context, r auth.Request, config ClientConfig, m metadata, persist, stepUp, interactive, force bool, rejected string) (Preparation, error, bool) {
	if persist {
		if err := p.persistBinding(ctx, r, config, m); err != nil {
			return Preparation{}, err, false
		}
	}
	key := p.key(r, config)
	if interactive {
		p.sweep(ctx, key)
	}
	machine := config.source == sourceDCR && config.Flow != pkceFlow
	for attempt := 0; ; attempt++ {
		if machine {
			var err error
			if config, err = p.registered(ctx, config, m, interactive, attempt > 0, force && attempt == 0); err != nil {
				return Preparation{}, err, false
			}
		}
		method, err := tokenMethod(config, m)
		if err != nil {
			return Preparation{}, err, false
		}
		config.TokenAuthMethod = method
		result, err, reason := p.acquireOnce(ctx, r, key, config, m, stepUp, interactive, rejected)
		if reason == errLogin {
			login, err := p.login(ctx, key, config, m)
			return Preparation{Login: login}, err, false
		}
		if machine && err == nil && config.failing && result.Credential != nil {
			// A successful token request with this client clears the count;
			// a failed write only leaves the backoff to elapse.
			p.recovered(ctx, config)
		}
		if reason != errInvalidClient || !machine {
			return result, err, reason == errEndpoint
		}
		if err := p.drop(ctx, config, attempt > 0); err != nil {
			return Preparation{}, err, false
		}
		if attempt > 0 {
			return Preparation{}, fail(auth.CodeCredentialUnavailable), false
		}
	}
}

// errLogin marks an interactive acquisition that needs a new login.
var errLogin = &auth.Error{Code: auth.CodeInteractionRequired}

// acquireOnce runs under the grant lock: it rechecks the stored grant, then
// refreshes or reissues client credentials. It reports errLogin when an
// interactive caller needs consent, errEndpoint when the token endpoint failed
// without an OAuth error response (the metadata used may be stale) or
// errInvalidClient when it rejected the client.
func (p *Provider) acquireOnce(ctx context.Context, r auth.Request, key string, config ClientConfig, m metadata, stepUp, interactive bool, rejected string) (Preparation, error, error) {
	var result Preparation
	// inner is the SDK's own outcome; any other Coordinate error is the host's.
	var inner error
	err := p.options.Store.Coordinate(ctx, key, func(ctx context.Context) error {
		inner = p.acquireLocked(ctx, r, key, config, m, stepUp, interactive, rejected, &result)
		return inner
	})
	if err != nil {
		var reason error
		for _, sentinel := range []error{errEndpoint, errInvalidClient, errLogin} {
			if errors.Is(inner, sentinel) {
				reason = sentinel
			}
		}
		if inner == nil {
			return Preparation{}, safe(ctx, err, auth.CodeProviderFailed), nil
		}
		return Preparation{}, keep(ctx, inner, auth.CodeProviderFailed), reason
	}
	if ctx.Err() != nil {
		// The exchange completed detached; the caller still sees cancellation.
		return Preparation{}, errors.Join(fail(auth.CodeProviderFailed), ctx.Err()), nil
	}
	return result, nil, nil
}

// acquireLocked is acquireOnce's work under the grant lock.
func (p *Provider) acquireLocked(ctx context.Context, r auth.Request, key string, config ClientConfig, m metadata, stepUp, interactive bool, rejected string, result *Preparation) error {
	record, err := p.options.Store.Load(ctx, key)
	if err != nil {
		return safe(ctx, err, auth.CodeProviderFailed)
	}
	record = cloneRecord(record)
	if stepUp && alreadyGranted(record, config, rejected) {
		return fail(auth.CodeAccessDenied, config.RequiredScopes...)
	}
	if satisfies(record, config) {
		result.Credential = p.credential(r, key, record)
		return nil
	}
	// covered: the previous grant already recorded R, so a renewal that comes
	// back narrower is the server narrowing it, not a step-up.
	covered := record != nil && scopeSubset(config.RequiredScopes, intersect(record.Scopes, allowedScopes(config)))
	next := record
	switch {
	case config.Flow == "client_credentials":
		next, err = p.machine(ctx, key, config, m, record)
	case record != nil && record.RefreshToken != "" && !usable(record) && (config.source != sourceDCR || record.ClientID != ""):
		next, err = p.refresh(ctx, key, config, m, record)
	}
	if err != nil {
		return err
	}
	if satisfies(next, config) {
		result.Credential = p.credential(r, key, next)
		return nil
	}
	if config.Flow == "client_credentials" || (usable(next) && (covered || (!stepUp && !interactive))) {
		// A live grant lacks a requirement: refresh cannot broaden it, and a
		// grant narrower than a recorded R is the server's refusal.
		return fail(auth.CodeAccessDenied, config.RequiredScopes...)
	}
	if !interactive {
		return fail(auth.CodeInteractionRequired, config.RequiredScopes...)
	}
	return errLogin
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
	// An absent, null or blank scope is omitted and inherits. Any other string
	// must be a strict RFC 6749 list; any other JSON type is malformed.
	switch value := token.Extra("scope").(type) {
	case nil:
	case string:
		if strings.Trim(value, " \t\r\n") == "" {
			break
		}
		if !authutil.ValidScopeList(value) {
			valid = false
		} else {
			response = strings.Split(value, " ")
		}
	default:
		valid = false
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
	next := &Record{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ClientID: c.ClientID, ExpiresAt: token.Expiry, Scopes: intersect(response, ceiling), Generation: randomID()}
	if !validRefresh(next.RefreshToken) {
		next.RefreshToken = ""
		if previous != nil {
			next.RefreshToken = previous.RefreshToken
		}
	}
	return next, nil
}

// persistBudget bounds receiving and persisting a sent exchange's outcome.
var persistBudget = time.Minute

// persisting detaches a store write from caller cancellation: once a code or
// refresh token is spent, losing its outcome would lose the rotated token.
func persisting(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), persistBudget)
}

// sending detaches a token request from caller cancellation once the request
// is written: a sent code or refresh token is spent, so its response is
// received and committed within persistBudget. Until then (policy checks, DNS,
// connect, TLS) caller cancellation still aborts it. A nil cancel means the
// caller already cancelled and nothing was sent.
func sending(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx.Err() != nil {
		return ctx, nil
	}
	detached, cancel := persisting(ctx)
	var mu sync.Mutex
	wrote := false
	stop := context.AfterFunc(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		if !wrote {
			cancel()
		}
	})
	detached = httptrace.WithClientTrace(detached, &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) {
		mu.Lock()
		defer mu.Unlock()
		wrote = true
	}})
	return detached, func() { stop(); cancel() }
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
// grant also requests and keeps its previously granted scopes, and any
// remembered 401 challenge scopes.
func (p *Provider) machine(ctx context.Context, key string, c ClientConfig, m metadata, previous *Record) (*Record, error) {
	var granted []string
	if previous != nil {
		granted = previous.Scopes
	}
	hint := p.hint(key)
	c.Scopes = merge(granted, requested(c, hint)...)
	ctx, cancel := sending(ctx)
	if cancel == nil {
		return nil, ctx.Err()
	}
	defer cancel()
	conf := clientcredentials.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, TokenURL: m.TokenEndpoint, Scopes: c.Scopes, AuthStyle: authStyle(c), EndpointParams: url.Values{"resource": {c.Resource}}}
	token, err := conf.Token(context.WithValue(ctx, oauth2.HTTPClient, p.tokenClient(c, m, nil)))
	if err != nil {
		return nil, acquisitionError(ctx, err, false)
	}
	next, err := p.grant(ctx, c, merge(granted, allowedScopes(c)...), token, nil)
	if next, err = p.commit(ctx, key, generation(previous), next, err); next != nil && len(hint) > 0 {
		p.forget(key)
	}
	return next, err
}

// errEndpoint marks a token request the endpoint provably did not process
// (DNS, TCP connect or TLS handshake failure, or HTTP 404/410): persisted
// metadata may be stale, and a retry cannot replay a spent refresh token.
// It never reaches callers; acquireOnce reports it as a flag.
var errEndpoint = &auth.Error{Code: auth.CodeProviderFailed}

// errInvalidClient marks a token-endpoint invalid_client: a client-credentials
// registration is then replaced, a PKCE DCR client needs a new login, any
// other client is misconfigured.
var errInvalidClient = &auth.Error{Code: auth.CodeInvalidConfiguration}

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
	case "invalid_client":
		return errInvalidClient
	case "unauthorized_client", "unsupported_grant_type":
		return fail(auth.CodeInvalidConfiguration)
	case "access_denied", "invalid_scope":
		return fail(auth.CodeAccessDenied)
	}
	return fail(auth.CodeProviderFailed)
}

// refresh never broadens the previous grant and uses the client stored with
// it. Transient failures keep the record untouched; a definitive invalid_grant,
// or invalid_client for a registered client, drops it.
func (p *Provider) refresh(ctx context.Context, key string, c ClientConfig, m metadata, previous *Record) (*Record, error) {
	if c.source == sourceDCR {
		c.ClientID, c.ClientSecret, c.TokenAuthMethod = previous.ClientID, "", "none"
	}
	ctx, cancel := sending(ctx)
	if cancel == nil {
		return nil, ctx.Err()
	}
	defer cancel()
	conf := oauthConfig(c, m)
	var rotated string
	token, err := conf.TokenSource(context.WithValue(ctx, oauth2.HTTPClient, p.tokenClient(c, m, &rotated)), &oauth2.Token{RefreshToken: previous.RefreshToken, Expiry: time.Now().Add(-time.Minute)}).Token()
	var rejected *oauth2.RetrieveError
	if err != nil && !errors.As(err, &rejected) && validRefresh(rotated) {
		// x/oauth2 rejected a 2xx response it could not decode: keep its
		// rotated refresh token and report the invalid response.
		kept := cloneRecord(previous)
		kept.AccessToken, kept.RefreshToken, kept.ExpiresAt, kept.Generation = "", rotated, time.Time{}, randomID()
		_, err = p.commit(ctx, key, previous.Generation, kept, fail(auth.CodeProviderFailed))
		return nil, err
	}
	if err != nil {
		invalidClient := rejected != nil && rejected.ErrorCode == "invalid_client" && c.source == sourceDCR
		if ctx.Err() == nil && rejected != nil && (rejected.ErrorCode == "invalid_grant" || invalidClient) {
			// Compare-and-delete: only the generation holding the presented
			// client and refresh token; a newer record (lost CAS) is kept.
			dropped := &Record{Generation: randomID()}
			if !invalidClient {
				dropped = cloneRecord(previous)
				dropped.AccessToken, dropped.RefreshToken, dropped.ExpiresAt, dropped.Generation = "", "", time.Time{}, randomID()
			}
			persist, cancel := persisting(ctx)
			defer cancel()
			if _, saveErr := p.options.Store.CompareAndSwap(persist, key, previous.Generation, dropped); saveErr != nil {
				return nil, safe(ctx, saveErr, auth.CodeProviderFailed)
			}
			if invalidClient {
				return nil, fail(auth.CodeInteractionRequired)
			}
			return nil, fail(auth.CodeRefreshRejected)
		}
		return nil, acquisitionError(ctx, err, false)
	}
	next, err := p.grant(ctx, c, previous.Scopes, token, previous)
	return p.commit(ctx, key, previous.Generation, next, err)
}

// login creates a pending login for this caller. It requests any previously
// granted scopes plus the request, required scopes and remembered 401
// challenge scopes, and stores the caller's ceiling, which bounds the grant
// recorded on completion, and the required set completion must cover. A dynamically
// registered PKCE client is registered here, with the login's exact redirect.
// Its lifetime is fixed here and does not depend on the caller's context.
func (p *Provider) login(ctx context.Context, key string, c ClientConfig, m metadata) (*PendingLogin, error) {
	if !validRedirect(c.RedirectURI) || (c.source == sourceCIMD && !documentAccepts(c.ClientIDMetadataDocument, c.RedirectURI)) {
		return nil, fail(auth.CodeInvalidConfiguration)
	}
	current, err := p.options.Store.Load(ctx, key)
	if err != nil {
		return nil, safe(ctx, err, auth.CodeProviderFailed)
	}
	ceiling := merge(allowedScopes(c))
	hint := p.hint(key)
	c.Scopes = requested(c, hint)
	if current != nil {
		c.Scopes = merge(current.Scopes, c.Scopes...)
	}
	if c.source == sourceDCR {
		if c.ClientID, err = p.registerLogin(ctx, c, m); err != nil {
			return nil, safe(ctx, err, auth.CodeProviderFailed)
		}
	}
	verifier := oauth2.GenerateVerifier()
	state := randomID()
	loginURL := oauthConfig(c, m).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("resource", c.Resource))
	if err := p.check(ctx, loginURL, Authorization); err != nil {
		return nil, err
	}
	pending := PendingRecord{State: state, Verifier: verifier, RedirectURI: c.RedirectURI, Scopes: c.Scopes, Ceiling: ceiling, Required: merge(c.RequiredScopes), ExpiresAt: time.Now().Add(p.options.LoginLifetime), ClientID: c.ClientID}
	err = p.pending(ctx, key, func(logins []PendingRecord) ([]PendingRecord, error) {
		// Beyond the cap, the oldest login is cancelled.
		logins = append(logins, pending)
		return logins[max(0, len(logins)-p.options.MaxPendingLogins):], nil
	})
	if err != nil {
		return nil, err
	}
	if len(hint) > 0 {
		p.forget(key)
	}
	return &PendingLogin{authorizationURL: loginURL, state: state, deadline: pending.ExpiresAt}, nil
}

// pending atomically edits a grant's unexpired pending logins under their
// lock. Expired logins are deleted.
func (p *Provider) pending(ctx context.Context, key string, edit func([]PendingRecord) ([]PendingRecord, error)) error {
	key = pendingKey(key)
	return p.logins.Coordinate(ctx, key, func(ctx context.Context) error {
		record, err := p.logins.Load(ctx, key)
		if err != nil {
			return safe(ctx, err, auth.CodeProviderFailed)
		}
		var live []PendingRecord
		if record != nil {
			now := time.Now()
			for _, login := range cloneRecord(record).Pending {
				if login.ExpiresAt.After(now) {
					live = append(live, login)
				}
			}
		}
		save := func(logins []PendingRecord) error {
			ok, err := p.logins.CompareAndSwap(ctx, key, generation(record), &Record{Generation: randomID(), Pending: logins})
			if err != nil {
				return safe(ctx, err, auth.CodeProviderFailed)
			}
			if !ok {
				return fail(auth.CodeProviderFailed)
			}
			return nil
		}
		next, err := edit(live)
		if err != nil {
			if record != nil && len(live) != len(record.Pending) {
				save(live)
			}
			return err
		}
		return save(next)
	})
}

// Cancel abandons exactly one pending login for r, matched by its state, so
// it never ends another caller's login sharing the grant. It never changes
// stored tokens; an ended or unknown login is a no-op.
func (p *Provider) Cancel(ctx context.Context, r auth.Request, login *PendingLogin) error {
	if login == nil || login.state == "" {
		return nil
	}
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
	return p.pending(ctx, p.key(r, config), func(logins []PendingRecord) ([]PendingRecord, error) {
		for i, pending := range logins {
			if subtle.ConstantTimeCompare([]byte(login.state), []byte(pending.State)) == 1 {
				return append(logins[:i:i], logins[i+1:]...), nil
			}
		}
		return logins, nil
	})
}

// errSweep ends a pending-login edit that only deletes expired logins.
var errSweep = errors.New("sweep")

// sweep deletes a grant's expired persisted pending logins and their verifiers.
func (p *Provider) sweep(ctx context.Context, key string) {
	if p.options.PersistLogins {
		p.pending(ctx, key, func([]PendingRecord) ([]PendingRecord, error) { return nil, errSweep })
	}
}

// Complete validates one callback against r's pending login with its state
// and performs a single bounded code exchange. The creating Provider completes
// it, or with Options.PersistLogins any Provider sharing the Store. An invalid
// callback never consumes the login; a cancelled, expired or already used
// login fails with interaction_required. Completion replaces the grant's
// client and tokens, so the newest completed login wins. It succeeds only when
// the grant, within the current ceiling, covers the login's required set;
// otherwise it fails with access_denied carrying that set, after the grant is
// saved and the login consumed.
//
// Every returned error carries an *auth.Error whose LoginEnded reports whether
// the pending login named by the callback's state no longer exists after the
// call: true once it was consumed, or when it had expired or was unknown;
// false when it is still pending (or its state could not be determined).
func (p *Provider) Complete(ctx context.Context, r auth.Request, callback string) (auth.Credential, error) {
	r = cloneRequest(r)
	credential, ended, err := p.complete(ctx, r, callback)
	if err == nil {
		return credential, nil
	}
	if ended == nil {
		ended = p.loginEnded(ctx, r, callback)
	}
	result := auth.Classify(err)
	if result == nil {
		result = &auth.Error{Code: auth.CodeProviderFailed}
	}
	if errors.Is(err, errCallback) && *ended {
		// Without a login named by its state, any callback is for no login.
		result = &auth.Error{Code: auth.CodeInteractionRequired}
	}
	result.LoginEnded = *ended
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, cause) {
			return auth.Credential{}, errors.Join(result, cause)
		}
	}
	return auth.Credential{}, result
}

// callbackStates returns the callback's state values.
func callbackStates(callback string) []string {
	value, err := url.Parse(callback)
	if err != nil {
		return nil
	}
	query, err := url.ParseQuery(value.RawQuery)
	if err != nil {
		return nil
	}
	return query["state"]
}

// loginEnded reports, for a failure before the login was claimed, whether the
// pending login named by the callback's state is gone. Without a state or a
// current binding no login can match; an indeterminate lookup reports
// false (still pending).
func (p *Provider) loginEnded(ctx context.Context, r auth.Request, callback string) *bool {
	ended := func(value bool) *bool { return &value }
	states := callbackStates(callback)
	if len(states) == 0 {
		return ended(true)
	}
	config, _, cached, err := p.cachedBinding(ctx, r)
	if err == errStaleBinding || (err == nil && !cached) {
		return ended(true)
	}
	if err != nil {
		return ended(false)
	}
	record, err := p.logins.Load(ctx, pendingKey(p.key(r, config)))
	if err != nil {
		return ended(false)
	}
	if record != nil {
		now := time.Now()
		for _, login := range record.Pending {
			for _, state := range states {
				if login.ExpiresAt.After(now) && subtle.ConstantTimeCompare([]byte(state), []byte(login.State)) == 1 {
					return ended(false)
				}
			}
		}
	}
	return ended(true)
}

// errCallback marks a callback rejected before its login was looked up.
var errCallback = &auth.Error{Code: auth.CodeAccessDenied}

// complete is Complete without the login-ended flag. It reports that flag
// once the claim decided it, or nil for the caller to look it up.
func (p *Provider) complete(ctx context.Context, r auth.Request, callback string) (auth.Credential, *bool, error) {
	ended := func(value bool) *bool { return &value }
	if err := bounded(ctx); err != nil {
		return auth.Credential{}, nil, err
	}
	value, err := url.Parse(callback)
	if err != nil || value.User != nil || strings.Contains(callback, "#") {
		return auth.Credential{}, nil, errCallback
	}
	query, err := url.ParseQuery(value.RawQuery)
	if err == nil && len(query["state"]) == 0 {
		// Without a state no login can match, as for an unknown state.
		return auth.Credential{}, ended(true), fail(auth.CodeInteractionRequired)
	}
	if err != nil {
		return auth.Credential{}, nil, errCallback
	}
	for _, values := range query {
		// No duplicated parameter.
		if len(values) != 1 {
			return auth.Credential{}, nil, errCallback
		}
	}
	if code, denied := query.Get("code"), query.Has("error"); denied == query.Has("code") || (!denied && code == "") || (denied && query.Get("error") == "") {
		// Exactly one of a nonempty code or error.
		return auth.Credential{}, nil, errCallback
	}
	// Resolve current secrets, policy and capabilities: the pending login never
	// makes a captured runtime secret authoritative.
	config, m, cached, err := p.cachedBinding(ctx, r)
	if err == nil && !cached {
		return auth.Credential{}, ended(true), fail(auth.CodeInteractionRequired)
	}
	if err == nil {
		config, m, err = p.resolveMetadata(ctx, config)
	}
	if err != nil {
		return auth.Credential{}, nil, safe(ctx, err, auth.CodeDiscoveryFailed)
	}
	key := p.key(r, config)
	var pending PendingRecord
	// found reports a live login for the state; claimed that it was consumed.
	found, claimed := false, false
	// Claim the valid callback's login once before the exchange.
	err = p.pending(ctx, key, func(logins []PendingRecord) ([]PendingRecord, error) {
		for i, login := range logins {
			if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(login.State)) != 1 {
				continue
			}
			found = true
			if config.source != sourceDCR && login.ClientID != config.ClientID {
				return nil, fail(auth.CodeInteractionRequired)
			}
			redirect, _ := url.Parse(login.RedirectURI)
			if value.Scheme != redirect.Scheme || value.Host != redirect.Host || value.EscapedPath() != redirect.EscapedPath() {
				return nil, fail(auth.CodeAccessDenied)
			}
			if issuer := query["iss"]; len(issuer) > 1 || (len(issuer) == 1 && issuer[0] != config.Issuer) || (m.ResponseIssuer && len(issuer) != 1) {
				return nil, fail(auth.CodeAccessDenied)
			}
			pending, claimed = login, true
			return append(logins[:i:i], logins[i+1:]...), nil
		}
		return nil, fail(auth.CodeInteractionRequired)
	})
	if err != nil {
		// A failed claim leaves a found login pending; a missing one is gone.
		return auth.Credential{}, ended(!found), safe(ctx, err, auth.CodeProviderFailed)
	}
	if !claimed {
		return auth.Credential{}, ended(false), fail(auth.CodeProviderFailed)
	}
	if denied := query.Get("error"); denied != "" {
		if denied == "invalid_client" && config.source == sourceCIMD {
			// The authorization server rejected the CIMD client: configuration.
			return auth.Credential{}, ended(true), fail(auth.CodeInvalidConfiguration)
		}
		return auth.Credential{}, ended(true), fail(auth.CodeAccessDenied)
	}
	exchange := cloneConfig(config)
	exchange.ClientID, exchange.Scopes, exchange.RedirectURI = pending.ClientID, pending.Scopes, pending.RedirectURI
	credential, err := p.exchange(ctx, r, key, exchange, m, pending, query.Get("code"))
	if errors.Is(err, errInvalidClient) {
		switch config.source {
		case sourceDCR:
			// Only this login ends; the stored grant may hold an older valid
			// client. The next prepare registers again.
			err = fail(auth.CodeInteractionRequired)
		case sourceCIMD:
			err = fail(auth.CodeInvalidConfiguration)
		default:
			// The host repairs its pre-registered client information.
			err = fail(auth.CodeCredentialUnavailable)
		}
	}
	if err == nil && ctx.Err() != nil {
		// The exchange completed detached; the caller still sees cancellation.
		err = ctx.Err()
	}
	if err != nil {
		return auth.Credential{}, ended(true), keep(ctx, err, auth.CodeProviderFailed)
	}
	p.markPrepared(r)
	return *credential, nil, nil
}

// exchange redeems a claimed login's code and commits its client and tokens
// into the grant under the grant lock, replacing the previous ones. Once the
// code is sent, the outcome is received and committed detached from caller
// cancellation. The committed grant, within the current ceiling, must cover
// the login's stored required set.
func (p *Provider) exchange(ctx context.Context, r auth.Request, key string, c ClientConfig, m metadata, pending PendingRecord, code string) (*auth.Credential, error) {
	ctx, cancel := sending(ctx)
	if cancel == nil {
		return nil, ctx.Err()
	}
	defer cancel()
	token, err := oauthConfig(c, m).Exchange(context.WithValue(ctx, oauth2.HTTPClient, p.tokenClient(c, m, nil)), code, oauth2.VerifierOption(pending.Verifier), oauth2.SetAuthURLParam("resource", c.Resource))
	if err != nil {
		return nil, acquisitionError(ctx, err, true)
	}
	var credential *auth.Credential
	// inner is the SDK's own outcome; any other Coordinate error is the host's.
	var inner error
	err = p.options.Store.Coordinate(ctx, key, func(ctx context.Context) error {
		inner = func() error {
			current, err := p.options.Store.Load(ctx, key)
			if err != nil {
				return safe(ctx, err, auth.CodeProviderFailed)
			}
			var granted []string
			if current != nil {
				granted = current.Scopes
			}
			next, err := p.grant(ctx, c, merge(pending.Ceiling, granted...), token, nil)
			if next, err = p.commit(ctx, key, generation(current), next, err); err != nil {
				return err
			}
			if !usable(next) || !scopeSubset(pending.Required, intersect(next.Scopes, allowedScopes(c))) {
				return fail(auth.CodeAccessDenied, pending.Required...)
			}
			credential = p.credential(r, key, next)
			return nil
		}()
		return inner
	})
	if inner != nil {
		return nil, inner
	}
	if err != nil {
		return nil, safe(ctx, err, auth.CodeProviderFailed)
	}
	return credential, nil
}

// processLogins holds pending logins in the creating Provider.
type processLogins struct {
	guard  chan struct{}
	mu     sync.Mutex
	values map[string]*Record
}

func (s *processLogins) Load(_ context.Context, key string) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneRecord(s.values[key]), nil
}

func (s *processLogins) CompareAndSwap(_ context.Context, key, expected string, value *Record) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation(s.values[key]) != expected {
		return false, nil
	}
	if len(value.Pending) == 0 {
		delete(s.values, key)
	} else {
		s.values[key] = cloneRecord(value)
	}
	return true, nil
}

func (s *processLogins) Coordinate(ctx context.Context, _ string, work func(context.Context) error) error {
	select {
	case s.guard <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.guard }()
	return work(ctx)
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
	result, err := p.prepare(ctx, cloneRequest(r), "", nil, "", false, false, false, "")
	if err != nil {
		return auth.Credential{}, err
	}
	return *result.Credential, nil
}

// Challenge recovers without creating a login. A 401 first retires the
// rejected token; its scope is only requested by the next acquisition. A 403
// insufficient_scope keeps the token and its scope is a step-up requirement;
// one the stored grant already records fails with access_denied.
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
	// A 401 retires the rejected token before any other decision; its scope
	// is only requested next. A 403 keeps the token and its scope drives step-up.
	var rejected string
	if owner, ok := c.Attempt.(attempted); ok {
		rejected = owner.token
	}
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
	result, err := p.prepare(ctx, cloneRequest(r), header, nil, "", c.StatusCode == http.StatusForbidden, false, false, rejected)
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
// renewed (including one needing consent) fails the operation. Host
// RequiredScopes outside the ceiling fail with access_denied before any request.
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
	// The ceiling decision is local, before any renewal or metadata request.
	if !scopeSubset(config.RequiredScopes, allowedScopes(config)) {
		return nil, fail(auth.CodeAccessDenied, config.RequiredScopes...)
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
	}
	result, err, stale := p.obtain(ctx, r, config, m, false, false, false, false, "")
	if stale {
		// Refetch only the stored issuer's metadata once, persist it and retry.
		if config, m, err = p.resolveMetadata(ctx, config); err != nil {
			return nil, safe(ctx, err, auth.CodeDiscoveryFailed)
		}
		result, err, _ = p.obtain(ctx, r, config, m, true, false, false, false, "")
	}
	return result.Credential, err
}
