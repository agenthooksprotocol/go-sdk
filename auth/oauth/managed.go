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

// fail builds an SDK error from an SDK-chosen code. It never carries scopes:
// only decide's outcomes do (see refuse).
func fail(code auth.Code) error {
	return &auth.Error{Code: code}
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
	// Requested, allowed and required scopes are checked by decide.
	if c.Registration != nil {
		if c.Registration.ClientName == "" {
			return false
		}
		for _, scope := range c.Registration.Scopes {
			if !authutil.ValidScope(scope) {
				return false
			}
		}
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
		if pending.HostRequired != nil {
			pending.HostRequired = append([]string{}, pending.HostRequired...)
		}
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
	if preset, explicit := target.OAuth(); explicit && (c.Issuer != preset.Issuer || c.Resource != preset.Resource || c.ClientID != preset.ClientID || c.Flow != preset.Flow) {
		// Preset scopes are checked by decide.
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

// attempted identifies a served credential: its grant key and generation.
type attempted struct {
	owner                     *Provider
	key, generation, identity string
}

func (attempted) String() string   { return "oauth.attempt{redacted}" }
func (attempted) GoString() string { return "oauth.attempt{redacted}" }
func (p *Provider) credential(r auth.Request, key string, record *Record) *auth.Credential {
	return &auth.Credential{Type: "bearer", Token: record.AccessToken, Attempt: attempted{p, key, record.Generation, requestIdentity(r)}}
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
	if options.RedirectURI != "" && !validRedirect(options.RedirectURI) {
		return Preparation{}, classify(ctx, fail(auth.CodeInvalidConfiguration), auth.CodeInvalidConfiguration, nil)
	}
	if err := bounded(ctx); err != nil {
		return Preparation{}, classify(ctx, err, auth.CodeInvalidConfiguration, nil)
	}
	preparation, err := p.operate(ctx, cloneRequest(r), call{op: opPrepare, explicit: options.RequiredScopes, redirect: options.RedirectURI, force: options.ForceRegistration})
	if err != nil {
		return Preparation{}, classify(ctx, err, auth.CodeProviderFailed, nil)
	}
	if preparation.Credential != nil {
		p.markPrepared(r)
	}
	return preparation, nil
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

// call is one operation's decision inputs besides configuration and grant.
type call struct {
	op        operation
	challenge challenge
	explicit  []string
	redirect  string
	force     bool
	// sent is the generation whose token the challenged request carried.
	sent string
}

// decide runs the decision procedure for r's grant under config: every entry
// point decides through it.
func (p *Provider) decide(q call, r auth.Request, config ClientConfig, grant *Record) decision {
	preset, hasPreset := presetScopes(r)
	d := decide(decisionInput{op: q.op, config: config, preset: preset, hasPreset: hasPreset, explicit: q.explicit, challenge: q.challenge, grant: grant, sent: q.sent})
	if p.trace != nil {
		p.trace(q.op, d)
	}
	return d
}

// decideStored loads the grant for config, decides, and retires the sent
// generation when the decision says so.
func (p *Provider) decideStored(ctx context.Context, q call, r auth.Request, config ClientConfig) (string, *Record, decision, error) {
	key := p.key(r, config)
	grant, err := p.options.Store.Load(ctx, key)
	if err != nil {
		return key, nil, decision{}, safe(ctx, err, auth.CodeProviderFailed)
	}
	d := p.decide(q, r, config, grant)
	if d.retire {
		err := p.options.Store.Coordinate(ctx, key, func(ctx context.Context) error {
			current, err := p.options.Store.Load(ctx, key)
			if err != nil {
				return safe(ctx, err, auth.CodeProviderFailed)
			}
			return p.retire(ctx, key, current, q.sent)
		})
		if err != nil {
			return key, nil, decision{}, safe(ctx, err, auth.CodeProviderFailed)
		}
	}
	return key, grant, d, nil
}

// retire drops the access token of generation sent if it is still current;
// a newer generation is left alone. The caller holds the grant lock.
func (p *Provider) retire(ctx context.Context, key string, current *Record, sent string) error {
	if current == nil || current.Generation != sent || current.AccessToken == "" {
		return nil
	}
	next := cloneRecord(current)
	next.AccessToken, next.Generation = "", randomID()
	return p.save(ctx, key, current.Generation, next)
}

// operate serves Credential, Challenge and Prepare: decide on the stored
// binding without network; otherwise select the client (an unbound target
// may fetch protected-resource metadata first), decide again before any
// authorization-server request, then fetch issuer metadata and acquire under
// the grant lock, which decides once more.
func (p *Provider) operate(ctx context.Context, r auth.Request, q call) (Preparation, error) {
	config, _, cached, err := p.cachedBinding(ctx, r)
	if err != nil && err != errStaleBinding && (ctx.Err() != nil || !errors.As(err, new(refusal))) {
		return Preparation{}, err
	}
	if cached {
		key, grant, d, err := p.decideStored(ctx, q, r, config)
		if err != nil {
			return Preparation{}, err
		}
		if q.op == opPrepare {
			p.sweep(ctx, key)
		}
		switch {
		case d.outcome == outcomeFail:
			return Preparation{}, d.err
		case d.outcome == outcomeUse && !(q.force && config.Flow != pkceFlow):
			return Preparation{Credential: p.credential(r, key, grant)}, nil
		}
	}
	// An exchange, login or registration needs current metadata: full
	// discovery, honouring a challenge's resource_metadata, rebuilds the binding.
	if config, err = p.discover(ctx, r, q.challenge.header); err != nil {
		return Preparation{}, err
	}
	// The client source of an unrecorded CIMD or DCR client is chosen from
	// metadata, so its grant is not known yet: only decisions that need no
	// grant (configuration, challenge form, ceiling) apply here.
	_, _, d, err := p.decideStored(ctx, q, r, config)
	if err != nil {
		return Preparation{}, err
	}
	if d.outcome == outcomeFail && d.early {
		return Preparation{}, d.err
	}
	m := metadata{}
	if config, m, err = p.resolveMetadata(ctx, config); err != nil {
		return Preparation{}, err
	}
	if q.redirect != "" && config.Flow == pkceFlow {
		config.RedirectURI = q.redirect
	}
	if config, err = p.choose(ctx, r, config, m); err != nil {
		return Preparation{}, err
	}
	result, err, _ := p.obtain(ctx, r, config, m, true, q)
	return result, err
}

// obtain persists the binding when asked, resolves a client-credentials
// registration when the client needs one, then runs the coordinated
// acquisition and, when interactive and consent is needed, creates a login.
// A token-endpoint invalid_client for a registered client-credentials client
// compare-and-deletes that registration, then re-registers and re-acquires
// once. It also reports whether the token endpoint failed without processing
// the request (stale metadata).
func (p *Provider) obtain(ctx context.Context, r auth.Request, config ClientConfig, m metadata, persist bool, q call) (Preparation, error, bool) {
	interactive, force := q.op == opPrepare, q.force
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
		result, d, err, reason := p.acquireOnce(ctx, r, key, config, m, q)
		if reason == errLogin {
			login, err := p.login(ctx, key, config, m, d)
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

// acquireOnce decides under the grant lock and carries out the decision:
// serve, refresh, issue client credentials, or report errLogin with the
// decision for a login. It reports errEndpoint when the token endpoint failed
// without an OAuth error response (the metadata used may be stale) or
// errInvalidClient when it rejected the client.
func (p *Provider) acquireOnce(ctx context.Context, r auth.Request, key string, config ClientConfig, m metadata, q call) (Preparation, decision, error, error) {
	var result Preparation
	var d decision
	// inner is the SDK's own outcome; any other Coordinate error is the host's.
	var inner error
	err := p.options.Store.Coordinate(ctx, key, func(ctx context.Context) error {
		inner = p.acquireLocked(ctx, r, key, config, m, q, &result, &d)
		return inner
	})
	if err != nil {
		if inner == nil {
			return Preparation{}, d, safe(ctx, err, auth.CodeProviderFailed), nil
		}
		var reason error
		for _, sentinel := range []error{errEndpoint, errInvalidClient, errLogin} {
			if errors.Is(inner, sentinel) {
				reason = sentinel
			}
		}
		return Preparation{}, d, inner, reason
	}
	if ctx.Err() != nil {
		// The exchange completed detached; the caller still sees cancellation.
		return Preparation{}, d, errors.Join(fail(auth.CodeProviderFailed), ctx.Err()), nil
	}
	return result, d, nil, nil
}

// acquireLocked is acquireOnce's work under the grant lock.
func (p *Provider) acquireLocked(ctx context.Context, r auth.Request, key string, config ClientConfig, m metadata, q call, result *Preparation, d *decision) error {
	record, err := p.options.Store.Load(ctx, key)
	if err != nil {
		return safe(ctx, err, auth.CodeProviderFailed)
	}
	record = cloneRecord(record)
	*d = p.decide(q, r, config, record)
	if d.retire {
		if err := p.retire(ctx, key, record, q.sent); err != nil {
			return err
		}
	}
	var next *Record
	switch d.outcome {
	case outcomeFail:
		return d.err
	case outcomeUse:
		result.Credential = p.credential(r, key, record)
		return nil
	case outcomeLogin:
		return errLogin
	case outcomeRefresh:
		next, err = p.refresh(ctx, key, config, m, record)
	case outcomeAcquire:
		next, err = p.machine(ctx, key, config, m, record, d.acquisition(config, record))
	}
	if err != nil {
		return err
	}
	if err := d.settle(next); err != nil {
		return err
	}
	result.Credential = p.credential(r, key, next)
	return nil
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
func (p *Provider) machine(ctx context.Context, key string, c ClientConfig, m metadata, previous *Record, scopes []string) (*Record, error) {
	var granted []string
	if previous != nil {
		granted = previous.Scopes
	}
	c.Scopes = scopes
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
	return p.commit(ctx, key, generation(previous), next, err)
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
func (p *Provider) login(ctx context.Context, key string, c ClientConfig, m metadata, d decision) (*PendingLogin, error) {
	if !validRedirect(c.RedirectURI) || (c.source == sourceCIMD && !documentAccepts(c.ClientIDMetadataDocument, c.RedirectURI)) {
		return nil, fail(auth.CodeInvalidConfiguration)
	}
	current, err := p.options.Store.Load(ctx, key)
	if err != nil {
		return nil, safe(ctx, err, auth.CodeProviderFailed)
	}
	ceiling := merge(allowedScopes(c))
	c.Scopes = d.login(c, current)
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
	pending := PendingRecord{State: state, Verifier: verifier, RedirectURI: c.RedirectURI, Scopes: c.Scopes, Ceiling: ceiling, Required: d.required, HasRequired: true, HostRequired: merge(c.RequiredScopes), ExpiresAt: time.Now().Add(p.options.LoginLifetime), ClientID: c.ClientID}
	err = p.pending(ctx, key, func(logins []PendingRecord) ([]PendingRecord, error) {
		// Beyond the cap, the oldest login is cancelled.
		logins = append(logins, pending)
		return logins[max(0, len(logins)-p.options.MaxPendingLogins):], nil
	})
	if err != nil {
		return nil, err
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
		return classify(ctx, err, auth.CodeProviderFailed, nil)
	}
	if !cached {
		return nil
	}
	err = p.pending(ctx, p.key(r, config), func(logins []PendingRecord) ([]PendingRecord, error) {
		for i, pending := range logins {
			if subtle.ConstantTimeCompare([]byte(login.state), []byte(pending.State)) == 1 {
				return append(logins[:i:i], logins[i+1:]...), nil
			}
		}
		return logins, nil
	})
	if err != nil {
		return classify(ctx, err, auth.CodeProviderFailed, nil)
	}
	return nil
}

// errSweep ends a pending-login edit that only deletes expired logins.
var errSweep = errors.New("sweep")

// sweep deletes a grant's expired persisted pending logins and their verifiers.
func (p *Provider) sweep(ctx context.Context, key string) {
	if p.options.PersistLogins {
		p.pending(ctx, key, func([]PendingRecord) ([]PendingRecord, error) { return nil, errSweep })
	}
}

// Complete completes the pending login named by the callback's state:
//
//  1. It finds the login by state from stored records, before any host
//     callback. None (absent, unknown, expired or ended state) fails with
//     interaction_required.
//  2. It validates the callback against the login: exact redirect, no
//     fragment or userinfo, one state, the issuer where required, exactly one
//     of code or error, no duplicated parameter. Failure is access_denied
//     and leaves the login pending.
//  3. It applies current host policy: client selection, the recorded client
//     source still being permitted (else invalid_configuration) and issuer
//     metadata destination checks. Failure keeps the host's code and leaves
//     the login pending.
//  4. It claims the login atomically; from here the login is ended.
//  5. A consent denial is access_denied (a CIMD invalid_client is
//     invalid_configuration).
//  6. It exchanges the code: invalid_grant is interaction_required;
//     invalid_client is credential_unavailable (pre-registered),
//     invalid_configuration (CIMD) or interaction_required (DCR); any other
//     token-endpoint failure or invalid token response is provider_failed.
//  7. It saves the grant, then requires the grant within the current ceiling
//     to cover the required set stored on the login, else access_denied
//     carrying it.
//
// The creating Provider completes a login, or with Options.PersistLogins any
// Provider sharing the Store. Completion replaces the grant's client and
// tokens, so the newest completed login wins. Every returned error is an
// *auth.Error whose LoginEnded reports whether the login named by the state
// no longer exists after the call; it is false when that cannot be
// determined. Only step 7 attaches scopes.
func (p *Provider) Complete(ctx context.Context, r auth.Request, callback string) (auth.Credential, error) {
	credential, ended, err := p.complete(ctx, cloneRequest(r), callback)
	if err != nil {
		return auth.Credential{}, classify(ctx, err, auth.CodeProviderFailed, &ended)
	}
	p.markPrepared(r)
	return credential, nil
}

// errGone marks a claim that found no live login for the state.
var errGone = &auth.Error{Code: auth.CodeInteractionRequired}

// lookup finds the live pending login named by one of states through the
// stored binding, without host callbacks. It returns the grant key the login
// lives under and the stored binding.
func (p *Provider) lookup(ctx context.Context, r auth.Request, states []string) (string, *PendingRecord, *BindingMetadata, error) {
	if len(states) == 0 {
		return "", nil, nil, nil
	}
	stored, err := p.options.Store.Load(ctx, p.bindingKey(r))
	if err != nil {
		return "", nil, nil, safe(ctx, err, auth.CodeProviderFailed)
	}
	if stored == nil || stored.Binding == nil {
		return "", nil, nil, nil
	}
	previous := stored.Binding.Config
	previous.source = stored.Binding.Source
	key := p.key(r, previous)
	login, err := p.find(ctx, key, states)
	return key, login, stored.Binding, err
}

// find returns the live pending login under key named by one of states.
func (p *Provider) find(ctx context.Context, key string, states []string) (*PendingRecord, error) {
	record, err := p.logins.Load(ctx, pendingKey(key))
	if err != nil {
		return nil, safe(ctx, err, auth.CodeProviderFailed)
	}
	if record == nil {
		return nil, nil
	}
	now := time.Now()
	for _, login := range cloneRecord(record).Pending {
		for _, state := range states {
			if login.ExpiresAt.After(now) && subtle.ConstantTimeCompare([]byte(state), []byte(login.State)) == 1 {
				return &login, nil
			}
		}
	}
	return nil, nil
}

// validCallback checks a callback against its login before the claim.
func validCallback(callback string, value *url.URL, query url.Values, login *PendingRecord, issuer string, requireIssuer bool) bool {
	if value.User != nil || strings.Contains(callback, "#") || !callbackMatches(value, login.RedirectURI) {
		return false
	}
	for _, values := range query {
		// One state and no other duplicated parameter.
		if len(values) != 1 {
			return false
		}
	}
	code, denied := query.Get("code"), query.Has("error")
	if denied == query.Has("code") || (!denied && code == "") || (denied && query.Get("error") == "") {
		// Exactly one of a nonempty code or error.
		return false
	}
	iss, hasIssuer := query["iss"]
	return (!hasIssuer || iss[0] == issuer) && (hasIssuer || !requireIssuer)
}

// complete is Complete before classification; it reports the login-ended flag.
func (p *Provider) complete(ctx context.Context, r auth.Request, callback string) (auth.Credential, bool, error) {
	value, err := url.Parse(callback)
	if err != nil {
		// No login can be named: an invalid callback.
		return auth.Credential{}, false, fail(auth.CodeAccessDenied)
	}
	query, queryErr := url.ParseQuery(value.RawQuery)
	// 1. The login named by the state, before any host callback.
	key, login, binding, err := p.lookup(ctx, r, query["state"])
	if err != nil {
		return auth.Credential{}, false, err
	}
	if login == nil {
		return auth.Credential{}, true, fail(auth.CodeInteractionRequired)
	}
	if err := bounded(ctx); err != nil {
		return auth.Credential{}, false, err
	}
	// 2. The callback itself.
	if queryErr != nil || !validCallback(callback, value, query, login, binding.Config.Issuer, binding.IssuerMetadata.ResponseIssuer) {
		return auth.Credential{}, false, fail(auth.CodeAccessDenied)
	}
	// 3. Current host policy and capabilities: the pending login never makes
	// a captured runtime secret authoritative.
	config, _, cached, err := p.cachedBinding(ctx, r)
	switch {
	case err == errStaleBinding:
		// The recorded client source is no longer permitted.
		return auth.Credential{}, false, fail(auth.CodeInvalidConfiguration)
	case err != nil:
		return auth.Credential{}, false, err
	case !cached || p.key(r, config) != key || (config.source != sourceDCR && login.ClientID != config.ClientID):
		return auth.Credential{}, false, fail(auth.CodeInvalidConfiguration)
	}
	config, m, err := p.resolveMetadata(ctx, config)
	if err != nil {
		return auth.Credential{}, false, err
	}
	if m.ResponseIssuer && !query.Has("iss") {
		return auth.Credential{}, false, fail(auth.CodeAccessDenied)
	}
	// 4. Claim the login once.
	pending, err := p.claim(ctx, key, login.State)
	if err == errGone {
		return auth.Credential{}, true, fail(auth.CodeInteractionRequired)
	}
	if err != nil {
		// Uncertain: re-read on a fresh short budget.
		recheck, cancel := context.WithTimeout(context.WithoutCancel(ctx), recheckBudget)
		defer cancel()
		still, findErr := p.find(recheck, key, []string{login.State})
		return auth.Credential{}, findErr == nil && still == nil, err
	}
	// 5. Consent denial.
	if denied := query.Get("error"); denied != "" {
		if denied == "invalid_client" && config.source == sourceCIMD {
			// The authorization server rejected the CIMD client: configuration.
			return auth.Credential{}, true, fail(auth.CodeInvalidConfiguration)
		}
		return auth.Credential{}, true, fail(auth.CodeAccessDenied)
	}
	// 6 and 7. The current ceiling, before the login's requested scopes
	// replace Scopes: a nil AllowedScopes defaults to the current scopes.
	ceiling := allowedScopes(config)
	required := pending.Required
	if !pending.HasRequired {
		// A login from an older release stored no required set.
		required = merge(config.RequiredScopes)
		if pending.HostRequired != nil {
			required = merge(pending.HostRequired)
		}
	}
	exchange := cloneConfig(config)
	exchange.ClientID, exchange.Scopes, exchange.RedirectURI = pending.ClientID, pending.Scopes, pending.RedirectURI
	credential, err := p.exchange(ctx, r, key, exchange, ceiling, required, m, pending, query.Get("code"))
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
		return auth.Credential{}, true, err
	}
	return *credential, true, nil
}

// recheckBudget bounds re-reading a pending login after an uncertain claim.
var recheckBudget = 5 * time.Second

// claim atomically removes the live pending login named by state.
func (p *Provider) claim(ctx context.Context, key, state string) (PendingRecord, error) {
	var claimed PendingRecord
	err := p.pending(ctx, key, func(logins []PendingRecord) ([]PendingRecord, error) {
		for i, login := range logins {
			if subtle.ConstantTimeCompare([]byte(state), []byte(login.State)) == 1 {
				claimed = login
				return append(logins[:i:i], logins[i+1:]...), nil
			}
		}
		return nil, errGone
	})
	if errors.Is(err, errGone) {
		return claimed, errGone
	}
	if err == nil && claimed.State == "" {
		// The store ran no edit: the outcome is uncertain.
		err = fail(auth.CodeProviderFailed)
	}
	return claimed, err
}

// callbackMatches compares a callback with the login's exact redirect: scheme,
// host and port, path, and every parameter of the redirect's own query.
// Parameters the authorization server adds (session_state) are allowed.
func callbackMatches(callback *url.URL, raw string) bool {
	redirect, err := url.Parse(raw)
	if err != nil || callback.Scheme != redirect.Scheme || callback.Host != redirect.Host || callback.EscapedPath() != redirect.EscapedPath() {
		return false
	}
	got := callback.Query()
	for name, values := range redirect.Query() {
		if !slices.Equal(got[name], values) {
			return false
		}
	}
	return true
}

// exchange redeems a claimed login's code and commits its client and tokens
// into the grant under the grant lock, replacing the previous ones. Once the
// code is sent, the outcome is received and committed detached from caller
// cancellation. The committed grant, within ceiling, must cover required.
func (p *Provider) exchange(ctx context.Context, r auth.Request, key string, c ClientConfig, ceiling, required []string, m metadata, pending PendingRecord, code string) (*auth.Credential, error) {
	ctx, cancel := sending(ctx)
	if cancel == nil {
		return nil, ctx.Err()
	}
	defer cancel()
	token, err := oauthConfig(c, m).Exchange(context.WithValue(ctx, oauth2.HTTPClient, p.tokenClient(c, m, nil)), code, oauth2.VerifierOption(pending.Verifier), oauth2.SetAuthURLParam("resource", c.Resource))
	if err != nil {
		return nil, exchangeError(ctx, err)
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
			// Scopes only: a short-lived token is still the completed grant.
			if err := completed(next, required, ceiling); err != nil {
				return err
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

// exchangeError maps a failed code exchange: invalid_grant needs a new login,
// invalid_client is classified by client source, and every other failure is
// provider_failed.
func exchangeError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var rejected *oauth2.RetrieveError
	if errors.As(err, &rejected) {
		switch rejected.ErrorCode {
		case "invalid_grant":
			return fail(auth.CodeInteractionRequired)
		case "invalid_client":
			return errInvalidClient
		}
	}
	return fail(auth.CodeProviderFailed)
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

// Credential serves the operation's credential without interaction: a
// binding, or a stored binding learned for an unbound request.
func (p *Provider) Credential(ctx context.Context, r auth.Request) (auth.Credential, error) {
	if err := ctx.Err(); err != nil {
		return auth.Credential{}, err
	}
	if len(r.Binding) == 0 {
		stored, err := p.options.Store.Load(ctx, p.bindingKey(r))
		if err != nil {
			return auth.Credential{}, classify(ctx, safe(ctx, err, auth.CodeProviderFailed), auth.CodeProviderFailed, nil)
		}
		if stored == nil || stored.Binding == nil {
			return auth.Credential{}, classify(ctx, fail(auth.CodeCredentialUnavailable), auth.CodeCredentialUnavailable, nil)
		}
	}
	if err := bounded(ctx); err != nil {
		return auth.Credential{}, classify(ctx, err, auth.CodeInvalidConfiguration, nil)
	}
	result, err := p.operate(ctx, cloneRequest(r), call{op: opCredential})
	if err != nil {
		return auth.Credential{}, classify(ctx, err, auth.CodeProviderFailed, nil)
	}
	return *result.Credential, nil
}

// Challenge recovers from a 401 or 403 without creating a login, through the
// decision procedure: a malformed or non-step-up challenge is access_denied;
// a 401 retires the rejected generation and its scope is only a
// client-credentials request hint; a 403 insufficient_scope is a step-up
// requirement, refused when the stored grant already records it for the
// rejected generation.
func (p *Provider) Challenge(ctx context.Context, r auth.Request, c auth.Challenge) (*auth.Credential, error) {
	if err := bounded(ctx); err != nil {
		return nil, classify(ctx, err, auth.CodeInvalidConfiguration, nil)
	}
	q := call{op: opChallenge, challenge: parseChallenge(c.StatusCode, strings.Join(c.Header.Values("WWW-Authenticate"), ", "))}
	if c.StatusCode != http.StatusUnauthorized && c.StatusCode != http.StatusForbidden {
		q.challenge = challenge{kind: forbidden, status: c.StatusCode}
	}
	if c.Attempt != nil {
		owner, ok := c.Attempt.(attempted)
		if !ok || owner.owner != p || owner.identity != requestIdentity(r) {
			return nil, classify(ctx, fail(auth.CodeInvalidConfiguration), auth.CodeInvalidConfiguration, nil)
		}
		q.sent = owner.generation
		if c.StatusCode == http.StatusUnauthorized {
			// Step 0: a 401 retires the sent generation before anything else,
			// including client selection and a malformed challenge.
			err := p.options.Store.Coordinate(ctx, owner.key, func(ctx context.Context) error {
				current, err := p.options.Store.Load(ctx, owner.key)
				if err != nil {
					return safe(ctx, err, auth.CodeProviderFailed)
				}
				return p.retire(ctx, owner.key, current, q.sent)
			})
			if err != nil {
				return nil, classify(ctx, safe(ctx, err, auth.CodeProviderFailed), auth.CodeProviderFailed, nil)
			}
		}
	} else if len(r.Binding) != 0 {
		return nil, classify(ctx, fail(auth.CodeInvalidConfiguration), auth.CodeInvalidConfiguration, nil)
	}
	result, err := p.operate(ctx, cloneRequest(r), q)
	if err != nil {
		return nil, classify(ctx, err, auth.CodeProviderFailed, nil)
	}
	return result.Credential, nil
}

// PreemptiveCredential is the up-front lookup for a known binding, through
// the decision procedure. It serves a usable stored grant, or renews it
// non-interactively (refresh or client credentials) with persisted issuer
// metadata, fetching only the stored issuer's metadata when none is
// persisted. It never runs protected-resource discovery or creates a login.
// Only a store miss or host policy refusal yields nil, an anonymous attempt;
// a known binding whose grant cannot be renewed (including one needing
// consent) fails the operation.
func (p *Provider) PreemptiveCredential(ctx context.Context, r auth.Request) (*auth.Credential, error) {
	credential, err := p.preemptive(ctx, cloneRequest(r))
	if err != nil {
		return nil, classify(ctx, err, auth.CodeProviderFailed, nil)
	}
	return credential, nil
}

func (p *Provider) preemptive(ctx context.Context, r auth.Request) (*auth.Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := auth.NormalizeTarget(r); err != nil {
		return nil, err
	}
	// Only a store miss or a host policy refusal is anonymous.
	config, m, cached, err := p.cachedBinding(ctx, r)
	if err != nil {
		if ctx.Err() != nil || !errors.As(err, new(refusal)) {
			return nil, err
		}
		return nil, nil
	}
	if !cached {
		return nil, nil
	}
	q := call{op: opPreemptive}
	key, grant, d, err := p.decideStored(ctx, q, r, config)
	if err != nil {
		return nil, err
	}
	switch d.outcome {
	case outcomeFail:
		return nil, d.err
	case outcomeUse:
		return p.credential(r, key, grant), nil
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, lookupBudget)
		defer cancel()
	}
	if m.TokenEndpoint == "" {
		// Only the stored issuer's metadata; never protected-resource discovery.
		if config, m, err = p.resolveMetadata(ctx, config); err != nil {
			return nil, err
		}
	}
	result, err, stale := p.obtain(ctx, r, config, m, false, q)
	if stale {
		// Refetch only the stored issuer's metadata once, persist it and retry.
		if config, m, err = p.resolveMetadata(ctx, config); err != nil {
			return nil, err
		}
		result, err, _ = p.obtain(ctx, r, config, m, true, q)
	}
	return result.Credential, err
}
