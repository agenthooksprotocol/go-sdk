package oauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
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

// New requires explicit host network, identity, persistence and token-validation
// policy. No default HTTP client, store, issuer or background task is installed.
func New(options Options) (*Provider, error) {
	if options.Namespace == "" || options.Store == nil || options.HTTPClient == nil || options.HTTPClient.Transport == nil || options.CheckDestination == nil || options.SelectClient == nil || options.ValidateToken == nil {
		return nil, fail(auth.CodeInvalidConfiguration)
	}
	client := *options.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	return &Provider{options: options, client: client, pending: make(map[string]*PendingLogin)}, nil
}

func fail(code auth.Code) error { return &auth.Error{Code: code} }
func safe(ctx context.Context, err error, fallback auth.Code) error {
	if ctx.Err() != nil {
		return errors.Join(fail(fallback), ctx.Err())
	}
	var classified *auth.Error
	if errors.As(err, &classified) && classified != nil {
		return fail(classified.Code)
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
func sortedScopes(scopes []string) []string {
	result := append([]string(nil), scopes...)
	slices.Sort(result)
	return result
}
func sameScopes(a, b []string) bool { return slices.Equal(sortedScopes(a), sortedScopes(b)) }
func validConfig(c ClientConfig) bool {
	if !discoveryIssuer(c.Issuer) || !discoveryHTTPS(c.Resource) || c.ClientID == "" || (c.Flow != "authorization_code_pkce" && c.Flow != "client_credentials") {
		return false
	}
	for _, scope := range append(append(append([]string{}, c.Scopes...), allowedScopes(c)...), c.RequiredScopes...) {
		if !authutil.ValidScope(scope) {
			return false
		}
	}
	if !scopeSubset(c.Scopes, allowedScopes(c)) || !scopeSubset(c.RequiredScopes, allowedScopes(c)) {
		return false
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
		b.RequiredScopes = append([]string(nil), b.RequiredScopes...)
		b.IssuerMetadata.GrantTypes = append([]string(nil), b.IssuerMetadata.GrantTypes...)
		b.IssuerMetadata.ChallengeMethods = append([]string(nil), b.IssuerMetadata.ChallengeMethods...)
		b.IssuerMetadata.TokenAuthMethods = append([]string(nil), b.IssuerMetadata.TokenAuthMethods...)
		copy.Binding = &b
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
	binding.Scopes = sortedScopes(binding.Scopes)
	encoded, _ := json.Marshal([]any{r.BackendID, r.Purpose, r.Destination, target.Kind(), binding})
	return string(encoded)
}
func sortedUnique(scopes []string) []string { return slices.Compact(sortedScopes(scopes)) }
func allowedScopes(c ClientConfig) []string {
	if c.AllowedScopes != nil {
		return c.AllowedScopes
	}
	return c.Scopes
}
func scopeSubset(scopes, ceiling []string) bool {
	for _, s := range scopes {
		if !contains(ceiling, s) {
			return false
		}
	}
	return true
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
func (p *Provider) key(r auth.Request, c ClientConfig) string {
	partition := "binding:" + p.bindingKey(r)
	if c.GrantPartition != "" {
		partition = "shared:" + c.GrantPartition
	}
	return frame("ahp.oauth.grant:", p.options.Namespace, c.Issuer, c.Resource, c.ClientID, c.Flow, strings.Join(sortedUnique(allowedScopes(c)), " "), partition)
}
func usable(record *Record) bool {
	return record != nil && !record.Rejected && !record.RefreshRejected && authutil.ValidBearer(record.AccessToken) && (record.ExpiresAt.IsZero() || record.ExpiresAt.After(time.Now().Add(10*time.Second)))
}
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
		return ClientConfig{}, metadata{}, false, safe(ctx, err, auth.CodeUntrustedDestination)
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
		return ClientConfig{}, metadata{}, false, nil
	}

	c.RequiredScopes = sortedUnique(append(c.RequiredScopes, b.RequiredScopes...))
	if !scopeSubset(c.RequiredScopes, allowedScopes(c)) {
		return ClientConfig{}, metadata{}, false, fail(auth.CodeAccessDenied)
	}
	return c, b.IssuerMetadata, true, nil
}
func (p *Provider) persistBinding(ctx context.Context, r auth.Request, c ClientConfig, m metadata) (ClientConfig, error) {
	c = cloneConfig(c)
	key := p.bindingKey(r)
	err := p.options.Store.Coordinate(ctx, key, func(ctx context.Context) error {
		old, err := p.options.Store.Load(ctx, key)
		if err != nil {
			return safe(ctx, err, auth.CodeProviderFailed)
		}
		if old != nil && old.Binding != nil && p.key(r, old.Binding.Config) == p.key(r, c) {
			c.RequiredScopes = sortedUnique(append(c.RequiredScopes, old.Binding.RequiredScopes...))
		}
		if !scopeSubset(c.RequiredScopes, allowedScopes(c)) {
			return fail(auth.CodeAccessDenied)
		}
		public := cloneConfig(c)
		public.ClientSecret = ""
		return p.save(ctx, key, generation(old), &Record{Generation: randomID(), Binding: &BindingMetadata{Config: public, IssuerMetadata: m, RequiredScopes: append([]string(nil), c.RequiredScopes...)}})
	})
	return c, err
}

type attempted struct {
	owner                     *Provider
	key, generation, identity string
}

func (attempted) String() string   { return "oauth.attempt{redacted}" }
func (attempted) GoString() string { return "oauth.attempt{redacted}" }
func (p *Provider) credential(r auth.Request, key string, record *Record) auth.Credential {
	return auth.Credential{Type: "bearer", Token: record.AccessToken, Attempt: attempted{p, key, record.Generation, requestIdentity(r)}}
}

// Prepare is the host-controlled interaction entrypoint. The context MUST carry
// the enclosing operation deadline. A Login never starts a listener or browser.
func (p *Provider) Prepare(ctx context.Context, r auth.Request) (Preparation, error) {
	return p.prepare(ctx, cloneRequest(r), "", true)
}
func (p *Provider) prepare(ctx context.Context, r auth.Request, challenge string, interactive bool) (Preparation, error) {
	if err := bounded(ctx); err != nil {
		return Preparation{}, err
	}
	p.prune(time.Now())
	config, m, cached, err := p.cachedBinding(ctx, r)
	if err == nil && !cached {
		config, m, err = p.resolve(ctx, r, challenge)
	}
	if err != nil {
		return Preparation{}, safe(ctx, err, auth.CodeDiscoveryFailed)
	}
	required, err := bearerParameter(challenge, "scope")
	if err != nil {
		return Preparation{}, fail(auth.CodeDiscoveryFailed)
	}
	if required != "" && !authutil.ValidScopeList(required) {
		return Preparation{}, fail(auth.CodeAccessDenied)
	}
	config.RequiredScopes = sortedUnique(append(config.RequiredScopes, strings.Fields(required)...))
	if !scopeSubset(config.RequiredScopes, allowedScopes(config)) {
		return Preparation{}, fail(auth.CodeAccessDenied)
	}
	// A usable grant requires no remote metadata. Renewal refreshes capabilities
	// outside the grant lock; the coordinated path below always rechecks the grant.
	if cached {
		current, loadErr := p.options.Store.Load(ctx, p.key(r, config))
		if loadErr != nil {
			return Preparation{}, safe(ctx, loadErr, auth.CodeProviderFailed)
		}
		if !usable(current) || !scopeSubset(config.RequiredScopes, current.Scopes) {
			config, m, err = p.resolveMetadata(ctx, config)
			if err != nil {
				return Preparation{}, safe(ctx, err, auth.CodeDiscoveryFailed)
			}
		}
	}
	config, err = p.persistBinding(ctx, r, config, m)
	if err != nil {
		return Preparation{}, err
	}
	key := p.key(r, config)
	var result Preparation
	source := ctx
	err = p.options.Store.Coordinate(ctx, key, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		record, err := p.options.Store.Load(ctx, key)
		if err != nil {
			return safe(ctx, err, auth.CodeProviderFailed)
		}
		binding, loadErr := p.options.Store.Load(ctx, p.bindingKey(r))
		if loadErr != nil {
			return safe(ctx, loadErr, auth.CodeProviderFailed)
		}
		if binding != nil && binding.Binding != nil && p.key(r, binding.Binding.Config) == key {
			config.RequiredScopes = sortedUnique(append(config.RequiredScopes, binding.Binding.RequiredScopes...))
		}
		if !scopeSubset(config.RequiredScopes, allowedScopes(config)) {
			return fail(auth.CodeAccessDenied)
		}
		record = cloneRecord(record)
		if record != nil {
			if record.Generation == "" || !scopeSubset(record.Scopes, allowedScopes(config)) {
				return fail(auth.CodeInvalidConfiguration)
			}
			if record.RefreshRejected && config.Flow == "authorization_code_pkce" {
				if !interactive {
					return fail(auth.CodeInteractionRequired)
				}
				config.AllowedScopes = append([]string{}, allowedScopes(config)...)
				config.Scopes = sortedUnique(append(config.Scopes, config.RequiredScopes...))
				login, err := p.login(ctx, source, r, key, generation(record), config, m)
				if err != nil {
					return err
				}
				result.Login = login
				return nil
			}
			if usable(record) && scopeSubset(config.RequiredScopes, record.Scopes) {
				credential := p.credential(r, key, record)
				result.Credential = &credential
				return nil
			}
			if config.Flow == "authorization_code_pkce" && record.RefreshToken != "" && scopeSubset(config.RequiredScopes, record.Scopes) {
				refreshed, err := p.refresh(ctx, key, config, m, record)
				if err != nil {
					return err
				}
				if !scopeSubset(config.RequiredScopes, refreshed.Scopes) {
					return fail(auth.CodeAccessDenied)
				}
				credential := p.credential(r, key, refreshed)
				result.Credential = &credential
				return nil
			}
		}
		if config.Flow == "client_credentials" {
			config.AllowedScopes = append([]string{}, allowedScopes(config)...)
			config.Scopes = sortedUnique(append(config.Scopes, config.RequiredScopes...))
			token, err := p.machine(ctx, config, m)
			if err != nil {
				return err
			}
			next, recordErr := p.record(ctx, config, token)
			if next == nil {
				return recordErr
			}
			if err = p.save(ctx, key, generation(record), next); err != nil {
				return err
			}
			if recordErr != nil {
				return recordErr
			}
			if !scopeSubset(config.RequiredScopes, next.Scopes) {
				return fail(auth.CodeAccessDenied)
			}
			credential := p.credential(r, key, next)
			result.Credential = &credential
			return nil
		}
		if !interactive {
			return fail(auth.CodeInteractionRequired)
		}
		config.AllowedScopes = append([]string{}, allowedScopes(config)...)
		config.Scopes = sortedUnique(append(config.Scopes, config.RequiredScopes...))
		login, err := p.login(ctx, source, r, key, generation(record), config, m)
		if err != nil {
			return err
		}
		result.Login = login
		return nil
	})
	if err != nil {
		return Preparation{}, safe(ctx, err, auth.CodeProviderFailed)
	}
	return result, nil
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
func (p *Provider) record(ctx context.Context, c ClientConfig, token *oauth2.Token) (*Record, error) {
	if token == nil {
		return nil, fail(auth.CodeCredentialUnavailable)
	}
	scopes := append([]string(nil), c.Scopes...)
	next := &Record{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ExpiresAt: token.Expiry, Scopes: scopes, Generation: randomID()}
	reject := func(code auth.Code) (*Record, error) {
		next.Rejected = true
		next.AccessToken = ""
		next.Scopes = nil
		return next, fail(code)
	}
	if !strings.EqualFold(token.TokenType, "Bearer") || !authutil.ValidBearer(token.AccessToken) || (!token.Expiry.IsZero() && !token.Expiry.After(time.Now())) {
		return reject(auth.CodeCredentialUnavailable)
	}
	if extra := token.Extra("expires_in"); extra != nil {
		var expiry float64
		var err error
		switch value := extra.(type) {
		case float64:
			expiry = value
		case int64:
			expiry = float64(value)
		case int:
			expiry = float64(value)
		case string:
			expiry, err = strconv.ParseFloat(value, 64)
		case json.Number:
			expiry, err = value.Float64()
		default:
			err = errors.New("invalid expiry")
		}
		if err != nil || math.IsNaN(expiry) || math.IsInf(expiry, 0) || expiry <= 0 {
			return reject(auth.CodeCredentialUnavailable)
		}
	}
	if extra := token.Extra("scope"); extra != nil {
		value, ok := extra.(string)
		if !ok || (value != "" && !authutil.ValidScopeList(value)) {
			return reject(auth.CodeAccessDenied)
		}
		scopes = strings.Fields(value)
		if !scopeSubset(scopes, allowedScopes(c)) {
			return reject(auth.CodeAccessDenied)
		}
	}
	if err := p.options.ValidateToken(ctx, c, token); err != nil {
		return nil, safe(ctx, err, auth.CodeAccessDenied)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	next.Scopes = sortedUnique(scopes)
	return next, nil
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

func (p *Provider) machine(ctx context.Context, c ClientConfig, m metadata) (*oauth2.Token, error) {
	client := p.tokenClient(ctx, c, m)
	conf := clientcredentials.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, TokenURL: m.TokenEndpoint, Scopes: c.Scopes, AuthStyle: authStyle(c), EndpointParams: url.Values{"resource": {c.Resource}}}
	token, err := conf.Token(context.WithValue(ctx, oauth2.HTTPClient, client))
	if err != nil {
		return nil, acquisitionError(ctx, err, false)
	}
	return token, nil
}
func acquisitionError(ctx context.Context, err error, interactive bool) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var rejected *oauth2.RetrieveError
	if errors.As(err, &rejected) {
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
	}
	return fail(auth.CodeProviderFailed)
}
func grantError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var rejected *oauth2.RetrieveError
	if errors.As(err, &rejected) && rejected.ErrorCode == "invalid_grant" {
		return fail(auth.CodeRefreshRejected)
	}
	return acquisitionError(ctx, err, false)
}
func knownTemporary(err error) bool {
	var result *oauth2.RetrieveError
	return errors.As(err, &result) && (result.ErrorCode == "temporarily_unavailable" || result.ErrorCode == "server_error")
}
func (p *Provider) refresh(ctx context.Context, key string, c ClientConfig, m metadata, previous *Record) (*Record, error) {
	// Persist ambiguity before exchange: CAS failure or cancellation cannot erase
	// evidence of possible external rotation. The marker permits explicit retry.
	marker := cloneRecord(previous)
	marker.Generation = randomID()
	marker.RefreshUncertain = true
	if err := p.save(ctx, key, previous.Generation, marker); err != nil {
		return nil, err
	}
	conf := oauthConfig(c, m)
	token, err := conf.TokenSource(context.WithValue(ctx, oauth2.HTTPClient, p.tokenClient(ctx, c, m)), &oauth2.Token{RefreshToken: previous.RefreshToken, Expiry: time.Now().Add(-time.Minute)}).Token()
	if err != nil {
		if ctx.Err() == nil {
			retained := cloneRecord(previous)
			retained.Generation = randomID()
			var rejected *oauth2.RetrieveError
			retained.RefreshRejected = errors.As(err, &rejected) && rejected.ErrorCode == "invalid_grant"
			retained.RefreshUncertain = !retained.RefreshRejected && !knownTemporary(err)
			if saveErr := p.save(ctx, key, marker.Generation, retained); saveErr != nil {
				return nil, saveErr
			}
		}
		return nil, grantError(ctx, err)
	}
	refreshConfig := cloneConfig(c)
	refreshConfig.Scopes = append([]string(nil), previous.Scopes...)
	refreshConfig.AllowedScopes = append([]string{}, previous.Scopes...)
	next, recordErr := p.record(ctx, refreshConfig, token)
	if next == nil {
		return nil, recordErr
	}
	if next.RefreshToken == "" {
		next.RefreshToken = previous.RefreshToken
	}
	if err = p.save(ctx, key, marker.Generation, next); err != nil {
		return nil, err
	}
	if recordErr != nil {
		return nil, recordErr
	}
	return next, nil
}

func (p *Provider) login(ctx, source context.Context, r auth.Request, key, expected string, c ClientConfig, m metadata) (*PendingLogin, error) {
	budget, _ := source.Deadline()
	deadline := budget
	now := time.Now()
	if limit := now.Add(10 * time.Minute); deadline.After(limit) {
		deadline = limit
	}
	p.mu.Lock()
	for k, login := range p.pending {
		if login.used.Load() || !login.deadline.After(now) {
			login.used.Store(true)
			delete(p.pending, k)
		}
	}
	existing := p.pending[key]
	if existing != nil && (existing.expected != expected || existing.identity != requestIdentity(r) || !sameScopes(existing.config.Scopes, c.Scopes) || !sameScopes(existing.config.RequiredScopes, c.RequiredScopes) || existing.config.RedirectURI != c.RedirectURI) {
		existing.used.Store(true)
		delete(p.pending, key)
		existing = nil
	}
	full := len(p.pending) >= 128
	p.mu.Unlock()
	var oldBudget time.Time
	if existing != nil {
		oldBudget, _ = existing.source.Deadline()
	}
	if existing != nil && (existing.source.Err() != nil || oldBudget.Before(budget)) {
		p.remove(existing)
		existing = nil
		p.mu.Lock()
		full = len(p.pending) >= 128
		p.mu.Unlock()
	}
	if existing != nil {
		return existing, nil
	}
	if full {
		return nil, fail(auth.CodeProviderFailed)
	}
	verifier := oauth2.GenerateVerifier()
	state := randomID()
	loginURL := oauthConfig(c, m).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("resource", c.Resource))
	if err := p.check(ctx, loginURL, Authorization); err != nil {
		return nil, err
	}
	login := &PendingLogin{pendingState: &pendingState{owner: p, key: key, expected: expected, identity: requestIdentity(r), authorizationURL: loginURL, state: state, verifier: verifier, config: c, metadata: m, request: cloneRequest(r), deadline: deadline, source: source}}
	p.mu.Lock()
	// Coordinate serializes a key, but another key may have filled the bounded
	// registry while host policy ran. No callback runs with this mutex held.
	if len(p.pending) >= 128 {
		p.mu.Unlock()
		return nil, fail(auth.CodeProviderFailed)
	}
	p.pending[key] = login
	p.mu.Unlock()
	return login, nil
}

// prune snapshots membership before invoking Context.Err outside the mutex.
// remove validates exact membership again, so cancellation cannot delete a
// replacement login or race a completion into resurrecting consumed state.
func (p *Provider) prune(now time.Time) {
	p.mu.Lock()
	entries := make([]*PendingLogin, 0, len(p.pending))
	for key, login := range p.pending {
		if login.used.Load() || !login.deadline.After(now) {
			login.used.Store(true)
			delete(p.pending, key)
		} else {
			entries = append(entries, login)
		}
	}
	p.mu.Unlock()
	for _, login := range entries {
		if login.source.Err() != nil {
			p.remove(login)
		}
	}
}
func (p *Provider) consume(login *PendingLogin) bool {
	if login == nil || login.pendingState == nil || login.owner != p {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending[login.key] != login || !login.used.CompareAndSwap(false, true) {
		return false
	}
	delete(p.pending, login.key)
	return true
}

func (p *Provider) remove(login *PendingLogin) {
	p.mu.Lock()
	if p.pending[login.key] == login {
		login.used.Store(true)
		delete(p.pending, login.key)
	}
	p.mu.Unlock()
}

// Cancel abandons a pending login. It never changes stored credentials.
func (p *Provider) Cancel(login *PendingLogin) {
	p.consume(login)
}

// Complete validates one callback and performs a single bounded code exchange.
// The original consent deadline cannot be extended by a new completion context.
func (p *Provider) Complete(ctx context.Context, login *PendingLogin, callback string) (auth.Credential, error) {
	if err := bounded(ctx); err != nil {
		return auth.Credential{}, err
	}
	if login == nil || login.pendingState == nil || login.owner != p || login.used.Load() {
		return auth.Credential{}, fail(auth.CodeInvalidConfiguration)
	}
	ctx, cancel := context.WithDeadline(ctx, login.deadline)
	defer cancel()
	stop := context.AfterFunc(login.source, cancel)
	defer stop()
	if err := login.source.Err(); err != nil {
		return auth.Credential{}, err
	}
	if err := ctx.Err(); err != nil {
		return auth.Credential{}, err
	}
	value, err := url.Parse(callback)
	redirect, _ := url.Parse(login.config.RedirectURI)
	if err != nil || value.User != nil || strings.Contains(callback, "#") || value.Scheme != redirect.Scheme || value.Host != redirect.Host || value.EscapedPath() != redirect.EscapedPath() {
		return auth.Credential{}, fail(auth.CodeAccessDenied)
	}
	query, err := url.ParseQuery(value.RawQuery)
	if err != nil || len(query["state"]) != 1 || subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(login.state)) != 1 {
		return auth.Credential{}, fail(auth.CodeAccessDenied)
	}
	if issuer := query["iss"]; len(issuer) > 1 || (len(issuer) == 1 && issuer[0] != login.config.Issuer) || (login.metadata.ResponseIssuer && len(issuer) != 1) {
		return auth.Credential{}, fail(auth.CodeAccessDenied)
	}
	if (query.Get("error") == "" && (len(query["code"]) != 1 || query.Get("code") == "")) || len(query["error"]) > 1 {
		return auth.Credential{}, fail(auth.CodeAccessDenied)
	}
	completionConfig, completionMetadata := cloneConfig(login.config), login.metadata
	if query.Get("error") == "" {
		// Resolve current secrets and permission policy again after host interaction.
		// The consent handle never makes its captured runtime secret authoritative.
		current, policyErr := p.options.SelectClient(ctx, cloneRequest(login.request), []string{login.config.Issuer}, login.config.Resource)
		if policyErr != nil {
			return auth.Credential{}, safe(ctx, policyErr, auth.CodeUntrustedDestination)
		}
		current = cloneConfig(current)
		if !validConfig(current) || p.key(login.request, current) != login.key || current.RedirectURI != login.config.RedirectURI || !scopeSubset(login.config.Scopes, allowedScopes(current)) {
			return auth.Credential{}, fail(auth.CodeInvalidConfiguration)
		}
		current.RequiredScopes = sortedUnique(append(current.RequiredScopes, login.config.RequiredScopes...))
		if !scopeSubset(current.RequiredScopes, allowedScopes(current)) {
			return auth.Credential{}, fail(auth.CodeAccessDenied)
		}
		current.AllowedScopes = append([]string{}, allowedScopes(current)...)
		current.Scopes = append([]string(nil), login.config.Scopes...)
		resolved, fresh, resolveErr := p.resolveMetadata(ctx, current)
		if resolveErr != nil {
			return auth.Credential{}, resolveErr
		}
		completionConfig, completionMetadata = resolved, fresh
	}
	if !p.consume(login) {
		return auth.Credential{}, fail(auth.CodeInvalidConfiguration)
	}
	if query.Get("error") != "" {
		return auth.Credential{}, fail(auth.CodeAccessDenied)
	}
	var credential auth.Credential
	err = p.options.Store.Coordinate(ctx, login.key, func(ctx context.Context) error {
		// Delivery can record a step-up while host consent remains pending. Read
		// those binding requirements before either the newer-grant shortcut or the
		// code exchange; the captured consent does not supersede them.
		binding, loadErr := p.options.Store.Load(ctx, p.bindingKey(login.request))
		if loadErr != nil {
			return safe(ctx, loadErr, auth.CodeProviderFailed)
		}
		if binding != nil && binding.Binding != nil && p.key(login.request, binding.Binding.Config) == login.key {
			completionConfig.RequiredScopes = sortedUnique(append(completionConfig.RequiredScopes, binding.Binding.RequiredScopes...))
		}
		if !scopeSubset(completionConfig.RequiredScopes, allowedScopes(completionConfig)) {
			return fail(auth.CodeAccessDenied)
		}
		current, err := p.options.Store.Load(ctx, login.key)
		if err != nil {
			return safe(ctx, err, auth.CodeProviderFailed)
		}
		current = cloneRecord(current)
		if generation(current) != login.expected {
			if usable(current) && scopeSubset(completionConfig.RequiredScopes, current.Scopes) {
				credential = p.credential(login.request, login.key, current)
				return nil
			}
			return fail(auth.CodeInteractionRequired)
		}
		token, err := oauthConfig(completionConfig, completionMetadata).Exchange(context.WithValue(ctx, oauth2.HTTPClient, p.tokenClient(ctx, completionConfig, completionMetadata)), query.Get("code"), oauth2.VerifierOption(login.verifier), oauth2.SetAuthURLParam("resource", completionConfig.Resource))
		if err != nil {
			return acquisitionError(ctx, err, true)
		}
		next, recordErr := p.record(ctx, completionConfig, token)
		if next == nil {
			return recordErr
		}
		if err = p.save(ctx, login.key, generation(current), next); err != nil {
			return err
		}
		if recordErr != nil {
			return recordErr
		}
		if !scopeSubset(completionConfig.RequiredScopes, next.Scopes) {
			return fail(auth.CodeAccessDenied)
		}
		credential = p.credential(login.request, login.key, next)
		return nil
	})
	if err != nil {
		return auth.Credential{}, safe(ctx, err, auth.CodeProviderFailed)
	}
	return credential, nil
}

func (p *Provider) Credential(ctx context.Context, r auth.Request) (auth.Credential, error) {
	if err := ctx.Err(); err != nil {
		return auth.Credential{}, err
	}
	if len(r.Binding) == 0 {
		cached, err := p.PreemptiveCredential(ctx, r)
		if err != nil {
			return auth.Credential{}, err
		}
		if cached == nil {
			return auth.Credential{}, fail(auth.CodeCredentialUnavailable)
		}
		return *cached, nil
	}
	result, err := p.prepare(ctx, cloneRequest(r), "", false)
	if err != nil {
		return auth.Credential{}, err
	}
	if result.Login != nil {
		return auth.Credential{}, fail(auth.CodeInteractionRequired)
	}
	return *result.Credential, nil
}
func (p *Provider) Challenge(ctx context.Context, r auth.Request, c auth.Challenge) (*auth.Credential, error) {
	if err := bounded(ctx); err != nil {
		return nil, err
	}
	if c.StatusCode != 401 {
		value, err := bearerParameter(strings.Join(c.Header.Values("WWW-Authenticate"), ", "), "error")
		required, scopeErr := bearerParameter(strings.Join(c.Header.Values("WWW-Authenticate"), ", "), "scope")
		if c.StatusCode != 403 || err != nil || scopeErr != nil || value != "insufficient_scope" {
			return nil, fail(auth.CodeAccessDenied)
		}
		if required == "" {
			config, _, cached, policyErr := p.cachedBinding(ctx, r)
			if policyErr != nil {
				return nil, policyErr
			}
			if !cached {
				return nil, fail(auth.CodeAccessDenied)
			}
			local, localErr := p.options.SelectClient(ctx, cloneRequest(r), []string{config.Issuer}, config.Resource)
			if localErr != nil {
				return nil, safe(ctx, localErr, auth.CodeUntrustedDestination)
			}
			if len(local.RequiredScopes) == 0 {
				return nil, fail(auth.CodeAccessDenied)
			}
		}
	}
	if c.Attempt != nil {
		owner, ok := c.Attempt.(attempted)
		if !ok || owner.owner != p || owner.identity != requestIdentity(r) {
			return nil, fail(auth.CodeInvalidConfiguration)
		}
		err := error(nil)
		if c.StatusCode == 401 {
			err = p.options.Store.Coordinate(ctx, owner.key, func(ctx context.Context) error {
				current, err := p.options.Store.Load(ctx, owner.key)
				if err != nil {
					return safe(ctx, err, auth.CodeProviderFailed)
				}
				current = cloneRecord(current)
				if current == nil || current.Generation != owner.generation || current.Rejected {
					return nil
				}
				current.Rejected = true
				current.Generation = randomID()
				return p.save(ctx, owner.key, owner.generation, current)
			})
		}
		if err != nil {
			return nil, safe(ctx, err, auth.CodeProviderFailed)
		}
	} else if len(r.Binding) != 0 {
		return nil, fail(auth.CodeInvalidConfiguration)
	}
	result, err := p.prepare(ctx, cloneRequest(r), strings.Join(c.Header.Values("WWW-Authenticate"), ", "), false)
	if err != nil {
		return nil, err
	}
	if result.Login != nil {
		return nil, fail(auth.CodeInteractionRequired)
	}
	return result.Credential, nil
}

// PreemptiveCredential returns nil only for an unknown unbound target.
func (p *Provider) PreemptiveCredential(ctx context.Context, r auth.Request) (*auth.Credential, error) {
	if err := bounded(ctx); err != nil {
		return nil, err
	}
	if _, err := auth.NormalizeTarget(r); err != nil {
		return nil, err
	}
	if len(r.Binding) == 0 {
		stored, err := p.options.Store.Load(ctx, p.bindingKey(r))
		if err != nil {
			return nil, safe(ctx, err, auth.CodeProviderFailed)
		}
		if stored == nil || stored.Binding == nil {
			return nil, nil
		}
	}
	result, err := p.prepare(ctx, cloneRequest(r), "", false)
	if err != nil {
		return nil, err
	}
	return result.Credential, nil
}
