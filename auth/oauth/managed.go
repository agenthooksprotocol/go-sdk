package oauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var _ auth.Provider = (*Provider)(nil)
var bearerToken = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)

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
	seen := map[string]bool{}
	for _, scope := range c.Scopes {
		if scope == "" || seen[scope] {
			return false
		}
		seen[scope] = true
		for _, b := range []byte(scope) {
			if b < 0x21 || b > 0x7e || b == '"' || b == '\\' {
				return false
			}
		}
	}
	if c.Flow == "client_credentials" {
		return c.ClientSecret != ""
	}
	redirect, err := url.Parse(c.RedirectURI)
	return err == nil && redirect.Hostname() != "" && redirect.User == nil && redirect.Fragment == "" && redirect.RawQuery == "" && (redirect.Scheme == "https" || (redirect.Scheme == "http" && (redirect.Hostname() == "127.0.0.1" || redirect.Hostname() == "[::1]" || redirect.Hostname() == "::1" || redirect.Hostname() == "localhost")))
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
func (p *Provider) key(r auth.Request, c ClientConfig) string {
	encoded, _ := json.Marshal([]any{p.options.Namespace, requestIdentity(r), c.Issuer, c.Resource, c.ClientID, c.Flow, c.TokenAuthMethod, sortedScopes(c.Scopes)})
	return string(encoded)
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
	return p.prepare(ctx, cloneRequest(r), "")
}
func (p *Provider) prepare(ctx context.Context, r auth.Request, challenge string) (Preparation, error) {
	if err := bounded(ctx); err != nil {
		return Preparation{}, err
	}
	p.prune(time.Now())
	config, m, err := p.resolve(ctx, r, challenge)
	if err != nil {
		return Preparation{}, safe(ctx, err, auth.CodeDiscoveryFailed)
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
		record = cloneRecord(record)
		if record != nil {
			if record.Generation == "" || !sameScopes(record.Scopes, config.Scopes) {
				return fail(auth.CodeInvalidConfiguration)
			}
			if record.RefreshUncertain || record.RefreshRejected {
				login, err := p.login(ctx, source, r, key, generation(record), config, m)
				if err != nil {
					return err
				}
				result.Login = login
				return nil
			}
			if !record.Rejected && record.ExpiresAt.After(time.Now().Add(10*time.Second)) && bearerToken.MatchString(record.AccessToken) {
				credential := p.credential(r, key, record)
				result.Credential = &credential
				return nil
			}
			if config.Flow == "authorization_code_pkce" && record.RefreshToken != "" {
				refreshed, err := p.refresh(ctx, key, config, m, record)
				if err != nil {
					return err
				}
				credential := p.credential(r, key, refreshed)
				result.Credential = &credential
				return nil
			}
		}
		if config.Flow == "client_credentials" {
			token, err := p.machine(ctx, config, m)
			if err != nil {
				return err
			}
			next, err := p.record(ctx, config, token)
			if err != nil {
				return err
			}
			if err = p.save(ctx, key, generation(record), next); err != nil {
				return err
			}
			credential := p.credential(r, key, next)
			result.Credential = &credential
			return nil
		}
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
	if token == nil || !strings.EqualFold(token.Type(), "Bearer") || !bearerToken.MatchString(token.AccessToken) || !token.Expiry.After(time.Now()) {
		return nil, fail(auth.CodeCredentialUnavailable)
	}
	scopes := append([]string(nil), c.Scopes...)
	if extra := token.Extra("scope"); extra != nil {
		value, ok := extra.(string)
		if !ok {
			return nil, fail(auth.CodeAccessDenied)
		}
		scopes = strings.Fields(value)
		if !sameScopes(scopes, c.Scopes) {
			return nil, fail(auth.CodeAccessDenied)
		}
	}
	if err := p.options.ValidateToken(ctx, c, token); err != nil {
		return nil, safe(ctx, err, auth.CodeAccessDenied)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &Record{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ExpiresAt: token.Expiry, Scopes: scopes, Generation: randomID()}, nil
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
		return nil, grantError(ctx, err)
	}
	return token, nil
}
func grantError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var rejected *oauth2.RetrieveError
	if errors.As(err, &rejected) && (rejected.ErrorCode == "invalid_grant" || rejected.ErrorCode == "access_denied") {
		return fail(auth.CodeRefreshRejected)
	}
	return fail(auth.CodeProviderFailed)
}
func knownTemporary(err error) bool {
	var result *oauth2.RetrieveError
	return errors.As(err, &result) && (result.ErrorCode == "temporarily_unavailable" || result.ErrorCode == "server_error")
}
func (p *Provider) refresh(ctx context.Context, key string, c ClientConfig, m metadata, previous *Record) (*Record, error) {
	// Persist an ambiguity marker before a possibly rotating external exchange.
	// A cancelled request or failed commit must never permit reuse of an old
	// refresh token with an unknown outcome. Known OAuth temporary errors restore
	// the retained generation; definitive invalid_grant requires reauthorization.
	marker := cloneRecord(previous)
	marker.Generation = randomID()
	marker.RefreshUncertain = true
	if err := p.save(ctx, key, previous.Generation, marker); err != nil {
		return nil, err
	}
	conf := oauthConfig(c, m)
	token, err := conf.TokenSource(context.WithValue(ctx, oauth2.HTTPClient, p.tokenClient(ctx, c, m)), &oauth2.Token{RefreshToken: previous.RefreshToken, Expiry: time.Now().Add(-time.Minute)}).Token()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		restored := cloneRecord(previous)
		restored.Generation = randomID()
		var rejected *oauth2.RetrieveError
		definitive := errors.As(err, &rejected) && rejected.ErrorCode == "invalid_grant"
		if definitive || knownTemporary(err) {
			restored.RefreshRejected = definitive
			if saveErr := p.save(ctx, key, marker.Generation, restored); saveErr != nil {
				return nil, saveErr
			}
		}
		return nil, grantError(ctx, err)
	}
	next, err := p.record(ctx, c, token)
	if err != nil {
		return nil, err
	}
	if next.RefreshToken == "" {
		next.RefreshToken = previous.RefreshToken
	}
	if err = p.save(ctx, key, marker.Generation, next); err != nil {
		return nil, err
	}
	return next, nil
}

func (p *Provider) login(ctx, source context.Context, r auth.Request, key, expected string, c ClientConfig, m metadata) (*PendingLogin, error) {
	deadline, _ := source.Deadline()
	now := time.Now()
	if limit := now.Add(10 * time.Minute); deadline.After(limit) {
		deadline = limit
	}
	p.mu.Lock()
	for k, login := range p.pending {
		if login.used.Load() || !login.deadline.After(now) {
			delete(p.pending, k)
		}
	}
	existing := p.pending[key]
	if existing != nil && existing.expected != expected {
		delete(p.pending, key)
		existing = nil
	}
	full := len(p.pending) >= 128
	p.mu.Unlock()
	if existing != nil && existing.source.Err() != nil {
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
	if !p.consume(login) {
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
	if err != nil || len(query["state"]) != 1 || subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(login.state)) != 1 || len(query["code"]) != 1 || query.Get("code") == "" || query.Get("error") != "" {
		return auth.Credential{}, fail(auth.CodeAccessDenied)
	}
	if issuer := query["iss"]; len(issuer) > 1 || (len(issuer) == 1 && issuer[0] != login.config.Issuer) || (login.metadata.ResponseIssuer && len(issuer) != 1) {
		return auth.Credential{}, fail(auth.CodeAccessDenied)
	}
	var credential auth.Credential
	err = p.options.Store.Coordinate(ctx, login.key, func(ctx context.Context) error {
		current, err := p.options.Store.Load(ctx, login.key)
		if err != nil {
			return safe(ctx, err, auth.CodeProviderFailed)
		}
		current = cloneRecord(current)
		if generation(current) != login.expected {
			if current != nil && !current.Rejected && !current.RefreshUncertain && !current.RefreshRejected && current.ExpiresAt.After(time.Now().Add(10*time.Second)) && sameScopes(current.Scopes, login.config.Scopes) && bearerToken.MatchString(current.AccessToken) {
				credential = p.credential(login.request, login.key, current)
				return nil
			}
			return fail(auth.CodeInteractionRequired)
		}
		token, err := oauthConfig(login.config, login.metadata).Exchange(context.WithValue(ctx, oauth2.HTTPClient, p.tokenClient(ctx, login.config, login.metadata)), query.Get("code"), oauth2.VerifierOption(login.verifier), oauth2.SetAuthURLParam("resource", login.config.Resource))
		if err != nil {
			return grantError(ctx, err)
		}
		next, err := p.record(ctx, login.config, token)
		if err != nil {
			return err
		}
		if err = p.save(ctx, login.key, generation(current), next); err != nil {
			return err
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
		return auth.Credential{}, nil
	}
	result, err := p.Prepare(ctx, r)
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
		return nil, fail(auth.CodeAccessDenied)
	}
	if c.Attempt != nil {
		owner, ok := c.Attempt.(attempted)
		if !ok || owner.owner != p || owner.identity != requestIdentity(r) {
			return nil, fail(auth.CodeInvalidConfiguration)
		}
		err := p.options.Store.Coordinate(ctx, owner.key, func(ctx context.Context) error {
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
		if err != nil {
			return nil, safe(ctx, err, auth.CodeProviderFailed)
		}
	} else if len(r.Binding) != 0 {
		return nil, fail(auth.CodeInvalidConfiguration)
	}
	result, err := p.prepare(ctx, cloneRequest(r), strings.Join(c.Header.Values("WWW-Authenticate"), ", "))
	if err != nil {
		return nil, err
	}
	if result.Login != nil {
		return nil, fail(auth.CodeInteractionRequired)
	}
	return result.Credential, nil
}
