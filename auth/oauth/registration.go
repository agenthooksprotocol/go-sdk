package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"github.com/agenthooksprotocol/go-sdk/internal/authutil"
)

const (
	pkceFlow            = "authorization_code_pkce"
	sourcePreregistered = "preregistered"
	sourceCIMD          = "cimd"
	sourceDCR           = "dcr"
)

// identity is the grant key's client identity: the configured client source,
// never an issued client_id.
func identity(c ClientConfig) string {
	switch c.source {
	case sourceCIMD:
		return "cimd:" + c.ClientID
	case sourceDCR:
		return "dcr"
	}
	return "preregistered:" + c.ClientID
}

// registrationKey locates the client-credentials registration for an issuer.
func (p *Provider) registrationKey(c ClientConfig) string {
	return frame("ahp.oauth.registration:", p.options.Namespace, c.Issuer)
}

// requestDigest identifies the host registration policy a record was made with.
func requestDigest(policy *RegistrationPolicy) string {
	sum := sha256.Sum256([]byte(frame("ahp.oauth.registration-request:", policy.ClientName, policy.SoftwareID, policy.SoftwareVersion, strings.Join(merge(policy.Scopes), " "), policy.InitialAccessTokenRef)))
	return hex.EncodeToString(sum[:])
}

// validDocumentURL: https, a path, no userinfo, fragment or dot segments.
func validDocumentURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !discoveryHTTPS(raw) || len(u.EscapedPath()) < 2 {
		return false
	}
	for _, segment := range strings.Split(u.EscapedPath(), "/") {
		if decoded, err := url.PathUnescape(segment); err != nil || decoded == "." || decoded == ".." {
			return false
		}
	}
	return true
}

// loopback reports a literal loopback IP host; a name such as localhost is not.
func loopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validRedirect accepts https, or http only to a literal loopback IP (RFC 8252).
func validRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !authutil.ValidURL(raw, true) || u.RawQuery != "" || u.ForceQuery {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && loopback(u.Hostname()))
}

// redirectMatches compares a login's redirect with a declared CIMD redirect
// URI: exactly, or for a loopback http redirect without userinfo, without the
// port, as authorization servers do (RFC 8252 section 7.3).
func redirectMatches(declared, redirect string) bool {
	if declared == redirect {
		return true
	}
	d, err := url.Parse(declared)
	r, err2 := url.Parse(redirect)
	if err != nil || err2 != nil || r.Scheme != "http" || d.Scheme != "http" || r.User != nil || d.User != nil || !loopback(r.Hostname()) {
		return false
	}
	return d.Hostname() == r.Hostname() && d.EscapedPath() == r.EscapedPath() && d.RawQuery == r.RawQuery && d.ForceQuery == r.ForceQuery && d.Fragment == r.Fragment
}

// documentAccepts checks a selected CIMD client's URL and the login redirect.
func documentAccepts(document *MetadataDocument, redirect string) bool {
	if document == nil || !validDocumentURL(document.URL) {
		return false
	}
	for _, declared := range document.RedirectURIs {
		if redirectMatches(declared, redirect) {
			return true
		}
	}
	return false
}

// recorded keeps a binding's recorded CIMD/DCR selection while current host
// policy still permits it, whatever the issuer metadata now advertises.
func recorded(c ClientConfig, b *BindingMetadata) ClientConfig {
	if c.ClientID != "" {
		c.source = sourcePreregistered
		return c
	}
	if b == nil || b.Config.Issuer != c.Issuer || b.Config.Flow != c.Flow {
		return c
	}
	switch {
	case b.Source == sourceCIMD && c.Flow == pkceFlow && c.ClientIDMetadataDocument != nil && c.ClientIDMetadataDocument.URL == b.Config.ClientID:
		c.ClientID, c.ClientSecret, c.TokenAuthMethod, c.source = b.Config.ClientID, "", "none", sourceCIMD
	case b.Source == sourceDCR && c.Registration != nil:
		c.ClientSecret, c.source = "", sourceDCR
	}
	return c
}

// choose selects the client source for discovered configuration without network:
// pre-registered, a recorded selection, CIMD, then permitted DCR.
func (p *Provider) choose(ctx context.Context, r auth.Request, c ClientConfig, m metadata) (ClientConfig, error) {
	stored, err := p.options.Store.Load(ctx, p.bindingKey(r))
	if err != nil {
		return c, safe(ctx, err, auth.CodeProviderFailed)
	}
	var b *BindingMetadata
	if stored != nil {
		b = stored.Binding
	}
	if c = recorded(c, b); c.source != "" {
		return c, nil
	}
	document := c.ClientIDMetadataDocument
	if c.Flow == pkceFlow && document != nil && bool(m.CIMDSupported) {
		// Without a redirect yet, login checks it.
		if !validDocumentURL(document.URL) || (c.RedirectURI != "" && !documentAccepts(document, c.RedirectURI)) {
			return c, fail(auth.CodeInvalidConfiguration)
		}
		c.ClientID, c.ClientSecret, c.TokenAuthMethod, c.source = document.URL, "", "none", sourceCIMD
		return c, nil
	}
	if c.Registration == nil || m.RegistrationEndpoint == "" {
		return c, fail(auth.CodeCredentialUnavailable)
	}
	if c.Flow != pkceFlow && (p.options.Secrets == nil || secretMethod(m) == "") {
		return c, fail(auth.CodeCredentialUnavailable)
	}
	if !discoveryHTTPS(m.RegistrationEndpoint) {
		return c, fail(auth.CodeUntrustedDestination)
	}
	c.ClientSecret, c.source = "", sourceDCR
	if c.Flow == pkceFlow {
		c.TokenAuthMethod = "none"
	}
	return c, nil
}

// secretMethod is the confidential method to register: basic, else post.
func secretMethod(m metadata) string {
	methods := m.TokenAuthMethods
	if methods == nil {
		methods = []string{"client_secret_basic"}
	}
	for _, method := range []string{"client_secret_basic", "client_secret_post"} {
		if contains(methods, method) {
			return method
		}
	}
	return ""
}

// registered resolves the client-credentials registration under the
// registration-key lock: it reuses a usable record, or registers once. Only a
// host Prepare (interactive) replaces a usable record made under other
// registration settings; it and the one re-registration after invalid_client
// (bypass) ignore the backoff.
func (p *Provider) registered(ctx context.Context, c ClientConfig, m metadata, interactive, bypass bool) (ClientConfig, error) {
	key, digest := p.registrationKey(c), requestDigest(c.Registration)
	err := p.options.Store.Coordinate(ctx, key, func(ctx context.Context) error {
		record, err := p.options.Store.Load(ctx, key)
		if err != nil {
			return safe(ctx, err, auth.CodeProviderFailed)
		}
		if record == nil {
			record = &Record{}
		}
		if reg := record.Registration; reg != nil && (reg.SecretExpiresAt.IsZero() || time.Now().Before(reg.SecretExpiresAt)) && (!interactive || reg.RequestDigest == digest) {
			if secret, ok := p.secret(ctx, reg); ok {
				c = use(c, reg, secret)
				c.failing = record.RegistrationFailure != nil
				return nil
			}
		}
		if failure := record.RegistrationFailure; !interactive && !bypass && failure != nil && time.Now().Before(failure.NextAttempt) {
			return fail(failure.Code)
		}
		c, err = p.register(ctx, key, record, c, m, digest)
		c.failing = c.registered != "" && record.RegistrationFailure != nil
		return err
	})
	if err != nil {
		return c, safe(ctx, err, auth.CodeProviderFailed)
	}
	return c, nil
}

func use(c ClientConfig, reg *RegistrationRecord, secret string) ClientConfig {
	c.ClientID, c.ClientSecret, c.TokenAuthMethod, c.registered = reg.ClientID, secret, reg.TokenAuthMethod, reg.Generation
	return c
}

// secret resolves a registration's client secret through the host hook.
func (p *Provider) secret(ctx context.Context, reg *RegistrationRecord) (string, bool) {
	if p.options.Secrets == nil || reg.SecretRef == "" {
		return "", false
	}
	secret, err := p.options.Secrets.Resolve(ctx, reg.SecretRef)
	return secret, err == nil && secret != ""
}

// replace compare-and-sets a registration-key record, then deletes the secret
// reference of a registration it removed.
func (p *Provider) replace(ctx context.Context, key string, old, next *Record) error {
	if err := p.save(ctx, key, generation(old), next); err != nil {
		return err
	}
	if reg := old.Registration; reg != nil && reg.SecretRef != "" && (next.Registration == nil || next.Registration.SecretRef != reg.SecretRef) && p.options.Secrets != nil {
		p.options.Secrets.Delete(ctx, reg.SecretRef)
	}
	return nil
}

// drop compare-and-deletes the client-credentials registration generation a
// token endpoint rejected with invalid_client, which counts as a failed
// registration for the backoff.
func (p *Provider) drop(ctx context.Context, c ClientConfig) error {
	key := p.registrationKey(c)
	return p.options.Store.Coordinate(ctx, key, func(ctx context.Context) error {
		record, err := p.options.Store.Load(ctx, key)
		if err != nil {
			return safe(ctx, err, auth.CodeProviderFailed)
		}
		if record == nil {
			record = &Record{}
		}
		next := cloneRecord(record)
		if reg := record.Registration; reg != nil && reg.Generation == c.registered {
			next.Registration = nil
		}
		next.RegistrationFailure, next.Generation = p.failure(record, auth.CodeCredentialUnavailable, 0), randomID()
		return p.replace(ctx, key, record, next)
	})
}

// recovered clears the failure count after a token request with registration
// generation c.registered succeeded.
func (p *Provider) recovered(ctx context.Context, c ClientConfig) error {
	key := p.registrationKey(c)
	return p.options.Store.Coordinate(ctx, key, func(ctx context.Context) error {
		record, err := p.options.Store.Load(ctx, key)
		if err != nil {
			return safe(ctx, err, auth.CodeProviderFailed)
		}
		if record == nil || record.RegistrationFailure == nil || record.Registration == nil || record.Registration.Generation != c.registered {
			return nil
		}
		next := cloneRecord(record)
		next.RegistrationFailure, next.Generation = nil, randomID()
		return p.save(ctx, key, record.Generation, next)
	})
}

// failure is the next backoff: exponential from the attempt count, or a later
// Retry-After, capped at the host maximum.
func (p *Provider) failure(record *Record, code auth.Code, retryAfter time.Duration) *RegistrationFailure {
	attempts := 1
	if previous := record.RegistrationFailure; previous != nil {
		attempts = previous.Attempts + 1
	}
	wait := p.options.RegistrationBackoff
	for i := 1; i < attempts && wait < p.options.RegistrationBackoffMax; i++ {
		wait *= 2
	}
	wait = min(max(wait, retryAfter), p.options.RegistrationBackoffMax)
	return &RegistrationFailure{Code: code, Attempts: attempts, NextAttempt: time.Now().Add(wait)}
}

// registration builds an RFC 7591 request for c and resolves its initial
// access token. A PKCE request registers the login's exact redirect.
func (p *Provider) registration(ctx context.Context, c ClientConfig, m metadata) (map[string]any, string, error) {
	if m.RegistrationEndpoint == "" || (c.Flow != pkceFlow && (p.options.Secrets == nil || secretMethod(m) == "")) {
		// A recorded DCR selection skips choose: recheck feasibility.
		return nil, "", fail(auth.CodeCredentialUnavailable)
	}
	if err := p.check(ctx, m.RegistrationEndpoint, Registration); err != nil {
		return nil, "", err
	}
	policy := c.Registration
	initial := ""
	if policy.InitialAccessTokenRef != "" {
		if p.options.Secrets == nil {
			return nil, "", fail(auth.CodeCredentialUnavailable)
		}
		token, err := p.options.Secrets.Resolve(ctx, policy.InitialAccessTokenRef)
		if err != nil || !authutil.ValidBearer(token) {
			return nil, "", safe(ctx, err, auth.CodeCredentialUnavailable)
		}
		initial = token
	}
	request := map[string]any{"client_name": policy.ClientName}
	method := "none"
	if c.Flow == pkceFlow {
		request["redirect_uris"] = []string{c.RedirectURI}
		if u, _ := url.Parse(c.RedirectURI); u.Scheme == "http" {
			request["application_type"] = "native"
		}
		request["grant_types"] = []string{"authorization_code", "refresh_token"}
		request["response_types"] = []string{"code"}
	} else {
		method = secretMethod(m)
		request["grant_types"] = []string{"client_credentials"}
	}
	request["token_endpoint_auth_method"] = method
	for name, value := range map[string]string{"software_id": policy.SoftwareID, "software_version": policy.SoftwareVersion, "scope": strings.Join(merge(policy.Scopes), " ")} {
		if value != "" {
			request[name] = value
		}
	}
	return request, initial, nil
}

// registerLogin registers a public PKCE client for one login and persists
// nothing: the login holds the issued client_id until completion stores it
// with the tokens.
func (p *Provider) registerLogin(ctx context.Context, c ClientConfig, m metadata) (string, error) {
	request, initial, err := p.registration(ctx, c, m)
	if err != nil {
		return "", err
	}
	reg, _, _, err := p.send(ctx, m.RegistrationEndpoint, initial, request, c.Flow)
	if err != nil {
		return "", err
	}
	return reg.ClientID, nil
}

// register sends one client-credentials registration and persists an
// accepted one by compare-and-set; a failure records the backoff.
func (p *Provider) register(ctx context.Context, key string, record *Record, c ClientConfig, m metadata, digest string) (ClientConfig, error) {
	request, initial, err := p.registration(ctx, c, m)
	if err != nil {
		return c, err
	}
	// Once written, a registration may have been processed: receive it, store
	// its secret and persist it detached from caller cancellation, so a cancel
	// never orphans a client; the caller still sees the cancellation.
	persist, cancel := sending(ctx)
	if cancel == nil {
		return c, ctx.Err()
	}
	defer cancel()
	reg, secret, retryAfter, err := p.send(persist, m.RegistrationEndpoint, initial, request, c.Flow)
	if err == nil {
		reg.SecretRef = randomID()
		if storeErr := p.options.Secrets.Store(persist, reg.SecretRef, secret); storeErr != nil {
			err = safe(persist, storeErr, auth.CodeProviderFailed)
		}
	}
	if err != nil {
		if persist.Err() == nil {
			failed := cloneRecord(record)
			code := auth.CodeProviderFailed
			if classified := auth.Classify(err); classified != nil {
				code = classified.Code
			}
			failed.RegistrationFailure, failed.Generation = p.failure(record, code, retryAfter), randomID()
			p.save(persist, key, generation(record), failed)
		}
		return c, err
	}
	reg.RequestDigest, reg.Generation = digest, randomID()
	next := cloneRecord(record)
	// The failure count survives until a token request with this client succeeds.
	next.Registration, next.Generation = reg, randomID()
	if err := p.replace(persist, key, record, next); err != nil {
		// Lost the compare-and-set: delete our fresh secret and use the winner's.
		p.options.Secrets.Delete(persist, reg.SecretRef)
		if winner, loadErr := p.options.Store.Load(persist, key); loadErr == nil && winner != nil && winner.Registration != nil {
			if secret, ok := p.secret(persist, winner.Registration); ok {
				return use(c, winner.Registration, secret), nil
			}
		}
		return c, err
	}
	if ctx.Err() != nil {
		return c, errors.Join(fail(auth.CodeProviderFailed), ctx.Err())
	}
	return use(c, reg, secret), nil
}

// send performs the registration request and validates its response.
func (p *Provider) send(ctx context.Context, endpoint, initial string, body map[string]any, flow string) (*RegistrationRecord, string, time.Duration, error) {
	encoded, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, "", 0, fail(auth.CodeProviderFailed)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if initial != "" {
		req.Header.Set("Authorization", "Bearer "+initial)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, "", 0, ctx.Err()
		}
		return nil, "", 0, fail(auth.CodeProviderFailed)
	}
	defer resp.Body.Close()
	retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
	status := resp.StatusCode
	switch {
	case status >= 300 && status < 400:
		return nil, "", retryAfter, fail(auth.CodeUntrustedDestination)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return nil, "", retryAfter, fail(auth.CodeCredentialUnavailable)
	case status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500 || status < 200:
		return nil, "", retryAfter, fail(auth.CodeProviderFailed)
	case status >= 400:
		return nil, "", retryAfter, fail(auth.CodeInvalidConfiguration)
	case status != http.StatusOK && status != http.StatusCreated:
		return nil, "", retryAfter, fail(auth.CodeProviderFailed)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, discoveryLimit+1))
	var fields map[string]json.RawMessage
	if err != nil || len(raw) > discoveryLimit || json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, "", retryAfter, fail(auth.CodeProviderFailed)
	}
	reg, secret, ok := accept(fields, body, flow)
	if !ok {
		return nil, "", retryAfter, fail(auth.CodeInvalidConfiguration)
	}
	return reg, secret, 0, nil
}

// accept validates a 200/201 registration object against the request.
// Management fields, echoed scope and unknown members are ignored, and so are
// a public PKCE client's secret and its expiry.
func accept(fields map[string]json.RawMessage, request map[string]any, flow string) (*RegistrationRecord, string, bool) {
	field := func(name string, value any) bool {
		raw, present := fields[name]
		return !present || json.Unmarshal(raw, value) == nil
	}
	var clientID, method, secret string
	var redirects, grants []string
	if json.Unmarshal(fields["client_id"], &clientID) != nil || clientID == "" || !field("redirect_uris", &redirects) || !field("grant_types", &grants) || !field("token_endpoint_auth_method", &method) {
		return nil, "", false
	}
	requestedMethod := request["token_endpoint_auth_method"].(string)
	wantGrant := "client_credentials"
	if flow == pkceFlow {
		wantGrant = "authorization_code"
	}
	if requested, _ := request["redirect_uris"].([]string); len(requested) == 1 && fields["redirect_uris"] != nil && !contains(redirects, requested[0]) {
		return nil, "", false
	}
	if _, ok := fields["grant_types"]; ok && !contains(grants, wantGrant) {
		return nil, "", false
	}
	if _, ok := fields["token_endpoint_auth_method"]; ok && method != requestedMethod {
		return nil, "", false
	}
	reg := &RegistrationRecord{ClientID: clientID, TokenAuthMethod: requestedMethod}
	if flow == pkceFlow {
		return reg, "", true
	}
	if json.Unmarshal(fields["client_secret"], &secret) != nil || secret == "" {
		return nil, "", false
	}
	if raw, ok := fields["client_secret_expires_at"]; ok {
		seconds, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil || seconds < 0 {
			return nil, "", false
		}
		if seconds != 0 {
			reg.SecretExpiresAt = time.Unix(seconds, 0)
			if !reg.SecretExpiresAt.After(time.Now()) {
				return nil, "", false
			}
		}
	}
	return reg, secret, true
}

// parseRetryAfter reads delay-seconds or an HTTP date.
func parseRetryAfter(value string) time.Duration {
	if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && seconds > 0 {
		return time.Duration(min(seconds, int64(24*time.Hour/time.Second))) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil {
		return max(time.Until(at), 0)
	}
	return 0
}
