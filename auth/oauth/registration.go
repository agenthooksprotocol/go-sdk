package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
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

func (p *Provider) registrationKey(c ClientConfig) string {
	redirect := ""
	if c.Flow == pkceFlow {
		redirect = c.RedirectURI
	}
	return frame("ahp.oauth.registration:", p.options.Namespace, c.Issuer, c.Flow, redirect)
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
		c.ClientID, c.ClientSecret, c.source = b.Config.ClientID, "", sourceDCR
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
		if !validDocumentURL(document.URL) || !contains(document.RedirectURIs, c.RedirectURI) {
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

func blocked(record *Record, digest string) bool {
	failure := record.RegistrationFailure
	return failure != nil && failure.RequestDigest == digest && time.Now().Before(failure.NextAttempt)
}

// renewalDue reports a known secret expiry inside the proactive renewal
// margin, min(10% of its lifetime since local registration, RenewalMargin).
func (p *Provider) renewalDue(reg *RegistrationRecord) bool {
	if reg.SecretExpiresAt.IsZero() {
		return false
	}
	margin := min(reg.SecretExpiresAt.Sub(reg.RegisteredAt)/10, p.options.RenewalMargin)
	return !time.Now().Before(reg.SecretExpiresAt.Add(-margin))
}

// registered resolves the dynamic registration for a DCR acquisition under
// the registration-key lock: it reuses a usable record, or registers when
// permitted. Only interactive (host Prepare) registers a PKCE client or
// bypasses the failed marker.
func (p *Provider) registered(ctx context.Context, c ClientConfig, m metadata, interactive, force bool) (ClientConfig, error) {
	key, digest := p.registrationKey(c), requestDigest(c.Registration)
	err := p.options.Store.Coordinate(ctx, key, func(ctx context.Context) error {
		record, err := p.options.Store.Load(ctx, key)
		if err != nil {
			return safe(ctx, err, auth.CodeProviderFailed)
		}
		if record == nil {
			record = &Record{}
		}
		if reg := record.Registration; reg != nil && (force || reg.RequestDigest != digest) {
			// Policy changed (or the host forces it): compare-and-delete.
			next := cloneRecord(record)
			next.Registration, next.Generation = nil, randomID()
			if force {
				next.RegistrationFailure = nil
			}
			if err := p.replace(ctx, key, record, next); err != nil {
				return err
			}
			record = next
		}
		if reg := record.Registration; reg != nil && (reg.SecretExpiresAt.IsZero() || time.Now().Before(reg.SecretExpiresAt)) {
			if secret, ok := p.secret(ctx, c, reg); ok {
				current := use(c, reg, secret)
				c = current
				if c.Flow != pkceFlow && p.renewalDue(reg) && (interactive || !blocked(record, digest)) {
					// A failed proactive renewal keeps the current registration.
					if renewed, err := p.register(ctx, key, record, current, m, digest); err == nil {
						c = renewed
					}
				}
				return nil
			}
		}
		if c.Flow == pkceFlow && !interactive {
			return fail(auth.CodeInteractionRequired)
		}
		if !interactive && blocked(record, digest) {
			return fail(auth.CodeCredentialUnavailable)
		}
		c, err = p.register(ctx, key, record, c, m, digest)
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

// secret resolves a confidential registration's secret; public clients have none.
func (p *Provider) secret(ctx context.Context, c ClientConfig, reg *RegistrationRecord) (string, bool) {
	if c.Flow == pkceFlow {
		return "", reg.SecretRef == ""
	}
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

// drop compare-and-deletes one rejected registration generation and, when
// mark is set, records a failed attempt.
func (p *Provider) drop(ctx context.Context, c ClientConfig, mark bool) error {
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
		} else if !mark {
			return nil
		}
		if mark {
			next.RegistrationFailure = p.failure(record, requestDigest(c.Registration), 0)
		}
		next.Generation = randomID()
		return p.replace(ctx, key, record, next)
	})
}

// failure is the next failed marker: exponential backoff from the attempt
// count, or a later Retry-After, capped at the host maximum.
func (p *Provider) failure(record *Record, digest string, retryAfter time.Duration) *RegistrationFailure {
	attempts := 1
	if previous := record.RegistrationFailure; previous != nil && previous.RequestDigest == digest {
		attempts = previous.Attempts + 1
	}
	wait := p.options.RegistrationBackoff
	for i := 1; i < attempts && wait < p.options.RegistrationBackoffMax; i++ {
		wait *= 2
	}
	wait = min(max(wait, retryAfter), p.options.RegistrationBackoffMax)
	now := time.Now()
	return &RegistrationFailure{RequestDigest: digest, FailedAt: now, NextAttempt: now.Add(wait), Attempts: attempts}
}

// register sends one RFC 7591 request and persists an accepted registration
// by compare-and-set; every failed outcome updates the failed marker.
func (p *Provider) register(ctx context.Context, key string, record *Record, c ClientConfig, m metadata, digest string) (ClientConfig, error) {
	if m.RegistrationEndpoint == "" {
		return c, fail(auth.CodeCredentialUnavailable)
	}
	if err := p.check(ctx, m.RegistrationEndpoint, Registration); err != nil {
		return c, err
	}
	policy := c.Registration
	initial := ""
	if policy.InitialAccessTokenRef != "" {
		if p.options.Secrets == nil {
			return c, fail(auth.CodeCredentialUnavailable)
		}
		token, err := p.options.Secrets.Resolve(ctx, policy.InitialAccessTokenRef)
		if err != nil || !authutil.ValidBearer(token) {
			return c, safe(ctx, err, auth.CodeCredentialUnavailable)
		}
		initial = token
	}
	request := map[string]any{"client_name": policy.ClientName}
	method := "none"
	if c.Flow == pkceFlow {
		request["redirect_uris"] = []string{c.RedirectURI}
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
	reg, secret, retryAfter, err := p.send(ctx, m.RegistrationEndpoint, initial, request, c.Flow)
	if err == nil && secret != "" {
		reg.SecretRef = randomID()
		if storeErr := p.options.Secrets.Store(ctx, reg.SecretRef, secret); storeErr != nil {
			err = safe(ctx, storeErr, auth.CodeProviderFailed)
		}
	}
	persist, cancel := persisting(ctx)
	defer cancel()
	if err != nil {
		if ctx.Err() == nil {
			failed := cloneRecord(record)
			failed.RegistrationFailure, failed.Generation = p.failure(record, digest, retryAfter), randomID()
			p.save(persist, key, generation(record), failed)
		}
		return c, err
	}
	reg.RequestDigest, reg.Generation, reg.RegisteredAt = digest, randomID(), time.Now()
	next := cloneRecord(record)
	next.Registration, next.RegistrationFailure, next.Generation = reg, nil, randomID()
	if err := p.replace(persist, key, record, next); err != nil {
		// Lost the compare-and-set: delete our fresh secret and use the winner's.
		if reg.SecretRef != "" {
			p.options.Secrets.Delete(persist, reg.SecretRef)
		}
		if winner, loadErr := p.options.Store.Load(persist, key); loadErr == nil && winner != nil && winner.Registration != nil && winner.Registration.RequestDigest == digest {
			if secret, ok := p.secret(persist, c, winner.Registration); ok {
				return use(c, winner.Registration, secret), nil
			}
		}
		return c, err
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
// Management fields, echoed scope and unknown members are ignored.
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
	requestedRedirects, _ := request["redirect_uris"].([]string)
	requestedMethod := request["token_endpoint_auth_method"].(string)
	wantGrant := "client_credentials"
	if flow == pkceFlow {
		wantGrant = "authorization_code"
	}
	if _, ok := fields["redirect_uris"]; ok && !slices.Equal(merge(redirects), merge(requestedRedirects)) {
		return nil, "", false
	}
	if _, ok := fields["grant_types"]; ok && !contains(grants, wantGrant) {
		return nil, "", false
	}
	if _, ok := fields["token_endpoint_auth_method"]; ok && method != requestedMethod {
		return nil, "", false
	}
	if raw, ok := fields["client_secret"]; flow == pkceFlow && ok {
		return nil, "", false
	} else if flow != pkceFlow && (json.Unmarshal(raw, &secret) != nil || secret == "") {
		return nil, "", false
	}
	reg := &RegistrationRecord{ClientID: clientID, TokenAuthMethod: requestedMethod, RedirectURIs: requestedRedirects, GrantTypes: grants}
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
