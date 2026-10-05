// Package auth supplies opt-in, independently scoped outbound HTTP credentials.
// It does not acquire OAuth tokens, verify JWTs, configure TLS, or authenticate
// inbound requests. Applications own those operations and the wrapped transport.
package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Operation identifies the independently authorized use of a credential.
type Operation string

const (
	Event  Operation = "event"
	Upload Operation = "upload"
)

var (
	ErrConfig     = errors.New("auth: invalid configuration")
	ErrScope      = errors.New("auth: request outside authorized scope")
	ErrCredential = errors.New("auth: credential unavailable or unauthorized")
	ErrTransport  = errors.New("auth: transport failed")
)

// Scope authorizes exactly one POST endpoint, audience and set of permissions.
// Endpoint must be an absolute HTTPS URL without user information or a fragment.
// Query strings, escaped paths and explicit ports are matched exactly.
type Scope struct {
	Endpoint string
	Audience string
	Scopes   []string
	// Header defaults to Authorization (with a Bearer prefix). Custom credential
	// headers receive the raw token. Routing and framing headers are not allowed.
	Header string
	// AllowLocalHTTP permits HTTP only for literal loopback addresses or localhost.
	// Use it only at an explicitly trusted local process/test boundary.
	AllowLocalHTTP bool
}

// TokenRequest is trusted configuration, not data derived from an event payload.
// Each call gets its own Scopes slice, which the provider may retain or modify.
type TokenRequest struct {
	Operation Operation
	Endpoint  string
	Audience  string
	Scopes    []string
}

// Token is an already acquired credential. The provider must validate its issuer,
// signature/proof and resource permissions; these fields are not JWT verification.
// ExpiresAt must be in the future. Scopes must include every requested permission.
type Token struct {
	Value     string
	Audience  string
	Scopes    []string
	ExpiresAt time.Time
}

// TokenProvider resolves/acquires/refreshes credentials without implicit SDK
// interaction. It must be safe for concurrent calls and honor context cancellation.
// Errors are redacted; only standard context cancellation/deadline errors
// retain their errors.Is identity, never the original provider error.
type TokenProvider func(context.Context, TokenRequest) (Token, error)

type transport struct {
	base      http.RoundTripper
	scope     Scope
	endpoint  *url.URL
	operation Operation
	provider  TokenProvider
}

// NewEventTransport constructs an event-only transport without calling provider.
// A nil base uses http.DefaultTransport. The base must validate receiver TLS and
// must not follow redirects itself. Its configuration is never mutated or closed.
func NewEventTransport(base http.RoundTripper, scope Scope, provider TokenProvider) (http.RoundTripper, error) {
	return newTransport(base, scope, provider, Event)
}

// NewUploadTransport constructs a separate upload-only transport. Event credentials
// are never inferred or reused; explicitly authorize the upload endpoint/provider.
func NewUploadTransport(base http.RoundTripper, scope Scope, provider TokenProvider) (http.RoundTripper, error) {
	return newTransport(base, scope, provider, Upload)
}

func newTransport(base http.RoundTripper, scope Scope, provider TokenProvider, op Operation) (http.RoundTripper, error) {
	u, err := url.Parse(scope.Endpoint)
	if err != nil || u == nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" || strings.Contains(scope.Endpoint, "#") || scope.Audience == "" || provider == nil {
		return nil, ErrConfig
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !scope.AllowLocalHTTP || !(u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())) {
			return nil, ErrConfig
		}
	}
	if u.Hostname() == "" {
		return nil, ErrConfig
	}
	if scope.Header == "" {
		scope.Header = "Authorization"
	}
	scope.Header = http.CanonicalHeaderKey(scope.Header)
	if !validHeader(scope.Header) {
		return nil, ErrConfig
	}
	for _, s := range scope.Scopes {
		if strings.TrimSpace(s) == "" {
			return nil, ErrConfig
		}
	}
	scope.Scopes = append([]string(nil), scope.Scopes...)
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{base: base, scope: scope, endpoint: u, operation: op, provider: provider}, nil
}

func validHeader(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	switch strings.ToLower(s) {
	case "", "host", "connection", "content-length", "content-type", "transfer-encoding", "trailer", "te", "upgrade", "proxy-authorization", "proxy-connection", "accept", "cookie":
		return false
	}
	return true
}

// RoundTrip rejects every redirect request (including same-origin redirects)
// before calling the provider or base. This also protects custom sensitive headers
// copied by http.Client. Use a dedicated client; do not replace its transport in
// CheckRedirect or configure global credentials on the underlying transport.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, ErrScope
	}
	// RoundTripper owns the body even when rejecting a request.
	reject := func(err error) (*http.Response, error) {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	if err := req.Context().Err(); err != nil {
		return reject(redactError(ErrCredential, err))
	}
	u := req.URL
	if u == nil || req.Response != nil || req.Method != http.MethodPost || req.RequestURI != "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawFragment != "" || u.Scheme != t.endpoint.Scheme || u.Host != t.endpoint.Host || u.EscapedPath() != t.endpoint.EscapedPath() || u.RawQuery != t.endpoint.RawQuery || u.ForceQuery != t.endpoint.ForceQuery || (req.Host != "" && req.Host != u.Host) {
		return reject(ErrScope)
	}
	token, err := t.provider(req.Context(), TokenRequest{Operation: t.operation, Endpoint: t.scope.Endpoint, Audience: t.scope.Audience, Scopes: append([]string(nil), t.scope.Scopes...)})
	if err != nil {
		return reject(redactError(ErrCredential, err))
	}
	if err := req.Context().Err(); err != nil {
		return reject(redactError(ErrCredential, err))
	}
	if token.Value == "" || !safeValue(token.Value) || token.Audience != t.scope.Audience || !token.ExpiresAt.After(time.Now()) {
		return reject(ErrCredential)
	}
	for _, required := range t.scope.Scopes {
		found := false
		for _, granted := range token.Scopes {
			if required == granted {
				found = true
				break
			}
		}
		if !found {
			return reject(ErrCredential)
		}
	}
	clone := req.Clone(req.Context())
	// Remove all case variants, including manually inserted noncanonical map keys.
	for key := range clone.Header {
		if strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Proxy-Authorization") || strings.EqualFold(key, t.scope.Header) {
			delete(clone.Header, key)
		}
	}
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}
	value := token.Value
	if t.scope.Header == "Authorization" {
		value = "Bearer " + value
	}
	clone.Header.Set(t.scope.Header, value)
	if err := req.Context().Err(); err != nil {
		return reject(redactError(ErrTransport, err))
	}
	response, err := t.base.RoundTrip(clone)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, redactError(ErrTransport, err)
	}
	return response, nil
}

func safeValue(s string) bool {
	for _, c := range s {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}

// redactError preserves only known safe cancellation identities. In particular,
// context.Cause and the original error chain may contain credential material.
func redactError(kind, err error) error {
	result := kind
	for _, safe := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, safe) {
			result = errors.Join(result, safe)
		}
	}
	return result
}
