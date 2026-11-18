package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/agenthooksprotocol/go-sdk/internal/authutil"
)

// Request is registration-owned authorization context. Binding is the complete
// selected endpoint binding, including extension fields, never the event binding
// for an upload. Each callback receives a detached copy it may retain or modify.
// An absent binding uses optional cached credentials, otherwise starts anonymously.
// Only an actual challenge is handed to an explicitly configured provider, whose
// host trust policy controls discovery.
type Request struct {
	Binding     json.RawMessage
	BackendID   string
	Destination string
	Purpose     Operation
}

// Credential is an already acquired endpoint credential, not a token-endpoint
// client secret. Attempt is an opaque host-owned identity passed back unchanged
// on rejection, so the host can distinguish stale from current credentials.
// The SDK never logs Token or Attempt. Providers must not mutate Attempt while
// it is in use. Type must be "bearer".
type Credential struct {
	Type    string
	Token   string
	Attempt any
}

// Challenge describes an actual 401 or Bearer insufficient_scope 403 response.
// Header is a detached copy. Neither the request Authorization header nor the
// response body is passed to callbacks.
type Challenge struct {
	StatusCode int
	Header     http.Header
	Attempt    any
}

// Provider owns acquisition, trust, consent, refresh, rotation and coordination.
// Calls are synchronous in the delivery context and must honor cancellation.
// Implementations must support concurrent calls. Their lifecycle belongs to the
// host, not Hooks. Challenge must stop serving the rejected credential and may
// return nil to decline recovery. A replacement permits at most one replay, only
// for a replayable request (see Do). Provider errors are redacted to an
// allowlisted *Error code, otherwise provider_failed; there is never anonymous
// fallback for a bound request.
type Provider interface {
	Credential(context.Context, Request) (Credential, error)
	Challenge(context.Context, Request, Challenge) (*Credential, error)
}

// PreemptiveProvider optionally supplies previously authorized credentials for an
// absent binding, so a known destination gets its stored token on the first
// attempt. A nil credential is a cache miss and the request is sent anonymously.
// Lookup must not initiate discovery, acquisition, or interactive login. A
// non-nil success must contain a valid bearer, just like Provider.Credential.
// Implementations must honor cancellation and support concurrent calls.
type PreemptiveProvider interface {
	PreemptiveCredential(context.Context, Request) (*Credential, error)
}

// PreparationTracker is optionally implemented by a Provider whose host can
// explicitly prepare an endpoint, such as oauth.Provider. client.Hooks uses it
// to re-attempt server-driven configuration for a backend skipped while its
// event endpoint was unavailable as soon as the host has prepared it, instead
// of waiting for backoff. Wrapping providers should forward it.
type PreparationTracker interface {
	// Preparations returns a process-local count of successful host prepares
	// for request's backend, purpose and destination; the binding is ignored.
	// Destinations should be compared by normalized URL (case-insensitive scheme
	// and host, default port and empty path ignored), not raw string.
	// It must be cheap, must not block on I/O, and must be safe for concurrent use.
	Preparations(Request) uint64
}

// EnvironmentProvider is the non-interactive default for bearer + tokenEnv.
// References and OAuth require an explicit host provider.
type EnvironmentProvider struct{}

func (EnvironmentProvider) Credential(ctx context.Context, request Request) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, redactError(ErrCredential, err)
	}
	var binding struct {
		Type     string
		TokenEnv string
		TokenRef string
	}
	if json.Unmarshal(request.Binding, &binding) != nil || binding.Type != "bearer" || binding.TokenEnv == "" || binding.TokenRef != "" {
		return Credential{}, &Error{Code: CodeCredentialUnavailable}
	}
	token, err := ResolveSecret(ctx, binding.TokenEnv, "", nil)
	if err != nil || !validBearer(token) {
		return Credential{}, &Error{Code: CodeCredentialUnavailable}
	}
	return Credential{Type: "bearer", Token: token}, nil
}
func (EnvironmentProvider) Challenge(context.Context, Request, Challenge) (*Credential, error) {
	return nil, nil
}

func validBearer(token string) bool { return authutil.ValidBearer(token) }
func copyRequest(r Request) Request { r.Binding = append(json.RawMessage(nil), r.Binding...); return r }

// Do applies registration-aware credentials to one independently authorized POST.
// After a 401 or Bearer insufficient_scope 403 the provider handles the
// challenge; Do then replays at most once, with the same buffered body (and so
// the same JSON-RPC id), only for an event POST whose body is a hooks/intercept,
// hooks/configuration or hooks/capabilities request. Notifications and uploads
// are never replayed. Other statuses and network failures are never retried. A
// final challenge is also reported to the provider, but cannot trigger another
// replay. Redirects are disabled; the caller owns response validation and
// closing its body. The supplied client's transport must not follow redirects
// itself or inject credentials for another scope. No transport is closed or
// mutated by Do.
func Do(client *http.Client, req *http.Request, request Request, provider Provider) (*http.Response, error) {
	return DoWithHeaders(client, req, request, provider, nil)
}

// replayable reports whether a buffered event body is a JSON-RPC request whose
// method permits challenged replay.
func replayable(body []byte) bool {
	var message struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if json.Unmarshal(body, &message) != nil || len(message.ID) == 0 || string(message.ID) == "null" {
		return false
	}
	switch message.Method {
	case "hooks/intercept", "hooks/configuration", "hooks/capabilities":
		return true
	}
	return false
}

// ApplyHeaders overlays configured headers case-insensitively after defaults/auth.
// Host and Content-Length use net/http's dedicated request fields.
func ApplyHeaders(req *http.Request, headers http.Header) {
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	for name, values := range headers {
		for existing := range req.Header {
			if strings.EqualFold(existing, name) {
				delete(req.Header, existing)
			}
		}
		req.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		if strings.EqualFold(name, "Host") && len(values) > 0 {
			req.Host = values[0]
		}
		if strings.EqualFold(name, "Content-Length") && len(values) > 0 {
			if length, err := strconv.ParseInt(values[0], 10, 64); err == nil {
				req.ContentLength = length
			}
		}
	}
}

// DoWithHeaders applies registration headers last. Explicit Authorization skips
// credential acquisition, discovery, and all challenge/retry handling. Existing
// redirect behavior is unchanged. Headers never reach provider-owned requests.
func DoWithHeaders(client *http.Client, req *http.Request, request Request, provider Provider, headers http.Header) (*http.Response, error) {
	if req == nil {
		return nil, ErrScope
	}
	reject := func(err error) (*http.Response, error) {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	if req.URL == nil || req.Method != http.MethodPost || req.URL.String() != request.Destination || req.URL.User != nil || req.URL.Fragment != "" || req.Response != nil || req.RequestURI != "" || (req.Host != "" && req.Host != req.URL.Host) || (request.Purpose != Event && request.Purpose != Upload) {
		return reject(ErrScope)
	}
	// Permit HTTP only at local endpoints, consistent with event transport policy.
	if !authutil.ValidURL(request.Destination, true) {
		return reject(ErrScope)
	}
	if err := req.Context().Err(); err != nil {
		return reject(redactError(ErrCredential, err))
	}
	request = copyRequest(request)

	explicitAuthorization := false
	for name := range headers {
		if strings.EqualFold(name, "Authorization") {
			explicitAuthorization = true
		}
	}
	if explicitAuthorization {
		provider = nil
	}
	authenticated := len(request.Binding) != 0 && !explicitAuthorization
	var credential Credential
	if authenticated {
		var binding struct {
			Type string
			Flow string
		}
		if json.Unmarshal(request.Binding, &binding) != nil || (binding.Type != "bearer" && binding.Type != "oauth") || (binding.Type == "oauth" && binding.Flow != "authorization_code_pkce" && binding.Flow != "client_credentials") {
			return reject(ErrConfig)
		}
		if provider == nil {
			provider = EnvironmentProvider{}
		}
		var err error
		credential, err = provider.Credential(req.Context(), copyRequest(request))
		if err != nil {
			return reject(redactProviderError(err))
		}
	} else if lookup, ok := provider.(PreemptiveProvider); ok {
		cached, err := lookup.PreemptiveCredential(req.Context(), copyRequest(request))
		if err != nil {
			return reject(redactProviderError(err))
		}
		if cached != nil {
			credential, authenticated = *cached, true
		}
	}
	// Only a replayable event request is buffered; its exact bytes are resent.
	var body []byte
	if request.Purpose == Event && req.Body != nil && req.Body != http.NoBody {
		var err error
		body, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, ErrTransport
		}
	}
	replay := provider != nil && replayable(body)
	copied := http.Client{}
	if client != nil {
		copied = *client
	}
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	copied.Jar = nil
	current := req.Clone(req.Context())
	if body != nil {
		current.Body = io.NopCloser(bytes.NewReader(body))
	}
	for attempt := 0; ; attempt++ {
		if err := req.Context().Err(); err != nil {
			if current.Body != nil {
				current.Body.Close()
			}
			return nil, redactError(ErrCredential, err)
		}
		// Credential selection belongs to this endpoint binding, never to headers
		// inherited from a previously prepared or separately scoped request.
		for key := range current.Header {
			if strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Proxy-Authorization") {
				delete(current.Header, key)
			}
		}
		if authenticated {
			if credential.Type != "bearer" || !validBearer(credential.Token) {
				if current.Body != nil {
					current.Body.Close()
				}
				return nil, ErrCredential
			}
			if current.Header == nil {
				current.Header = make(http.Header)
			}
			current.Header.Set("Authorization", "Bearer "+credential.Token)
		}
		ApplyHeaders(current, headers)
		response, err := copied.Do(current)
		if err != nil {
			if response != nil && response.Body != nil {
				response.Body.Close()
			}
			return nil, redactError(ErrTransport, err)
		}
		if provider == nil || !(response.StatusCode == http.StatusUnauthorized || insufficientScope(response)) {
			return response, nil
		}
		next, err := provider.Challenge(req.Context(), copyRequest(request), Challenge{StatusCode: response.StatusCode, Header: response.Header.Clone(), Attempt: credential.Attempt})
		if err != nil {
			response.Body.Close()
			return nil, redactProviderError(err)
		}
		if err = req.Context().Err(); err != nil {
			response.Body.Close()
			return nil, redactError(ErrCredential, err)
		}
		if next == nil || !replay || attempt != 0 {
			return response, nil
		}
		response.Body.Close()
		current = req.Clone(req.Context())
		current.Body = io.NopCloser(bytes.NewReader(body))
		credential = *next
		authenticated = true
	}
}
