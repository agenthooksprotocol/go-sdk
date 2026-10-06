package auth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Request is registration-owned authorization context. Binding is the complete
// selected endpoint binding, including extension fields, never the event binding
// for an upload. Each callback receives a detached copy it may retain or modify.
// An absent binding starts anonymously. Only an actual 401 is handed to an
// explicitly configured provider, whose host trust policy controls discovery.
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

// Challenge describes an actual 401 response. Header is a detached copy. Neither
// the request Authorization header nor the response body is passed to callbacks.
type Challenge struct {
	StatusCode int
	Header     http.Header
	Attempt    any
}

// Provider owns acquisition, trust, consent, refresh, rotation and coordination.
// Calls are synchronous in the delivery context and must honor cancellation.
// Implementations must support concurrent calls. Their lifecycle belongs to the
// host, not Hooks. Challenge may return nil to decline recovery. A replacement
// permits at most one retry, only when the SDK operation explicitly allows it.
// Provider errors are redacted; there is never anonymous fallback.
type Provider interface {
	Credential(context.Context, Request) (Credential, error)
	Challenge(context.Context, Request, Challenge) (*Credential, error)
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
		return Credential{}, ErrCredential
	}
	token := os.Getenv(binding.TokenEnv)
	if !validBearer(token) {
		return Credential{}, ErrCredential
	}
	return Credential{Type: "bearer", Token: token}, nil
}
func (EnvironmentProvider) Challenge(context.Context, Request, Challenge) (*Credential, error) {
	return nil, nil
}

var bearerPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)

func validBearer(token string) bool { return bearerPattern.MatchString(token) }
func copyRequest(r Request) Request { r.Binding = append(json.RawMessage(nil), r.Binding...); return r }

// Do applies registration-aware credentials to one independently authorized POST.
// retrySafe must be false for arbitrary effectful operations (including uploads).
// With true, a 401 may be retried once using the exact GetBody representation and
// request identity. Other statuses and network failures are never retried. A final
// 401 is also reported to the provider, but cannot trigger another retry. Redirects
// are disabled; the caller owns response validation and closing its body.
// The supplied client's transport must not follow redirects itself or inject
// credentials for another scope. No transport is closed or mutated by Do.
func Do(client *http.Client, req *http.Request, request Request, provider Provider, retrySafe bool) (*http.Response, error) {
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
	endpoint, err := url.Parse(request.Destination)
	if err != nil || endpoint.Hostname() == "" || endpoint.Opaque != "" || strings.Contains(request.Destination, "#") {
		return reject(ErrScope)
	}
	if endpoint.Scheme != "https" {
		ip := net.ParseIP(endpoint.Hostname())
		if endpoint.Scheme != "http" || !(endpoint.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())) {
			return reject(ErrScope)
		}
	}
	if err := req.Context().Err(); err != nil {
		return reject(redactError(ErrCredential, err))
	}
	request = copyRequest(request)
	authenticated := len(request.Binding) != 0
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
			return reject(redactError(ErrCredential, err))
		}
	}
	copied := http.Client{}
	if client != nil {
		copied = *client
	}
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	copied.Jar = nil
	current := req.Clone(req.Context())
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
		response, err := copied.Do(current)
		if err != nil {
			if response != nil && response.Body != nil {
				response.Body.Close()
			}
			return nil, redactError(ErrTransport, err)
		}
		if provider == nil || response.StatusCode != http.StatusUnauthorized {
			return response, nil
		}
		next, err := provider.Challenge(req.Context(), copyRequest(request), Challenge{StatusCode: response.StatusCode, Header: response.Header.Clone(), Attempt: credential.Attempt})
		if err != nil {
			response.Body.Close()
			return nil, redactError(ErrCredential, err)
		}
		if err = req.Context().Err(); err != nil {
			response.Body.Close()
			return nil, redactError(ErrCredential, err)
		}
		if next == nil || !retrySafe || request.Purpose == Upload || attempt != 0 || req.GetBody == nil {
			return response, nil
		}
		response.Body.Close()
		body, err := req.GetBody()
		if err != nil {
			return nil, ErrTransport
		}
		current = req.Clone(req.Context())
		current.Body = body
		credential = *next
		authenticated = true
	}
}
