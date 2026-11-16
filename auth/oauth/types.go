package oauth

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

// Purpose identifies an outbound OAuth operation for host network policy.
type Purpose string

const (
	Metadata      Purpose = "metadata"
	Authorization Purpose = "authorization"
	TokenEndpoint Purpose = "token"
)

// ClientConfig is selected by local policy, never by an advertisement alone.
// Scopes are the locally permitted AND requested scopes. ClientSecret is a
// runtime secret, not registration data. Its formatting is always redacted.
type ClientConfig struct {
	Issuer, Resource, ClientID, Flow string
	Scopes                           []string
	ClientSecret, RedirectURI        string
	// TokenAuthMethod is optional: discovery selects a supported method when empty.
	TokenAuthMethod string
}

func (ClientConfig) String() string   { return "oauth.ClientConfig{redacted}" }
func (ClientConfig) GoString() string { return "oauth.ClientConfig{redacted}" }

// Record is an opaque-to-the-SDK host-persisted credential generation. Hosts
// must return detached values and atomically persist complete copies. A refresh
// with an unknown outcome retains the old secrets but is not retried blindly.
type Record struct {
	AccessToken, RefreshToken, Generation       string
	ExpiresAt                                   time.Time
	Scopes                                      []string
	Rejected, RefreshRejected, RefreshUncertain bool
}

func (Record) String() string   { return "oauth.Record{redacted}" }
func (Record) GoString() string { return "oauth.Record{redacted}" }

// Store owns persistence and cross-instance/process coordination. Coordinate
// must serialize the complete callback for a key, honor cancellation while
// waiting, and release ownership on error or panic. Load returns a detached
// snapshot. CompareAndSwap is atomic; empty generation means absent. No store
// callback may recursively enter this provider for the same key. Hosts own
// durable record migrations and secure storage; the SDK creates neither.
type Store interface {
	Load(context.Context, string) (*Record, error)
	CompareAndSwap(context.Context, string, string, *Record) (bool, error)
	Coordinate(context.Context, string, func(context.Context) error) error
}

type Options struct {
	Namespace string
	Store     Store
	// HTTPClient must enforce DNS/connect policy through its transport, including
	// protection against rebinding. It must not inject ambient credentials. The
	// provider disables redirects and cookies without mutating the supplied client.
	HTTPClient *http.Client
	// CheckDestination must apply local trust to EVERY metadata, authorization
	// and token URL. URL inspection alone cannot replace the transport DNS policy.
	CheckDestination func(context.Context, string, Purpose) error
	// SelectClient sees untrusted issuers/resource; it must choose a trusted local
	// identity and allowlisted scopes. Explicit presets constrain the result too.
	SelectClient func(context.Context, auth.Request, []string, string) (ClientConfig, error)
	// ValidateToken must verify token validity and resource/audience under local
	// policy (including JWT verification where applicable). Never log its input.
	ValidateToken func(context.Context, ClientConfig, *oauth2.Token) error
}

// Provider has no workers, listeners or owned HTTP lifecycle. The host owns it.
// mu guards only pending-map membership: entries are immutable except the
// atomic consumed flag. No host callbacks, network calls or stores run under mu.
// Writers: Prepare inserts/prunes, Complete/Cancel remove their exact entry.
// Cancellation never resurrects a consumed entry; expired entries are pruned
// during preparation. Bounded entries hold at most 128 active login secrets.
type Provider struct {
	options Options
	client  http.Client
	mu      sync.Mutex
	pending map[string]*PendingLogin
}

// PendingLogin is a single-use, bounded consent operation. Only the explicit
// AuthorizationURL accessor reveals the URL; formatting never reveals secrets.
// It is tied to this provider, original target, redirect, state and deadline.
// Copying this handle shares state; no secret or atomic is copied by value.
type PendingLogin struct{ *pendingState }
type pendingState struct {
	owner                                                      *Provider
	key, expected, identity, authorizationURL, state, verifier string
	config                                                     ClientConfig
	metadata                                                   metadata
	request                                                    auth.Request
	deadline                                                   time.Time
	source                                                     context.Context
	used                                                       atomic.Bool
}

func (PendingLogin) String() string              { return "oauth.PendingLogin{redacted}" }
func (PendingLogin) GoString() string            { return "oauth.PendingLogin{redacted}" }
func (p *PendingLogin) AuthorizationURL() string { return p.authorizationURL }
func (p *PendingLogin) Deadline() time.Time      { return p.deadline }

// Preparation contains exactly one of Credential and Login on success.
type Preparation struct {
	Credential *auth.Credential
	Login      *PendingLogin
}

func (Preparation) String() string   { return "oauth.Preparation{redacted}" }
func (Preparation) GoString() string { return "oauth.Preparation{redacted}" }
