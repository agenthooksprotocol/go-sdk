package oauth

import (
	"context"
	"net/http"
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
// Scopes are requested scopes. AllowedScopes, the ceiling, defaults to Scopes;
// it governs what the SDK requests and records, not what an issued token can
// do (enforce that in ValidateToken). RequiredScopes are explicit operation
// requirements. ClientSecret is a
// runtime secret, not registration data. Its formatting is always redacted.
type ClientConfig struct {
	Issuer, Resource, ClientID, Flow string
	Scopes                           []string
	// A nil AllowedScopes defaults to Scopes; an empty non-nil ceiling permits none.
	AllowedScopes, RequiredScopes []string
	// GrantPartition opts independently approved bindings into shared consent.
	// Empty keeps each destination/backend/purpose binding isolated.
	GrantPartition            string
	ClientSecret, RedirectURI string
	// TokenAuthMethod is optional: discovery selects a supported method when empty.
	TokenAuthMethod string
}

func (ClientConfig) String() string   { return "oauth.ClientConfig{redacted}" }
func (ClientConfig) GoString() string { return "oauth.ClientConfig{redacted}" }

// Record is an opaque-to-the-SDK host-persisted credential generation. Hosts
// must return detached values and atomically persist complete copies.
type Record struct {
	AccessToken, RefreshToken, Generation string
	// Zero ExpiresAt means unknown expiry, not an expired credential.
	ExpiresAt time.Time
	// Scopes is the recorded grant: response scopes within the acquisition
	// ceiling, or within the previous grant on refresh. Each caller's current
	// ceiling filters it at use.
	Scopes  []string
	Binding *BindingMetadata
	// Pending is the explicit host login awaiting its callback, if any.
	Pending *PendingRecord
}

// BindingMetadata is secret-free principal and discovery state at a binding key.
type BindingMetadata struct {
	Config         ClientConfig
	IssuerMetadata metadata
}

// PendingRecord is a stored login. Its lifetime is fixed at creation, so any
// process sharing the Store can complete it before ExpiresAt.
type PendingRecord struct {
	State, Verifier, RedirectURI, AuthorizationURL string
	// Scopes are requested; Ceiling bounds the grant recorded on completion.
	Scopes, Ceiling []string
	ExpiresAt       time.Time
}

func (Record) String() string          { return "oauth.Record{redacted}" }
func (Record) GoString() string        { return "oauth.Record{redacted}" }
func (PendingRecord) String() string   { return "oauth.PendingRecord{redacted}" }
func (PendingRecord) GoString() string { return "oauth.PendingRecord{redacted}" }

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
	// LoginLifetime fixes how long a pending login stays completable. Zero means
	// the default and maximum of 10 minutes.
	LoginLifetime time.Duration
}

// Provider has no workers, listeners, owned HTTP lifecycle or in-memory login
// state. Pending logins live in the Store. The host owns the Provider.
type Provider struct {
	options Options
	client  http.Client
}

// PendingLogin describes a stored login. Only the explicit AuthorizationURL
// accessor reveals the URL; formatting never reveals it.
type PendingLogin struct {
	authorizationURL string
	deadline         time.Time
}

func (PendingLogin) String() string   { return "oauth.PendingLogin{redacted}" }
func (PendingLogin) GoString() string { return "oauth.PendingLogin{redacted}" }

// AuthorizationURL returns the URL the host opens for consent.
func (p *PendingLogin) AuthorizationURL() string {
	if p == nil {
		return ""
	}
	return p.authorizationURL
}

// Deadline is the fixed expiry of the stored login.
func (p *PendingLogin) Deadline() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.deadline
}

// Preparation contains exactly one of Credential and Login on success.
type Preparation struct {
	Credential *auth.Credential
	Login      *PendingLogin
}

func (Preparation) String() string   { return "oauth.Preparation{redacted}" }
func (Preparation) GoString() string { return "oauth.Preparation{redacted}" }
