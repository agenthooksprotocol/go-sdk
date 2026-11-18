package oauth

import (
	"context"
	"net/http"
	"sync"
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
	// Registration is an RFC 7591 registration endpoint.
	Registration Purpose = "registration"
)

// ClientConfig is selected by local policy, never by an advertisement alone.
// Scopes are requested scopes. AllowedScopes, the ceiling, defaults to Scopes;
// it governs what the SDK requests and records, not what an issued token can
// do (enforce that in ValidateToken). RequiredScopes are explicit operation
// requirements. ClientSecret is a
// runtime secret, not registration data. Its formatting is always redacted.
//
// A non-empty ClientID is a pre-registered client and always wins. With an
// empty ClientID the SDK selects ClientIDMetadataDocument (PKCE only, when the
// issuer advertises support), then Registration (RFC 7591 at Issuer, when the
// issuer advertises a registration endpoint), else credential_unavailable.
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
	// ClientIDMetadataDocument offers a CIMD client for PKCE when ClientID is empty.
	ClientIDMetadataDocument *MetadataDocument
	// Registration permits dynamic client registration at Issuer when ClientID is empty.
	Registration *RegistrationPolicy

	// source and registered record the selected client source and, for DCR,
	// the registration generation in use. Hosts never set them.
	source, registered string
	// renew marks a client-credentials registration inside its renewal margin.
	renew bool
}

// MetadataDocument is a host-published Client ID Metadata Document. URL is the
// client_id verbatim; the SDK never fetches it. RedirectURIs are the
// document's redirect_uris: the PKCE RedirectURI must be one of them.
type MetadataDocument struct {
	URL          string
	RedirectURIs []string
}

// RegistrationPolicy is host permission to register a client at the exact
// ClientConfig.Issuer and the request metadata to send. ClientName is required.
// Scopes, when set, is the registration scope. InitialAccessTokenRef, when set,
// is resolved through Options.Secrets and sent as a Bearer credential only to
// that issuer's registration endpoint; it is never persisted. Changing any
// field makes a stored registration stale.
type RegistrationPolicy struct {
	ClientName, SoftwareID, SoftwareVersion string
	Scopes                                  []string
	InitialAccessTokenRef                   string
}

// SecretStore is the host secret-storage hook for registered client secrets.
// The SDK stores a secret under a fresh opaque reference, resolves it by
// reference and deletes references it no longer uses. It has no fallback store.
type SecretStore interface {
	Store(ctx context.Context, ref, secret string) error
	Resolve(ctx context.Context, ref string) (string, error)
	Delete(ctx context.Context, ref string) error
}

// PrepareOptions configures an explicit host Prepare. RequiredScopes are
// explicit operation requirements. ForceRegistration discards the current
// dynamic registration (for example after the authorization server deleted a
// PKCE client), clears any failed-registration backoff and registers anew.
type PrepareOptions struct {
	RequiredScopes    []string
	ForceRegistration bool
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
	// Registration and RegistrationFailure live at a registration key, apart
	// from bindings and grants. Neither contains a client secret.
	Registration        *RegistrationRecord
	RegistrationFailure *RegistrationFailure
}

// RegistrationRecord is one stored dynamic client registration. SecretRef is
// the host SecretStore reference of a confidential client's secret. A zero
// SecretExpiresAt means no known expiry. Generation identifies this
// registration, independently of the enclosing Record generation.
type RegistrationRecord struct {
	ClientID, SecretRef, TokenAuthMethod string
	RedirectURIs, GrantTypes             []string
	SecretExpiresAt, RegisteredAt        time.Time
	RequestDigest, Generation            string
}

// RegistrationFailure is the persisted failed-registration backoff marker.
// Until NextAttempt only an explicit host Prepare sends a registration request.
type RegistrationFailure struct {
	RequestDigest         string
	FailedAt, NextAttempt time.Time
	Attempts              int
}

// BindingMetadata is secret-free principal and discovery state at a binding key.
// Source is the selected client source ("preregistered", "cimd" or "dcr");
// RegistrationKey is set for "dcr".
type BindingMetadata struct {
	Config                  ClientConfig
	IssuerMetadata          metadata
	Source, RegistrationKey string
}

// PendingRecord is a stored login. Its lifetime is fixed at creation, so any
// process sharing the Store can complete it before ExpiresAt.
type PendingRecord struct {
	State, Verifier, RedirectURI, AuthorizationURL string
	// Scopes are requested; Ceiling bounds the grant recorded on completion.
	Scopes, Ceiling []string
	ExpiresAt       time.Time
	// ClientID is the client the login completes with; RegistrationGeneration
	// is the dynamic registration it was created under, if any.
	ClientID, RegistrationGeneration string
}

func (Record) String() string               { return "oauth.Record{redacted}" }
func (RegistrationPolicy) String() string   { return "oauth.RegistrationPolicy{redacted}" }
func (RegistrationPolicy) GoString() string { return "oauth.RegistrationPolicy{redacted}" }
func (Record) GoString() string             { return "oauth.Record{redacted}" }
func (PendingRecord) String() string        { return "oauth.PendingRecord{redacted}" }
func (PendingRecord) GoString() string      { return "oauth.PendingRecord{redacted}" }

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
	// Secrets stores dynamically registered client secrets. Without it
	// client-credentials registration is unavailable; PKCE registration is not.
	Secrets SecretStore
	// RegistrationBackoff is the first failed-registration backoff, doubling per
	// attempt; zero means 1 minute. RegistrationBackoffMax caps it and any
	// Retry-After; zero means 1 hour.
	RegistrationBackoff, RegistrationBackoffMax time.Duration
	// RenewalMargin caps the proactive client-secret renewal margin,
	// min(10% of the secret lifetime, RenewalMargin); zero means 1 hour.
	RenewalMargin time.Duration
}

// Provider has no listeners, owned HTTP lifecycle or in-memory login state.
// Pending logins live in the Store. The host owns the Provider. Its only
// background work is a proactive client-secret renewal, which may run for up
// to the commit budget (one minute) after an acquisition, using the host's
// Store, Secrets and HTTP client.
type Provider struct {
	options Options
	client  http.Client
	// prepared counts successful host prepares per endpoint (*atomic.Uint64).
	prepared sync.Map
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
