# Set up managed OAuth for hook backends

Use `auth/oauth` when a host needs authorization-code PKCE or client-credentials
support without implementing the OAuth protocol itself. The adapter uses
`golang.org/x/oauth2` for grant requests and PKCE. It implements AHP's protected
resource and authorization-server discovery, resource-bound refresh, and the
`auth.Provider` interface. Importing it does not start network activity.

## Supply host policy and storage

Construct a provider with explicit host-owned dependencies:

```go
managed, err := oauth.New(oauth.Options{
    Namespace:        accountID,
    Store:            credentialStore,
    HTTPClient:       policyHTTPClient,
    CheckDestination: checkDestination,
    SelectClient:     selectTrustedClient,
    ValidateToken:    validateToken,
})
if err != nil {
    return err
}
provider := auth.Route(auth.Routes{
    Bearer: auth.NewBearerProvider(auth.BearerOptions{
        ResolveSecret: resolveSecret,
    }),
    OAuth: managed,
})
// Supply provider through client.Options.AuthProvider.
```

The host functions have these contracts:

- **`HTTPClient`** has an explicit transport enforcing TLS, DNS/connect and egress
  policy, including protection against DNS rebinding. It must not inject ambient
  credentials or internally follow redirects. The adapter copies the client,
  disables redirects and cookies, and never closes it.
- **`CheckDestination(ctx, url, purpose)`** permits each metadata, authorization
  and token URL before use. Purposes are `Metadata`, `Authorization` and
  `TokenEndpoint`. URL checks alone cannot replace connection-level DNS policy.
  Do not log URLs: an authorization URL contains state and PKCE parameters.
- **`SelectClient(ctx, request, issuers, resource)`** selects a trusted local
  issuer, client and supported flow from untrusted advertisements. Independently
  approve the request destination and event/upload purpose on every call.
  `Scopes` are requested, never required; `AllowedScopes` is the local ceiling
  (defaults to `Scopes` when nil). A requested scope outside the ceiling is
  `invalid_configuration`; it is never dropped silently. The ceiling governs
  what the adapter requests and records, not what an issued token can do;
  enforce that in `ValidateToken`. `RequiredScopes` (H) names scopes this
  operation requires. Return `ClientConfig`, including the registered redirect URI
  for PKCE and a runtime client secret for client credentials. Resolve any
  `clientSecretRef` through host secrets here. Explicit registration presets
  constrain issuer, resource, client, flow and scopes; they cannot be replaced.
  A preset's `scopes` are requested scopes, never required: a grant that lacks
  them still serves an operation whose required set is covered.
  `TokenAuthMethod` may select `none`, `client_secret_basic` or
  `client_secret_post`; discovery verifies issuer support. When omitted, the
  adapter selects a supported method without automatic credential-style probing.
- **`ValidateToken(ctx, client, token)`** verifies validity and resource/audience
  under local policy, including cryptographic JWT validation where appropriate.
  An absent expiry remains usable until rejection; an explicit expired lifetime
  does not; `expires_in` must be a positive integer (or digit string). An
  acquisition (consent or client credentials) requests any previously granted
  scopes plus the requested and required scopes, and records the response scopes
  within the previous grant plus the acquisition ceiling (the pending login's,
  or the client-credentials caller's); extra scopes are ignored. A response
  `scope` that is absent, `null` or blank (only SP, HTAB, CR, LF; including a
  form-encoded `scope=`) is omitted and inherits the requested set, or the
  previous grant on refresh. Any other value must be a strict RFC 6749 list
  (single-SP separators) or the response fails as `provider_failed`. A refresh records the response within the previous grant, so it
  never broadens it, and a narrowed ceiling never shrinks it: each caller's
  ceiling filters the grant only at use; broader requirements need fresh consent or a new
  client-credentials grant. A PKCE grant is refreshed only when its recorded
  scopes cover the required set; a refresh or client-credentials grant that
  then does not cover it fails the operation with `access_denied` carrying
  that set, after the grant is saved. A PKCE grant that never covered it needs
  consent: `interaction_required` carrying the set (`Prepare` creates a
  login). Client-credentials grants are always reissued, never refreshed. The host retains responsibility for trusting opaque issuer tokens.
- **`Store`** loads detached `Record` snapshots, atomically compares generations,
  and coordinates the complete acquisition/refresh callback for a key across
  host instances/processes. Its methods must honor context cancellation and
  release coordination on errors or panics. Do not reenter the same provider/key
  from a store callback. Secure persistence and durable schema migrations belong
  to the host; no filesystem format or default store is installed. Persist the
  complete `Record`, including its optional `ClientID`, `Binding`, `Pending`, `Registration` and `RegistrationFailure` fields, and
  preserve zero `ExpiresAt` as unknown expiry. Binding records contain no client
  secret. Coordination prevents refresh storms across processes; the generation
  compare-and-swap fences a writer whose coordination lease lapsed.
  The length-framed binding/grant keys replace earlier experimental JSON keys;
  old records are not automatically migrated and can require fresh consent.

All network, policy and store work uses the supplied context. `Prepare`,
`Complete` and `Challenge` require a context with an enclosing deadline; they
never extend it. The host must
ensure its callbacks honor cancellation. No browser, callback listener, worker,
credential database or automatically refreshing background source is created.

## Present and complete a PKCE login

Prepare authorization before starting a session when the host can present UI:

```go
ctx, cancel := context.WithTimeout(parent, time.Minute)
defer cancel()

prepared, err := managed.Prepare(ctx, request)
if err != nil {
    return err // inspect auth.Error.Code; do not print raw host errors
}
if prepared.Login != nil {
    presentAuthorizationURL(prepared.Login.AuthorizationURL())
    // This Provider completes it; with Options.PersistLogins, any Provider
    // sharing the Store may complete it (for example from a pasted URL).
    callbackURL, err := receiveCallback(callbackCtx)
    if err != nil {
        return managed.Cancel(ctx, request, prepared.Login)
    }
    _, err = managed.Complete(ctx, request, callbackURL)
    return err
}
// prepared.Credential is ready; normal delivery acquires through auth.Provider.
```

A pending login has a lifetime fixed at creation (`Options.LoginLifetime`,
default and maximum ten minutes), independent of the creating context. As in
MCP clients, it belongs to the Provider that created it, which receives its
callback and completes it by `state`. Set `Options.PersistLogins` to keep
pending logins in the `Store` instead, so another process sharing it can
complete one; the PKCE verifier then lives only in that pending record.

Each `Prepare` that needs consent creates a new login, requesting any
previously granted scopes and its requested and required scopes; its ceiling bounds the grant recorded on
completion. The login stores its required set (host `RequiredScopes` at prepare
time, plus the explicit and challenged scopes it was prepared with):
`Complete` succeeds only when the grant, within the current ceiling (a nil
`AllowedScopes` is the current `Scopes`), covers it, and otherwise fails with `access_denied` carrying that set. The grant (and any
rotated refresh token) is still saved and the login consumed. Several logins may be pending for one grant,
up to `Options.MaxPendingLogins` (default 5, per Provider or per Store when
persisted); a new one beyond the cap cancels the oldest, and expired logins are
deleted. Completion validates state, the login's exact redirect (including a
loopback port) and the optional/advertised issuer response before claiming the
login; an invalid callback does not consume it. Each completion replaces the
grant's client and tokens, so the newest completed login wins. A login ends
once: completion (including denial), `Cancel` (which ends exactly that login,
matched by its state, never another caller's login on a shared grant), the cap
or expiry; a callback for an ended login fails with `interaction_required`.
`Cancel` never erases stored credentials. With `PersistLogins`, a host
`Prepare` also deletes the grant's expired pending logins and their verifiers.

`Complete` runs in order. It first finds the login named by the callback's
`state` from stored records, before any host callback: none (absent, unknown,
expired or ended) is `interaction_required`, however malformed. An invalid
callback for a live login (redirect, `iss`, fragment, userinfo, not exactly one
of `code` or `error`, a duplicated parameter, an unparseable URL) is
`access_denied`. Current host policy then runs: a `SelectClient`, store or
issuer-metadata failure keeps its code, and a recorded client source that
policy no longer permits is `invalid_configuration`. Both leave the login
pending. The login is then claimed atomically. After the claim: consent denial is `access_denied`;
token-endpoint `invalid_grant` is `interaction_required`; `invalid_client` is
`credential_unavailable` for a pre-registered client, `invalid_configuration`
for a CIMD client and `interaction_required` for a DCR client (the next
`Prepare` registers again); any other token-endpoint failure or invalid token
response is `provider_failed`. These carry no scopes.

Every `Complete` error carries an `*auth.Error` whose `LoginEnded` reports
whether the pending login named by the callback's `state` no longer exists
after the call: `true` when it was consumed, had expired or was unknown,
`false` when it is still pending (for example after a stray or invalid callback
rejected before the claim, or a host failure) or its state could not be
determined (an uncertain claim is re-read once on a short budget). Keep waiting
for another callback only while it is `false`. `LoginEnded` is a `*bool`, set
(and emitted in JSON) only on `Complete` errors; it is nil on every other error
and never copied from a host error. `errors.Is` and `errors.As` work as for
any SDK error.

To bind a new loopback port for each login, as MCP clients do, pass it with
`PrepareWith(ctx, request, oauth.PrepareOptions{RedirectURI: redirect})`;
`SelectClient` then need not return a `RedirectURI`. A redirect is required
only when a login is created; lookup, refresh and `Complete` never need one.
Redirects are HTTPS or HTTP to a literal loopback IP (`127.0.0.1`, `[::1]`),
optionally with a query, which a callback must repeat exactly (parameters the
authorization server adds, such as `session_state`, are allowed);
`localhost` is `invalid_configuration` (RFC 8252 section 8.3), checked before
client selection, registration or any login.

A dispatch that needs consent returns `interaction_required`; it never launches
interactive UI, waits for a human or creates a login. Client credentials
completes through `Prepare` without UI and requires explicit issuer grant support.

## Select or register a client

`SelectClient` returning a `ClientID` selects a pre-registered client; it always
wins. With an empty `ClientID` the adapter selects, per exact issuer and flow:

1. `ClientIDMetadataDocument` (PKCE only) when the issuer metadata has
   `client_id_metadata_document_supported: true`. Its `URL` (https, with a
   path, no userinfo, fragment or dot segments) is the `client_id`, and the
   login's redirect must match one of its `RedirectURIs`, where a loopback
   `http` redirect is compared without its port (RFC 8252 section 7.3);
   otherwise `invalid_configuration`. The adapter never fetches the document.
   A CIMD client is public; its `invalid_client` is `invalid_configuration`.
2. `Registration` (RFC 7591) at `Issuer` when the metadata advertises
   `registration_endpoint`. `CheckDestination` sees it with purpose
   `Registration`; redirects are never followed. Client credentials also need
   `Options.Secrets` and `client_secret_basic` or `client_secret_post` support.
3. Otherwise `credential_unavailable`.

The grant is keyed by this configured client source (`preregistered:<id>`,
`cimd:<url>` or `dcr`), never by an issued `client_id`. A recorded CIMD or DCR
selection stays in use while host policy still permits it, whatever the
metadata later advertises; a new pre-registered client, or a removed or changed
CIMD URL or DCR permission, selects a new client and grant.

**PKCE registration is part of the login**, as in MCP clients. Only an explicit
`Prepare` registers, inside the `Prepare` that creates a login, with that
login's exact redirect and `application_type: "native"` for a loopback
redirect; delivery paths return `interaction_required`. There is no
registration record: the login holds the issued `client_id`, and completion
stores it with the tokens in the grant record, which refresh then uses. Any
`client_secret` in the response is ignored. An `invalid_client` at completion
ends only that login (`interaction_required`; the stored grant is kept). At
refresh it returns `interaction_required` and deletes the grant only if it
still holds the presented client and refresh token; the next `Prepare`
registers again.

**Client-credentials registrations** are stored at their own `Store` key
(namespace and issuer), shared by every client-credentials grant with that
key, and registered once across processes under `Coordinate`. The secret goes
only to `Options.Secrets` (`Store`, `Resolve`, `Delete` by reference); records
hold its reference, and replaced or deleted registrations have their reference
deleted. A registration is re-registered when its secret expired or cannot be
resolved, and after a token-endpoint `invalid_client` (at most once per
operation; a repeated `invalid_client` is `credential_unavailable`). The
first `invalid_client` just re-registers; the repeated one counts as a failed
registration for the backoff, and the count survives a new registration until a
token request with a registered client succeeds, so a server that rejects every
registered client is retried ever more rarely. A usable
registration is never replaced automatically, even after a `RegistrationPolicy`
change; pass `PrepareOptions{ForceRegistration: true}` to replace it. After
a failed registration, no registration request is sent until a backoff passes
(`RegistrationBackoff`, default 1 minute doubling, and any `Retry-After`, capped
at `RegistrationBackoffMax`, default 1 hour), shared through the `Store`;
meanwhile operations return the last failure's code, so a retryable failure is
`provider_failed`. `Prepare` bypasses the backoff. `InitialAccessTokenRef` is
resolved through `Options.Secrets`, sent only to that issuer's registration
endpoint and never stored.

## Discovery, isolation and failure recovery

An unknown unbound HTTP endpoint starts anonymously. A previously authorized
unbound endpoint sends its cached bearer up front, including for notifications
and uploads, even after provider recreation or during a metadata outage. That
lookup never runs protected-resource discovery or creates a login; it refreshes
or re-acquires an expired grant (within a 30-second budget when the context has
no deadline) using the issuer
metadata persisted with the binding (fetching only the stored issuer's metadata
if none is persisted). Only a store miss or host policy refusal sends
anonymously; a known binding whose grant cannot be renewed, including one that
needs consent, fails the operation. If the token endpoint provably did not
process a renewal (DNS, connect or TLS-handshake failure, or HTTP 404/410), the
lookup refetches the stored issuer's metadata once, persists it if the issuer is
unchanged and retries once; a changed issuer or failed refetch returns
`discovery_failed`. `Prepare` and challenge handling repair it: when they need an
exchange or login they rerun full discovery (honouring a challenge's
`resource_metadata`), while a usable cached token is served without network. Ambiguous failures (timeouts,
resets, 5xx, redirects, non-OAuth bodies) return `provider_failed` with no
refetch or immediate retry, so a spent refresh token is never replayed. A 401 retires the rejected token
before any other decision, even before its expiry, so it is renewed rather than resent.
A challenge on a notification or upload is not replayed but still runs challenge
handling, so the next operation sends a credential. Local policy still runs before using a stored
grant. Explicit presets skip protected
resource discovery and validate the selected issuer metadata instead. On a real 401 the
adapter honors the Bearer challenge's `resource_metadata`, otherwise tries the
endpoint-path and origin-root RFC 9728 locations in order. It validates the exact RFC 9728 retrieval-source resource identifier in addition
to resource coverage, and discovers the exact selected issuer using OAuth/OIDC well-known
locations. `scopes_supported` never grants consent.

Tokens and refresh requests carry the validated RFC 8707 resource. Default grant
partitions isolate every namespace, backend, exact destination and event/upload
purpose. A nonempty `ClientConfig.GrantPartition` explicitly shares consent only
between independently approved bindings with the same issuer, resource, client
and flow. Changing the allowed ceiling, a secret, the token-endpoint
authentication method, a metadata capability or the granted scope set does not
change grant identity; the grant is re-intersected with the current ceiling at
use. Uploads never inherit event authorization. A 401 drops the rejected
token, so it is never resent (a stale 401 leaves a newer token alone); a 403
`insufficient_scope` keeps it. The provider never replays a delivery itself; `auth.Do` replays only intercept,
configuration and capabilities requests, once. Explicit Authorization headers bypass the entire auth path.

An operation's required set R is the host `RequiredScopes` (H), the explicit
scopes passed to `Prepare` (E) and the validated scopes of a Bearer 403
`insufficient_scope` challenge (Ch). Only R is mandatory. If R contains a scope
outside the ceiling, the operation fails with `access_denied` carrying R; the
decision is local, before any issuer metadata, token or registration request,
on every path (`Prepare`, `Credential`, `Challenge` and `PreemptiveCredential`,
fresh or cached binding). Every scoped `access_denied` and
`interaction_required` carries the full R, deduplicated and byte-sorted. Errors
from host callbacks (`SelectClient`, `ValidateToken`, `CheckDestination`,
stores) never carry scopes.

Every entry point (`Credential` and delivery, `Prepare`/`PrepareWith`
including `ForceRegistration`, `Challenge`, `PreemptiveCredential`) runs one
decision procedure, and one classification step is the only place that sets an
error's code and scopes. A 401 first retires the rejected generation if it is
still current, whatever the outcome (a newer generation is left alone). Its
Bearer `scope` is not a requirement: the scopes within the ceiling are
requested only by a client-credentials acquisition in the same operation, never
stored, and a 401 never yields `access_denied` because of its `scope`.

A Bearer 403 with `error="insufficient_scope"` creates a step-up requirement only
for the challenged operation; it is never stored. PKCE reports
`interaction_required` carrying R; pass it to `Prepare(ctx, request,
err.Scopes...)` to request consent. Client credentials reissue
noninteractively. If the stored grant already records R within the ceiling
and its generation is the one rejected (or no token was sent), the server and
the record disagree: the challenge fails with `access_denied` carrying R,
without replaying the token, interaction or a login. If a newer generation
already covers R, it is served. If a scope
challenge omits `scope`, H ∪ E is the requirement when non-empty; otherwise it
returns `access_denied` with no scopes. A malformed challenge `scope` (empty, a tab,
repeated, leading or trailing spaces, an invalid character, a duplicated
parameter), two Bearer challenges or an unparseable challenge fails closed with `access_denied`, no
scopes and recovery `none`. Other 403 responses are not auth retries. Dispatch
never creates pending consent.

Transient OAuth errors, 5xx, non-OAuth responses and transport failures preserve
refresh material and return retry advice. Definitive PKCE `invalid_grant` drops
the stored tokens (unless a newer record replaced them) and becomes
`refresh_rejected`; call `Prepare` for consent. An invalid token response is
never dispatched and returns `provider_failed`: an initial exchange persists
nothing, a refresh keeps only a valid rotated refresh token. No in-flight marker
is stored, so a subsequent attempt may retry the retained refresh token. An external rotating
issuer can then reject it; the SDK cannot roll back an external exchange or
promise recovery after a failed local commit. Client credentials never require
human login. Hosts may impose stricter explicit policy.

Use `errors.As(err, *auth.Error)` for safe classifications and `errors.Is` for
native cancellation/deadlines. `(*auth.Error).Recovery()` returns `configure`,
`login`, `retry` or `none` for host decisions. Diagnostics discard raw upstream response bodies,
callback URLs, credentials and host error chains. Login/config/record formatting
is redacted; explicitly accessing secret fields still requires host care.

## Verify an integration

```sh
go test ./auth/oauth
go test -race ./auth/...
```

The behavior suite uses verified TLS issuers and host-store boundaries. It covers
both flows, state/issuer/redirect validation, metadata trust, resource-bound
refresh, concurrent acquisition, independent destinations/uploads/namespaces,
stale rejections, transient and definitive failures, cancellation and failed
commits. The original low-level `auth.Provider` remains available for hosts with
existing OAuth infrastructure.
