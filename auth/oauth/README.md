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
  `Scopes` requests consent; `AllowedScopes` is the local ceiling (defaults to
  `Scopes` when nil). The ceiling governs what the adapter requests and records,
  not what an issued token can do; enforce that in `ValidateToken`.
  `RequiredScopes` names scopes needed by this operation. Return `ClientConfig`, including the registered redirect URI
  for PKCE and a runtime client secret for client credentials. Resolve any
  `clientSecretRef` through host secrets here. Explicit registration presets
  constrain issuer, resource, client, flow and scopes; they cannot be replaced.
  `TokenAuthMethod` may select `none`, `client_secret_basic` or
  `client_secret_post`; discovery verifies issuer support. When omitted, the
  adapter selects a supported method without automatic credential-style probing.
- **`ValidateToken(ctx, client, token)`** verifies validity and resource/audience
  under local policy, including cryptographic JWT validation where appropriate.
  An absent expiry remains usable until rejection; an explicit expired lifetime
  does not; `expires_in` must be a positive integer (or digit string). An
  acquisition (consent or client credentials) requests any previously granted
  scopes plus the ceiling-filtered request, and records the response scopes
  within the previous grant plus the acquisition ceiling (the pending login's,
  or the client-credentials caller's); extra scopes are ignored. A refresh records the response within the previous grant, so it
  never broadens it, and a narrowed ceiling never shrinks it: each caller's
  ceiling filters the grant only at use; broader requirements need fresh consent or a new
  client-credentials grant. A missing required scope fails the operation with
  `access_denied` after the grant is saved. The host retains responsibility for trusting opaque issuer tokens.
- **`Store`** loads detached `Record` snapshots, atomically compares generations,
  and coordinates the complete acquisition/refresh callback for a key across
  host instances/processes. Its methods must honor context cancellation and
  release coordination on errors or panics. Do not reenter the same provider/key
  from a store callback. Secure persistence and durable schema migrations belong
  to the host; no filesystem format or default store is installed. Persist the
  complete `Record`, including its optional `Binding` and `Pending` fields, and
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
    // Any process sharing the Store may receive the callback and complete it.
    callbackURL, err := receiveCallback(callbackCtx)
    if err != nil {
        return managed.Cancel(ctx, request)
    }
    _, err = managed.Complete(ctx, request, callbackURL)
    return err
}
// prepared.Credential is ready; normal delivery acquires through auth.Provider.
```

A pending login is a stored record with a lifetime fixed at creation
(`Options.LoginLifetime`, default and maximum ten minutes), independent of the
creating context. Completion validates state, exact redirect path and the
optional/advertised issuer response before claiming the login; an invalid
callback does not consume it. A later `Prepare` reuses an unexpired login when
the grant and redirect match and its scopes cover the new requested and
required scopes. Otherwise it supersedes the login, requesting the old login's
scopes plus the new ceiling-filtered request and storing the union of both
ceilings, which bounds the grant recorded on completion. Both only grow, so
alternating callers converge. A login ends once:
completion (including denial), supersede, `Cancel` or expiry; a callback for an
ended login fails with `interaction_required`. `Cancel` never erases stored
credentials.

A dispatch that needs consent returns `interaction_required`; it never launches
interactive UI, waits for a human or creates a login. Client credentials
completes through `Prepare` without UI and requires explicit issuer grant support.

## Discovery, isolation and failure recovery

An unknown unbound HTTP endpoint starts anonymously. A previously authorized
unbound endpoint sends its cached bearer up front, including for notifications
and uploads, even after provider recreation or during a metadata outage. That
lookup never runs protected-resource discovery or creates a login; with a
context deadline it refreshes or re-acquires an expired grant using the issuer
metadata persisted with the binding (fetching only the stored issuer's metadata
if none is persisted). Only a store miss or host policy refusal sends
anonymously; a known binding whose grant cannot be renewed, including one that
needs consent, fails the operation. A 401 marks the rejected token stale even
before its expiry, so it is renewed rather than resent.
A challenge on a notification or upload is not replayed but still runs challenge
handling, so the next operation sends a credential. Local policy still runs before using a stored
grant. Explicit presets skip protected
resource discovery and validate the selected issuer metadata instead. On a real 401 the
adapter honors the Bearer challenge's `resource_metadata`, otherwise tries the
endpoint-path and origin-root RFC 9728 locations in order. It validates the exact RFC 9728 retrieval-source resource identifier in addition
to resource coverage, and discovers the exact selected issuer using OAuth/OIDC well-known
locations. Server-required scopes must already be permitted locally;
`scopes_supported` never grants consent. No dynamic client registration is
performed: the host selects an already registered client.

Tokens and refresh requests carry the validated RFC 8707 resource. Default grant
partitions isolate every namespace, backend, exact destination and event/upload
purpose. A nonempty `ClientConfig.GrantPartition` explicitly shares consent only
between independently approved bindings with the same issuer, resource, client
and flow. Changing the allowed ceiling, a secret, the token-endpoint
authentication method, a metadata capability or the granted scope set does not
change grant identity; the grant is re-intersected with the current ceiling at
use. Uploads never inherit event authorization. A challenge drops the rejected
token, so it is never resent; a stale 401 leaves a newer token alone. The
provider never replays a delivery itself; `auth.Do` replays only intercept,
configuration and capabilities requests, once. Explicit Authorization headers bypass the entire auth path.

A Bearer 403 with `error="insufficient_scope"` can request step-up only within the
local allowed ceiling and only for the challenged operation; it is never stored.
PKCE reports `interaction_required` carrying the required `Scopes`; pass them to
`Prepare(ctx, request, err.Scopes...)` to request consent. `Prepare` denies
required scopes outside the ceiling; `access_denied` may report them for
diagnostics only. Client credentials
reissue noninteractively.
If a scope challenge omits `scope`, only an explicit host requirement can
identify a permitted step-up; otherwise it returns `access_denied`. Other 403
responses are not auth retries. Dispatch never creates pending consent.

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
