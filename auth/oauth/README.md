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
  `Scopes` when nil), and `RequiredScopes` names scopes needed by this operation. Return `ClientConfig`, including the registered redirect URI
  for PKCE and a runtime client secret for client credentials. Resolve any
  `clientSecretRef` through host secrets here. Explicit registration presets
  constrain issuer, resource, client, flow and scopes; they cannot be replaced.
  `TokenAuthMethod` may select `none`, `client_secret_basic` or
  `client_secret_post`; discovery verifies issuer support. When omitted, the
  adapter selects a supported method without automatic credential-style probing.
- **`ValidateToken(ctx, client, token)`** verifies validity and resource/audience
  under local policy, including cryptographic JWT validation where appropriate.
  An absent expiry remains usable until rejection; an explicit expired lifetime
  does not. Grants may narrow requested scopes or add only locally allowed
  scopes. Refresh responses inherit the previously granted scopes when omitted
  and cannot broaden them; broader requirements need fresh consent or a new
  client-credentials grant. Missing required scopes prevent use without discarding rotated refresh
  credentials. The host retains responsibility for trusting opaque issuer tokens.
- **`Store`** loads detached `Record` snapshots, atomically compares generations,
  and coordinates the complete acquisition/refresh callback for a key across
  host instances/processes. Its methods must honor context cancellation and
  release coordination on errors or panics. Do not reenter the same provider/key
  from a store callback. Secure persistence and durable schema migrations belong
  to the host; no filesystem format or default store is installed. Persist the
  complete `Record`, including its optional `Binding` metadata, and preserve
  zero `ExpiresAt` as unknown expiry. Binding records contain no client secret.
  The length-framed binding/grant keys replace earlier experimental JSON keys;
  old records are not automatically migrated and can require fresh consent.

All network, policy and store work uses the supplied context. Provider operations
require a context with an enclosing deadline; they never extend it. The host must
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
    login := prepared.Login
    presentAuthorizationURL(login.AuthorizationURL())
    // The host receives this URL through its own trusted callback transport.
    callbackURL, err := receiveCallback(ctx)
    if err != nil {
        managed.Cancel(login)
        return err
    }
    _, err = managed.Complete(ctx, login, callbackURL)
    return err
}
// prepared.Credential is ready; normal delivery acquires through auth.Provider.
```

Login completion validates state, exact redirect path, optional/advertised issuer
response and the original deadline/cancellation. An invalid state, redirect or issuer does not consume a pending login. A valid
callback atomically claims the login once before exchange; denial consumes it.
Repeated preparations reuse consent only for the same grant, exact redirect,
requested and required scopes, while the original context is active and its
deadline covers the new prepare budget. An incompatible explicit preparation
replaces the old handle; its callback cannot complete the replacement. Poll the
same operation with its original budget instead of repeatedly extending it. Its
maximum lifetime is ten minutes, and each provider holds at most 128 active
pending logins. Use `Cancel` when abandoning consent; cancellation never erases
stored credentials. Concurrent providers share token coordination through the
host store, but their in-memory consent handles are independent.

A dispatch that needs consent returns `interaction_required`; it never launches
interactive UI or waits for a human. Call `Prepare` from the host UI path to get
the pending login. Client credentials completes through `Prepare` without UI and
requires explicit issuer grant support.

## Discovery, isolation and failure recovery

An unknown unbound HTTP endpoint starts anonymously. A previously authorized
unbound endpoint sends its cached bearer up front, including for notifications
and uploads, even after provider recreation or during a metadata outage. Local
policy still runs before using a stored grant. Explicit presets skip protected
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
between independently approved bindings with the same issuer, resource, client,
flow and allowed ceiling. Changing a secret, metadata capability or granted scope
set does not change grant identity. Uploads never inherit event authorization.
A stale 401 cannot invalidate a newer generation. The provider never independently
replays a delivery; `auth.Do` permits at most one safe retry and never replays an
effectful delivery. Explicit Authorization headers bypass the entire auth path.

A Bearer 403 with `error="insufficient_scope"` can request step-up only within the
local allowed ceiling. PKCE reports `interaction_required`; call `Prepare` with
an independent host consent budget. Client credentials reissue noninteractively.
If a scope challenge omits `scope`, only an explicit host requirement can
identify a permitted step-up; otherwise it returns `access_denied`. Other 403
responses are not auth retries. Dispatch never creates pending consent.

Transient OAuth errors, 5xx, non-OAuth responses and transport failures preserve
refresh material and return retry advice. Definitive PKCE `invalid_grant` becomes
`refresh_rejected`; call `Prepare` for consent. An ambiguous exchange can retain
`RefreshUncertain` for host diagnosis but does not permanently wedge the grant:
a subsequent attempt may retry the retained refresh token. An external rotating
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
