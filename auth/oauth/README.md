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
  issuer, client, supported flow and allowed/requested scopes from untrusted
  advertisements. Return `ClientConfig`, including the registered redirect URI
  for PKCE and a runtime client secret for client credentials. Resolve any
  `clientSecretRef` through host secrets here. Explicit registration presets
  constrain issuer, resource, client, flow and scopes; they cannot be replaced.
  `TokenAuthMethod` may select `none`, `client_secret_basic` or
  `client_secret_post`; discovery verifies issuer support. When omitted, the
  adapter selects a supported method without automatic credential-style probing.
- **`ValidateToken(ctx, client, token)`** verifies validity and resource/audience
  under local policy, including cryptographic JWT validation where appropriate.
  Only bearer tokens with a future expiry and the requested scope set are
  accepted. The host retains responsibility for trusting opaque issuer tokens.
- **`Store`** loads detached `Record` snapshots, atomically compares generations,
  and coordinates the complete acquisition/refresh callback for a key across
  host instances/processes. Its methods must honor context cancellation and
  release coordination on errors or panics. Do not reenter the same provider/key
  from a store callback. Secure persistence and durable schema migrations belong
  to the host; no filesystem format or default store is installed.

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
response and the original deadline/cancellation. A pending login is single-use.
Repeated preparations for the same provider/key share the pending login. Its
maximum lifetime is ten minutes, and each provider holds at most 128 active
pending logins. Use `Cancel` when abandoning consent; cancellation never erases
stored credentials. Concurrent providers share token coordination through the
host store, but their in-memory consent handles are independent.

A dispatch that needs consent returns `interaction_required`; it never launches
interactive UI or waits for a human. Call `Prepare` from the host UI path to get
the pending login. Client credentials completes through `Prepare` without UI and
requires explicit issuer grant support.

## Discovery, isolation and failure recovery

For an unbound HTTP endpoint, delivery starts anonymously. On a real 401 the
adapter honors the Bearer challenge's `resource_metadata`, otherwise tries the
endpoint-path and origin-root RFC 9728 locations in order. It validates resource
coverage and discovers the exact selected issuer using OAuth/OIDC well-known
locations. Server-required scopes must already be permitted locally;
`scopes_supported` never grants consent. No dynamic client registration is
performed: the host selects an already registered client.

Tokens and refresh requests carry the validated RFC 8707 resource. Store keys
include namespace, backend, complete destination, event/upload purpose, binding,
issuer, resource, client, flow, token-auth method and scopes. Uploads never inherit
event tokens. A stale 401 cannot invalidate a newer generation. The provider
never independently replays a delivery; `auth.Do` retains its existing bounded
safe-retry rules. Configured Authorization headers bypass the entire auth path.

Known OAuth `temporarily_unavailable`/`server_error` responses retain credentials
for a later attempt. Definitive `invalid_grant` becomes `refresh_rejected`; call
`Prepare` again to obtain repair consent. Before a rotating refresh, the adapter
persists an ambiguity marker. Cancellation, an ambiguous network outcome or a
failed post-exchange commit retains the old secrets but does **not** blindly
reuse the old refresh token. `Prepare` offers a fresh login for explicit repair.
This conservative policy cannot guarantee transactional rollback at an external
authorization server.

Use `errors.As(err, *auth.Error)` for safe classifications and `errors.Is` for
native cancellation/deadlines. Diagnostics discard raw upstream response bodies,
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
