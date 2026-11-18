# Server-driven configuration

A backend can publish subscription defaults through `hooks/configuration`. The
same public subscription declarations work in backend configuration and explicit
client registration:

```go
configuration := ahp.NewConfiguration(
    subscription.NewIntercept(
        event.ToolBefore,
        750*time.Millisecond,
        subscription.FailOpen,
        content.Metadata(),
    ),
).Subscribe(
    subscription.NewObserve(content.Metadata(), event.ToolAfter),
)

handler, err := server.NewHandler(server.Handlers{
    Configuration: configuration,
    Intercept: server.InterceptHandlers{ToolBefore: handleToolBefore},
}, server.Options{})
```

Import `ahp` from `github.com/agenthooksprotocol/go-sdk` and the `content`, `event`,
`server`, and `subscription` subpackages. For static configuration, `NewHandler` validates and snapshots the
declaration; later caller mutations do not change the advertisement. Mount the
handler on the application's authenticated HTTP route, or pass it to
`server.ServeStdio`. Authentication remains application-owned.

## Dynamic backend configuration

The same `Handlers.Configuration` field accepts an `ahp.ConfigurationSource`.
Use `ahp.ConfigurationFunc` for a function, or implement `ResolveConfiguration`
on an application-owned type:

```go
source := ahp.ConfigurationFunc(func(ctx context.Context) (*ahp.Configuration, error) {
    // Read tenant information installed by your authentication middleware.
    if err := ctx.Err(); err != nil {
        return nil, err
    }
    return ahp.NewConfiguration(
        subscription.NewIntercept(
            event.ToolBefore,
            750*time.Millisecond,
            subscription.FailOpen,
            content.Metadata(),
        ),
    ), nil
})
handler, err := server.NewHandler(server.Handlers{Configuration: source}, server.Options{})
```

The SDK invokes a dynamic source only for a validated `hooks/configuration`
request, with the current request context. HTTP authentication remains middleware
owned. Stdio uses the same handler without inventing an authenticated principal.
The SDK owns JSON-RPC routing, correlation, validation, and response serialization.

Dynamic sources can run concurrently and must honor context cancellation. Each
successful result is validated and copied; do not mutate it concurrently with
that copy. There is no dynamic-result cache. A nil result, invalid configuration,
callback error, or panic produces a sanitized backend error and
`server.ErrConfigurationUnavailable` through `Options.Diagnostic`. Errors and
panic values are never included in diagnostics or responses. A nil source,
including a typed nil pointer or function, means discovery is unavailable.
Static `*ahp.Configuration` callers retain setup-time validation and snapshot
behavior.

## Client discovery

The client opts into discovery by omitting subscriptions:

```go
registration.New(
    registration.NewDiscoveredBackend(
        "com.example.policy",
        transport.NewHttp("https://policy.example.test/hooks"),
    ),
)
```

A JSON registration has the same behavior when the backend's `subscriptions`
member is absent. An explicit empty array is invalid. Explicit non-empty
subscriptions replace server defaults completely and never trigger discovery;
existing servers need not implement discovery for explicit registration to work.
Use `registration.NewBackend` and `registration.WithBackendSubscriptions` to
supply the same typed subscriptions explicitly.

`client.New` completes discovery before returning. `Options.ConfigurationTimeout`
bounds each discovery exchange, including endpoint authentication; zero means
five seconds. `Options.InitializationContext` supports caller cancellation and a
shared initialization deadline. A discovery timeout skips that backend, while
cancellation of the initialization context returns an error. Both HTTP and stdio
use the existing transport, authentication, configured headers, and ownership
rules. Persistent processes remain client-owned; skipped transports are closed,
and a re-attempt opens a fresh one.

The client resolves advertised selectors against its supported event modes.
Unsupported matches are dropped; other settings are not rewritten. Failed,
malformed, or inapplicable advertisements skip the backend.
`Options.TransportDiagnostic` receives a `*client.ConfigurationSkipError`
`{BackendID, Code, AuthError, Recovery}` (JSON `{backendId, code, authError?,
recovery?}`), which matches `client.ErrConfigurationSkipped` with `errors.Is`,
without response bodies or credentials. `Code` is one of:

| Code | Cause | Re-attempted |
| --- | --- | --- |
| `configuration_unavailable` | Transport failure, timeout, non-success HTTP status, JSON-RPC error other than method-not-found, endpoint authentication failure | Yes |
| `configuration_invalid` | Method-not-found; uncorrelated, malformed or version-incompatible response; an unsupported discovered setting | No |
| `no_applicable_subscriptions` | No advertised subscription matches this client | No |
| `configuration_local_secret` | A discovered upload names a local secret reference | No |

`AuthError` and `Recovery` are the safe `auth.Code` and its `auth.Recovery`,
set only when an authentication error caused the skip; `errors.As` also finds
the redacted `*auth.Error`.

A `configuration_unavailable` backend is re-attempted inside the next event
admission (`Dispatch` and the named methods) once it is eligible:

- At once after a successful host prepare for its event endpoint, which also
  resets backoff. The client learns of it from an `AuthProvider` implementing
  `auth.PreparationTracker`, as `oauth.Provider` does (a `Prepare` that returns
  a credential, or a successful `Complete`). Prepare with the same backend ID
  and endpoint URL as the registration.
- After backoff, only when there is no `AuthError` or its recovery is `retry`.
  `Options.ConfigurationRetryDelay` (default 30 seconds) doubles after each
  failed attempt up to `Options.ConfigurationRetryMaxDelay` (default one hour).
  With recovery `login`, `configure` or `none`, only a prepare or a new client
  re-attempts it.

A re-attempt is bounded by `ConfigurationTimeout` and the event's context, and
cancellation emits no diagnostic. It is part of a single shared admission:
another event arriving meanwhile is delivered with the previous routes rather
than waiting, and a successful attempt installs all of the backend's routes at
once, in registration order. Events admitted earlier are never replayed to it.
Other codes are not re-attempted. There is no periodic refresh or effect
guarantee; per-request capability grants remain authoritative.

A backend with omitted subscriptions is advisory while its configuration is
unavailable: no failure policy is inferred and events are delivered without it.
Enforcement while a backend is unreachable or unauthenticated requires explicit
subscriptions with `failurePolicy` `fail-closed`.

## Discovered uploads

Discovered upload settings are admitted like any other discovered subscription
setting, with no separate approval. A discovered upload is a modality of the
content the backend already receives, so the backend's configured headers apply to
it exactly as they apply to other uploads from that backend.

Server configuration is untrusted and cannot authorize access to local credentials.
If any advertised subscription's upload `auth` names `tokenEnv`, `tokenRef`, or
`clientSecretRef`, the entire backend is skipped without resolving the reference;
the reference is not removed to admit the remainder. `Options.TransportDiagnostic`
receives a `configuration_local_secret` skip, which matches
`client.ErrConfigurationLocalSecretReference` and `client.ErrConfigurationSkipped`.

Existing per-item content authorization and independent upload authentication
still apply after admission. Explicit client subscriptions retain their existing
behavior, including local secret references, and do not invoke discovery.
