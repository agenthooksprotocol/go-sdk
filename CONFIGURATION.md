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
`server`, and `subscription` subpackages. `NewHandler` validates and snapshots the
configuration; later caller mutations do not change the advertisement. Mount the
handler on the application's authenticated HTTP route, or pass it to
`server.ServeStdio`. Authentication remains application-owned.

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
rules. Persistent processes remain client-owned; skipped transports are closed.

The client resolves advertised selectors against its supported event modes.
Unsupported matches are dropped; other settings are not rewritten. Failed,
malformed, or inapplicable advertisements skip the backend.
`Options.TransportDiagnostic` receives `client.ErrConfigurationSkipped` without
response bodies or credentials. There is no periodic refresh or effect guarantee;
per-request capability grants remain authoritative.

## Upload authorization

Server configuration is untrusted. An advertised upload destination or credential
reference does not authorize access to local credentials. Upload-bearing defaults
are skipped unless `Options.AuthorizeConfiguration` explicitly approves them.
This callback receives the bounded initialization context and a detached
configuration snapshot. Inspect upload destinations and authentication bindings
against local policy before returning true. Returning false or an error skips the
backend; mutating the snapshot cannot change its subscriptions.

For configurations without upload settings, this callback is optional. When
supplied, it runs for those configurations too. Existing per-item content
authorization and independent upload authentication still apply after admission;
configuration approval does not bypass them. Explicit client subscriptions retain
their existing behavior and do not invoke this discovery callback.
