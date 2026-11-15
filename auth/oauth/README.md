# Managed OAuth: security gate held

**No managed `auth.Provider` is shipped in this package.** Neither PKCE nor
client credentials is exposed as a supported managed flow. Existing hosts can
continue to supply their own `auth.Provider`; merely importing this package does
not enable discovery or acquisition. No browser, listener, store, token source,
worker, or network operation is created by this package.

The dependency compatibility spike uses **Go 1.27.3** and
`golang.org/x/oauth2 v0.38.0`. Run it with:

```sh
go test ./auth/oauth
```

## Verified, but not a managed implementation

The TLS `httptest` cases exercise real `oauth2.Config` and
`clientcredentials.Config` requests, not mocks of those APIs:

- `GenerateVerifier`, `S256ChallengeOption`, `VerifierOption`, and `Exchange`
  support host-controlled PKCE mechanics. The host still owns state validation,
  callback transport, issuer/resource validation, and persistence.
- Initial code exchange accepts `resource` through `SetAuthURLParam`.
- Client credentials accepts `resource` through `EndpointParams`.
- **Refresh does not preserve the initial exchange's `resource` parameter.**
  `Config.TokenSource` has no refresh-parameter option. A managed implementation
  needs a separately reviewed resource-bound refresh path; a generic token
  source alone is insufficient.
- Explicit token endpoint `AuthStyle` avoids automatic credential-style probing
  and its possible repeated token POST. Native cancellation reaches grant calls.

These tests demonstrate library compatibility, **not** compliant AHP behavior.
They use fake credentials and an in-process TLS issuer. There are no store-boundary
or managed-flow parity claims, because those boundaries have not been implemented.
The dependency is currently used only by compatibility tests; Go does not isolate
subpackage test dependencies into a separate optional dependency manifest.

## Required before exposing an adapter

`spec/draft/capability-auth.md:101–155` in the protocol repository is normative.
Static configured token endpoints cannot replace discovery. A managed adapter
must satisfy these gates:

1. Without binding/Authorization, attempt the endpoint anonymously first. On
   401, parse `WWW-Authenticate`; honor `resource_metadata`, or try path-specific
   then origin-root RFC 9728 metadata locations in MCP order.
2. Validate the RFC 9728 section 3.3 resource identifier, choose only locally
   trusted authorization servers, and perform MCP's ordered OAuth/OIDC metadata
   discovery. Require exact issuer identity. Explicit OAuth bindings constrain
   this discovery; a failed explicit binding must never switch identities.
3. Apply host URL, destination, DNS, TLS and redirect policy to **every** metadata,
   authorization, token and registration endpoint. Redirects must not leak
   credentials. Bound response sizes, discovery steps and operation deadlines.
4. Request only locally permitted scopes; neither challenge scopes nor
   `scopes_supported` grant consent. Bind all grants **and refreshes** to the
   validated RFC 8707 resource. Validate token type, validity and permissions.
5. Use host-controlled atomic persistence/coordination keyed by credential
   namespace, issuer, resource, client, flow, scopes and independently authorized
   destination/purpose. Test concurrent refresh, rotation, stale 401s and store
   failure/cancellation. Do not retain operation contexts in background sources.
6. For PKCE, reserve/dedupe pending login before asynchronous work, verify state,
   callback URI and issuer, consume only its own generation, and let the host own
   display, callback transport and cancellation. Client credentials additionally
   requires explicit issuer support. Unsupported flows need typed outcomes.
7. Integrate `auth.Request`, `Credential`, and `Challenge` with safe classified
   errors and native cancellation. No response bodies, tokens or callback URLs
   may appear in error chains. Never independently replay effectful deliveries.

## Host-controlled mechanics example (not an AHP adapter)

The test suite contains the executable form of this fragment. These URLs must
come from already validated metadata, not an arbitrary registration/challenge:

```go
ctx = context.WithValue(ctx, oauth2.HTTPClient, trustedHTTPClient)
verifier := oauth2.GenerateVerifier() // host retains this with random state
loginURL := config.AuthCodeURL(state,
    oauth2.S256ChallengeOption(verifier),
    oauth2.SetAuthURLParam("resource", validatedResource))
// Host displays loginURL and receives callback; validate state/issuer/URI first.
token, err := config.Exchange(ctx, code,
    oauth2.VerifierOption(verifier),
    oauth2.SetAuthURLParam("resource", validatedResource))
// Host must still validate and atomically persist token; do not log token/err.
```

Do not copy this fragment as a complete provider: it intentionally omits the
security gates above. Managed implementation is **blocked**, not attempted-and-
successful, and the complete parity suite has **not** been run for an adapter.
