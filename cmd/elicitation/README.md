# Elicitation fixture adapter

This is a synthetic interoperability host, not an application agent. Ordinary
`user.elicitation.request` and `user.elicitation.result` sends use the public
client, serialized MCP JSON in inline text parts, and protocol acceptance.
Inline text is not uploaded. Raw upload probes verify immutable binary storage.
The receiver uses the public server handler. Only explicitly marked `bypass`
intercepts, raw upload framing, and host-control operations use the byte driver.

## Prior-request ownership across processes

The canonical runner starts a fresh sender process for each step. It does not repeat the original request with each result. The sender therefore persists the **actual accepted original
request envelope with its exact inline JSON text** in private host-owned storage.
It never infers an original request identity from a result or invents a source,
session, server, or event ID.

The default store is in the OS temporary directory, scoped by a SHA-256 digest
of the configured receiver endpoint and event credential. Credential bytes are
not stored. Its limits are:

- 16 receiver/credential scopes;
- 128 pending requests per scope;
- 8 MiB per persisted scope;
- 15-minute request lifetime;
- private directories (0700), atomic private files (0600), and a cancellable
  exclusive lock with a 5-second acquisition limit.

A successful result consumes its matching pending request. Adversarial raw
probes do not overwrite or consume ordinary host state. Missing, expired, or
conflicting prior state causes an error, never a fallback to raw result sending.
SDK snapshot reconstruction runs locally from the original envelope;
it does not replay the original request to the receiver. The result boundary
receives the resulting opaque `client.ElicitationRequest` through
`WithElicitationRequest` and performs normal public protocol acceptance.

The sender plan also accepts:

- `stateFile`: an explicit private host-state file. Its parent directory must be
  private and owned by the current user. Endpoint/credential scope still applies.
- `originalRequest`: the actual complete prior AHP request envelope, for a host
  that keeps its own state. Its inline text part contains the serialized MCP request. This is an explicit
  host input, not a result-derived template.

The current fixture persistence implementation targets the Unix/macOS test-host
platforms used by the repository's integration runners.
