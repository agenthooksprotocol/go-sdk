# Agent Hooks Protocol SDK for Go

The active draft also provides MCP-aligned elicitation, automatic short-circuit
observation delivery, and before/after compaction controls. See the shared
[boundary API guide](https://github.com/agenthooksprotocol/agent-hooks-protocol/blob/main/docs/accepted-boundary-apis.md)
for entrypoints, upload binding, trusted-host obligations, and test scope.

Typed Go models and JSON codecs for the [Agent Hooks Protocol (AHP)](https://github.com/agenthooksprotocol/agent-hooks-protocol).

The SDK follows the current AHP `draft` schema snapshot and supports Go 1.27 or newer.

## Installation

```sh
go get github.com/agenthooksprotocol/go-sdk@latest
```

While the protocol is a working draft, pin a commit SHA for reproducible builds.

## Quick start

Every public AHP schema has a Go type plus `Parse<Type>` and `Encode<Type>` functions.

```go
package main

import (
    "fmt"
    "log"

    ahp "github.com/agenthooksprotocol/go-sdk"
)

func main() {
    input := []byte(`{"effects":["deny"],"com.example.preview":true}`)
    result := ahp.ParseCapabilities(input)
    if !result.OK {
        log.Fatal(result.Diagnostics)
    }

    fmt.Println(result.Value.Effects)

    encoded, err := ahp.EncodeCapabilities(result.Value)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(encoded))
}
```

A successful `ParseResult[T]` contains the typed `Value`, the original JSON in `Raw`, and compatibility diagnostics. A failed result retains `Raw` when the input was valid JSON and reports diagnostics with a JSON Pointer path and machine-readable code.

## API

The package exports:

- `SchemaRevision` and `ProtocolVersionValue`
- typed models for registrations, JSON-RPC messages, hook events, requests, responses, capabilities, and effects
- `Parse<Type>([]byte) ParseResult[Type]` for structural parsing
- `Encode<Type>(Type) ([]byte, error)` for JSON encoding
- `ParseDiagnostic`, `DiagnosticCode`, and `DiagnosticSeverity`

Generated structs preserve unknown object members in `AdditionalProperties`. Open enums retain unknown string values, and discriminated unions preserve unknown variants. Parsing does not coerce values, insert defaults, or discard extension data.

## Public runtime

The `client` package composes protocol decisions; it does **not** run tools,
validate application argument schemas, grant native permissions, or commit
compaction changes. The host remains responsible for those operations.

- Configure `client.Hooks` with JSON registration, stable host `Source`, and
  explicit event modes/capability grants. A full manifest is an advanced
  alternative. Registration order, selectors, deadlines, and failure policies
  govern delivery. Construction performs no network or process I/O.
- Call the context-first named boundary methods with generated `event` input
  projections. `ToolBefore` preserves the application argument type through its
  result. Use `json.RawMessage` as the type for dynamic tool registries.
- `WithInitialState` carries a native decision already accumulated for this
  occurrence. `WithCapabilities` can only narrow the manifest. Neither option
  proves execution or grants authority.
- A protocol denial is a result, not a Go error. Operational failures appear in
  `Result.Diagnostics`; fail-closed failures are distinguishable from backend effects.
  `Result.Errors` remains a compatibility view of interception failures.
  `Result.Permission` is the canonical settled permission: `none` is not approval,
  `ask` requires host approval, and interruption always prevents execution.
  Each `DeliveryError.Code` is a typed `DeliveryCode`: `protocol_rejection`,
  `remote_rpc`, `transport`, `cancelled`, `deadline_exceeded`, `preparation`, or
  `capacity`. `Stage` still identifies the phase, and `FailClosed` identifies
  synthetic denial. Remote RPC codes require a valid, correlated error envelope;
  backend error messages/data are not exposed. Inspect `Code`, not error text.
  Cancellation returns the accepted prefix with `Interrupted` set and a context
  error. Never execute interrupted work, including under fail-open policy.
- A `DecodeError` means protocol acceptance succeeded but the effective input
  cannot be represented by the application's type. The non-nil result retains
  accepted effects and raw `EffectiveInput`; `InputAvailable` is false. Do not
  treat this as a rejected backend response or use the typed zero value.
- Each boundary call owns its bounded observation deliveries and finishes them
  before returning. Observation failures appear in `Diagnostics` but never change
  the settled decision. `Observations` remains an already-completed compatibility
  handle. Hosts own concurrency: run the whole call in a goroutine and retain its
  result; never execute a gated operation before obtaining its decision.
- The call's `context.Context` bounds queue waits, content preparation/uploads,
  authentication, event delivery, retries and observations with one remaining
  budget. Backend deadlines can shorten that budget, never reset it. Cancellation
  stops new work and retires owned I/O; safety cleanup may outlast the deadline.
- `Close` rejects new work, cancels active calls, waits for owned resource retirement
  and reaps subprocesses. Concurrent/repeated calls wait for the same completion
  and return the same outcome. Await calls before closing for graceful completion.
  Borrowed HTTP clients and harness-owned auth providers are never closed.

Generated semantic packages (`registration`, `transport`, `subscription`,
`effect`, `content`, `capability`, `event`, and `tool`) construct the existing
wire types. Constructors fill schema literals and annotated defaults; parsers
continue to preserve presence and never invent omitted required fields. The
API targets the draft wire protocol and may evolve with it.

`client.Hooks` is the registration-driven harness. Construct it with ordinary
JSON registration and explicit event grants; there is no separate initialization
step or custom registration-file loader:

```go
data, err := os.ReadFile("hooks.json")
if err != nil { return err }
var reg ahp.Registration
if err := json.Unmarshal(data, &reg); err != nil { return err }

toolCapabilities, err := capability.Intercept(
    capability.Deny(), capability.ModifyInput(capability.Replace))
if err != nil { return err }

hooks, err := client.New(reg, client.Options{
    Source: "urn:example:host",
    Events: map[string]client.EventCapabilities{
        "tool.before": toolCapabilities,
    },
    Content: hostContentPolicy, // Explicit, receiver-scoped host disclosure policy.
})
if err != nil { return err }
defer hooks.Close()

type Arguments struct { Path string `json:"path"` }
result, err := hooks.ToolBefore(ctx, event.ToolBeforeInput[Arguments]{
    CallID: "call-1", Path: "execute",
    Name: "read_file", Origin: ahp.ExecutionEventToolOriginNative,
    Input: Arguments{Path: "notes.txt"},
})
// Check err, result.Interrupted, protocol state, and host policy before execution.
// result.Input has type Arguments when result.InputAvailable is true.
```

The JSON document uses the unchanged `ahp.Registration` wire model: backend
routes, modes, deadlines, failure policies, content selections, and upload
endpoints remain registration data. The event map grants no effects or elicitation support beyond the supplied
declaration. `capability.Intercept` deliberately advertises both intercept and
observe modes; `capability.Observe` advertises only observe. Include
`capability.ElicitationForm()` explicitly when advertising form decisions.
`Options.Manifest` remains available for advanced full-manifest metadata;
provide it instead of `Events`, not together with it. `client.Client` is a
deprecated alias of `Hooks`, not a second runtime or API.

See the executable [JSON registration and typed boundary example](client/example_hooks_test.go),
[generated constructor examples](facade_generated_test.go), and
[public HTTP tests](client/public_http_test.go). The compiled example includes
initial state, capability narrowing, decode-error handling, observation drain,
shutdown, and a standard owned-stream stdio server. The compiled
[resolved-content walkthrough](public_protocol_completion_test.go) shows verified
host bytes, explicit receiver authorization, independent upload routes,
`WithCompactionInstructions`, and detached `Result.Content` retrieval side by
side with the receiving HTTP handlers.

Duration constructors preserve exact decimal milliseconds. Canonical admission
rejects fractional milliseconds and nonpositive deadlines. Use the generated
`NewInterceptDuration` helper for an eager checked constructor, or
`NewInterceptMilliseconds` for explicit wire values. No timeout or stdio
lifecycle default is invented.

### Generated event, capability, state, and effect helpers

Generated `event.*Input` structs are ergonomic boundary inputs, not copies of
nested wire envelopes. For tool boundaries, set `CallID`, `Name`, `Origin`,
`Input`, and `Path` directly instead of constructing `Call` and `Tool` wrappers.
`ToolBeforeInput[T]` retains the application's typed input. Other event-specific
fields remain typed; optional fields use `ahp.Some(value)`, including `ID` and
`ParentEventID`. Zero optional values mean absent, not an explicit null.
The generated marshaler restores canonical nested wire fields. Use root `ahp`
wire models and parsers for decoding protocol JSON, not ergonomic input structs.
Advanced dynamic callers can use `Hooks.Dispatch(ctx, eventType, input, options...)`
with canonical host fields, excluding SDK-owned `type`, `source`, and `manifest`.
Canonical fixture adapters use this path instead of duplicating generated mappings.
The SDK owns the protocol envelope and fills permitted identity fields; callers
still supply required occurrence and application data.

`capability.Event` is the event declaration used by `client.EventCapabilities`.
`capability.Intercept(grants...)` returns `(capability.Event, error)` and requires
explicit grants; always handle its error. Available grants are:

- `Allow`, `Ask`, `Deny`, `Message`, and `Return`.
- `ModifyContent`, `ModifyInput`, `ModifyInstructions`, `ModifyOutput`,
  `ModifyPrompt`, `ModifyRequest`, `ModifyResponse`, `ModifySummary`, and
  `ModifyWorkspace`, each with explicit `capability.Merge` and/or
  `capability.Replace` operations.
- `FlowContinue(remaining, count)` and `FlowStop`.
- `InjectContextAppend`, with explicit `capability.Now` and/or
  `capability.NextTurn` delivery timing.
- `ElicitationForm` and `ElicitationURL`, independently granted.

Construction is not event admission or execution authorization. Hooks still
checks event compatibility, host support, and per-call narrowing. Pass a checked
narrower declaration's dereferenced `Capabilities` to `client.WithCapabilities`.
The lower-level `capability.New` and event-specific wire constructors remain
available for advanced declarations.

`state.Initial(permission.None)` returns a pointer to state with no candidate.
`permission.Allow`, `Ask`, `Deny`, and `None` represent native decisions already
made for this occurrence, not a new authorization. Pass the dereferenced result
to `client.WithInitialState`. `state.Candidate(value, provenance...)` encodes a
candidate and returns an error; `state.WithCandidate`, `WithFlow`,
`WithInjections`, and `WithInstructions` supply explicit accumulated state.
`state.NoCandidate` represents an explicit absent candidate. Initial state never
skips host permission, approval, or application-schema validation.

Receiver-side `effect.Modify<Target>Merge(value)` and
`effect.Modify<Target>Replace(value)` accept typed application values for all
nine modification targets above. `effect.Return(value)` and
`effect.InjectContextAppend(effect.Now, value)` (or `effect.NextTurn`) likewise
encode payloads and return `(*ahp.Effect, error)`; check errors before publishing
a response. Simple effects retain `NewAllow`, `NewAsk`, `NewDeny`, `NewMessage`,
`NewFlowStop`, and `NewFlowContinue`. Raw `NewModify`, `NewReturn`, and
`NewInjectAppend` remain advanced wire helpers. These constructors neither grant
capabilities nor establish that a payload satisfies the host application's schema.

Generated content-source companions such as `ItemsSources`, `InstructionsSource`,
and `SummarySource` bind owned `*content.Source` values to their descriptor slots
without serializing readers or reading at construction. Sources supplement, not
replace, canonical descriptors. Explicit host content authorization, disclosure
policy, size limits, and source ownership rules still apply.

### Current composition coverage

The client composes input and resolved non-input modifications, protocol
permission/candidate decisions, messages, injections, and bounded flow effects.
Invalid capability grants and missing target bindings fail before delivery.

Descriptor-backed modifications use verified, occurrence-owned bytes. Each
receiver gets its own uploaded reference; logical item identity is preserved.
`Result.EffectiveValues` exposes accepted target values, and
`Result.Content("/canonical/item/path")` returns detached effective body bytes.
Compaction instructions and summaries have fixed canonical bindings. When
instructions are absent, `WithCompactionInstructions` supplies a host-owned
descriptor template; the SDK does not invent one. A returned compaction summary
is only a pending candidate, not installed context.

Ambiguous native targets require `WithModificationTarget(target, binding)`.
`ModificationTarget.Path` selects an allowed canonical descriptor, collection,
or model-request `/params`. Collection effects always contain an array, even
for zero or one item; additions require host-owned `Templates`. These bindings
are an SDK mapping contract, not additional protocol wire fields.

Elicitation request results retain an immutable `Snapshot` of the original
exchange. Pass it with `WithElicitationRequest(result.Snapshot)` for the
corresponding result boundary. Answer validation uses the pinned MCP schemas
and original requested form schema, without network schema loading. Correlation
is checked before body resolution. URL acceptance is consent, not evidence of
completion. AHP mode support is independent of effect support: `return`, `deny`,
and result `modify` require the matching explicit `capabilities.elicitation.form`
or `.url` grant. An absent mode or empty AHP elicitation object grants nothing;
MCP's legacy empty-object form fallback does not apply. Passive delivery and
informational `message` effects do not decide or alter the interaction and do not
require this decision-mode grant. Application schemas for ordinary tools remain
the host's concern.

### Receiving hooks

`server.NewHandler` returns an ordinary `http.Handler` with intercept, observe,
and capabilities callbacks. Mount it in an application-owned mux and use normal
HTTP authentication middleware. `server.ServeStdio` adapts owned input/output
streams to the **same handler**; it is not a second protocol engine or backend
registry. The application still owns listener startup, admission policy, and
shutdown. Callback errors are redacted; notifications never receive JSON-RPC
replies.

### Content and authentication

Configure one harness-owned `Options.AuthProvider` implementing `auth.Provider`.
`Credential` receives the full selected authentication binding, backend identity,
exact destination, event/upload purpose, and operation context. `Challenge` receives
actual 401 response headers and the opaque `Credential.Attempt` identity; secrets
never appear in diagnostics. The provider owns discovery/trust, login/consent,
exchange, refresh/rotation, coordination and persistence. Hooks neither starts
a browser nor closes the provider. Without a provider, only bearer `tokenEnv`
resolution is built in; missing secrets and unsupported configured mechanisms
fail closed. An absent binding starts anonymously; an explicitly supplied provider
may authorize recovery from an actual challenge according to host trust policy.

Event and upload bindings remain independent: uploads never inherit event
credentials. Authenticated interceptor delivery permits one challenge retry with
the same request identity/body and remaining context budget. Notifications and
uploads are not replayed. Redirects are never followed. Existing separately scoped
`auth` transports and `EventTransportResolver` remain advanced compatibility paths;
deployment-specific TLS/workload mechanisms stay transport-owned. Borrowed HTTP
clients are never closed.

Content selection does not grant access. `client.ContentOptions` supplies
receiver-scoped disclosure decisions and host-owned content resolution. The
zero value does not disclose bodies or opaque application payloads; provide an
explicit projection policy for tool inputs and other opaque fields. Resolver
references are opaque handles, not URLs the SDK automatically fetches. Selected
uploads complete before delivery and hash the original bytes. Metadata-only
delivery does not itself read bodies; preparing advertised descriptor-backed
modifications or validating an elicitation exchange can require verified host
bodies regardless of receiver selection. Upload credentials are never inferred
from event credentials.

For an unread stream, `content.NewSource(io.ReadCloser)` (also
`client.NewContentSource`) transfers ownership when bound to a boundary. Construction
performs no reads. Only an authorized selected body snapshots bytes, within the
configured limit, computes actual size/SHA-256 and uploads independently to each
receiver before publishing its event. Fan-out reuses the immutable snapshot. Unused,
failed and cancelled sources are closed, and a source cannot be reused across
occurrences. Reader `Close` must unblock a pending `Read`. Original source snapshots
and rewritten prepared bodies each have an aggregate `MaxContentBytes` bound;
together they can retain twice that limit, plus bounded delivery copies. Advanced callers may
bind canonical slots with `client.WithContentSource`; wire references/resolvers
remain available for already prepared content.

On the receiver, upload parsing verifies declared size and digest only at
successful EOF. Early close or a failed read cannot yield a verified reference.
The application authorizes scope, stages and commits immutable storage, allocates
the receiver reference, and only then writes the upload response. The SDK does
not provide a content store or infer publication from verification.

## Development

```sh
git clone https://github.com/agenthooksprotocol/agent-hooks-protocol.git
git clone https://github.com/agenthooksprotocol/go-sdk.git
cd go-sdk
gofmt -w .
go vet ./...
go test ./...
```

The interoperability adapters and tests use the sibling protocol checkout's
canonical schemas, shared scenarios, and public test certificates. During
coordinated changes, `AHP_INTEROP_FIXTURE_ROOT` can point lifecycle/observation
tests at the pinned protocol checkout's `interop` directory; its expectations
are used unchanged. CI pins the
generator and fixture revision and checks this SDK's bundled schema snapshot. See
[the adapter guide](interop/README.md) and [lifecycle guide](interop/LIFECYCLE.md)
for transport, authentication, upload, and synthetic-host boundaries.

Generated code lives in `generated.go`, semantic-package `generated.go` files, and `client/boundaries_generated.go`. Its provenance is recorded in `ahp-codegen.lock.json`; schema changes are made in the [protocol repository](https://github.com/agenthooksprotocol/agent-hooks-protocol), not by editing the generated file.

The generator source is protocol commit `7a3353d92c14514215cc092a930685b0947f0bc1`. From a protocol checkout at that commit, regenerate and verify with:

```sh
python3 tools/generate_sdk.py --go-sdk ../go-sdk
python3 tools/generate_sdk.py --go-sdk ../go-sdk --check
```

## License

Apache-2.0
