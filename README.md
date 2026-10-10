# Agent Hooks Protocol SDK for Go

The draft provides MCP-aligned elicitation, automatic short-circuit
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
  `Result.Errors` lists interception failures.
  `Result.Permission` is the canonical settled permission: `none` is not approval,
  `ask` requires host approval, and interruption always prevents execution.
  Each `DeliveryError.Code` is a typed `DeliveryCode`: `protocol_rejection`,
  `remote_rpc`, `transport`, `cancelled`, `deadline_exceeded`, `preparation`, or
  `capacity`. `Stage` identifies the phase, and `FailClosed` identifies
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
  the settled decision. `Observations` is an already-completed handle. Hosts own
  concurrency: run the whole call in a goroutine and retain its result; never execute a gated operation before obtaining its decision.
- The call's `context.Context` bounds queue waits, content preparation/uploads,
  authentication, event delivery, retries and observations with one remaining
  budget. Backend deadlines can shorten that budget, never reset it. Cancellation
  stops new work and retires owned I/O; safety cleanup may outlast the deadline.
- `Close` rejects new work, cancels active calls, waits for owned resource retirement
  and reaps subprocesses. Concurrent/repeated calls wait for the same completion
  and return the same outcome. Await calls before closing for graceful completion.
  Borrowed HTTP clients and harness-owned auth providers are never closed.

Generated semantic packages (`registration`, `transport`, `subscription`,
`effect`, `content`, `capability`, `event`, and `tool`) construct the
wire types. Constructors fill schema literals and annotated defaults; parsers
preserve presence and never invent omitted required fields. The
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

The JSON document uses the `ahp.Registration` wire model: backend
routes, modes, deadlines, failure policies, content selections, and upload
endpoints are registration data. The event map grants no effects or elicitation support beyond the supplied
declaration. `capability.Intercept` deliberately advertises both intercept and
observe modes; `capability.Observe` advertises only observe. Include
`capability.ElicitationForm()` explicitly when advertising form decisions.
`Options.Manifest` is available for advanced full-manifest metadata;
provide it instead of `Events`, not together with it. `client.Client` aliases `Hooks`.

See the executable [JSON registration and typed boundary example](client/example_hooks_test.go),
[generated constructor examples](facade_generated_test.go), and
[public HTTP tests](client/public_http_test.go). The compiled example includes
initial state, capability narrowing, decode-error handling, observation drain,
shutdown, and a standard owned-stream stdio server. The compiled
[resolved-content walkthrough](public_protocol_completion_test.go) shows verified
inline `TextParts` instructions, accepted list replacement, verified attachment
bytes, explicit receiver authorization, and independent upload routes alongside
the receiving HTTP handlers.

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
fields are typed; optional fields use `ahp.Some(value)`, including `ID` and
`ParentEventID`. Zero optional values mean absent, not an explicit null.
The generated marshaler restores canonical nested wire fields. Use root `ahp`
wire models and parsers for decoding protocol JSON, not ergonomic input structs.
Advanced dynamic callers can use `Hooks.Dispatch(ctx, eventType, input, options...)`
with canonical host fields, excluding SDK-owned `type`, `source`, and `manifest`.
Canonical fixture adapters use this path instead of duplicating generated mappings.
The SDK owns the protocol envelope and fills permitted identity fields; callers
supply required occurrence and application data.

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

Construction is not event admission or execution authorization. Hooks
checks event compatibility, host support, and per-call narrowing. Pass a checked
narrower declaration's dereferenced `Capabilities` to `client.WithCapabilities`.
The lower-level `capability.New` and event-specific wire constructors are
available for advanced declarations.

`state.Initial(permission.None)` returns a pointer to state with no candidate.
`permission.Allow`, `Ask`, `Deny`, and `None` represent native decisions already
made for this occurrence, not a new authorization. Pass the dereferenced result
to `client.WithInitialState`. `state.Candidate(value, provenance...)` encodes a
candidate and returns an error; `state.WithCandidate`, `WithFlow`,
`WithInjections`, and `WithInstructions` supply explicit accumulated state.
`state.NoCandidate` represents an explicit absent candidate. Initial state never
skips host permission, approval, or application-schema validation.

`Nullable[T]` represents JSON null independently of property presence. A required
nullable property uses `Nullable[T]`; an optional one uses `Optional[Nullable[T]]`.
Use `ahp.Null[T]()` for null and `ahp.NonNull(value)` for a non-null value. Check
`Valid` before reading `Value`; `false`, `0`, and empty strings remain non-null
values. For an optional property, check `Present` first: absent, explicit null,
and a non-null value are three different states.

`state.NoCandidate()` encodes `null`, while `state.Candidate(nil)` encodes
`{"value":null}`. Named nullable models, including response IDs, are values rather
than pointers; pass their address to `json.Unmarshal`. Non-null selections whose
payload serializes to null (for example a nil slice or pointer) return an encoding
error. `Nullable[T]` handles null itself and delegates non-null decoding to `T`.

Generated model `UnmarshalJSON` methods and named `Parse*` entrypoints enforce the
same generated **structural** rules: required members, JSON types, literals,
closed enums, nested models, forbidden property combinations, and union matching.
For example, decoding a candidate `{}` fails because `value` is required;
`null` and `{"value":null}` are distinct valid candidate states. Open string
enums and unknown tagged variants are accepted, and supported extension
members are retained. `Parse*` additionally returns structured diagnostics
(including warnings) and the original raw JSON; direct decoding returns an error
for structural failures without a diagnostics collection.

This is not complete canonical JSON Schema validation. The generated IR does not
represent string length/pattern/format, numeric bounds, or all array/object
keywords. Unknown members remain forward-compatible even where the canonical
schema closes objects. Server-side canonical validation and request-dependent
checks are separate. Do not substitute decoding for those checks.

Named primitive models such as `ReverseDnsName` are defined Go types. Convert
string variables explicitly, for example `id := ahp.ReverseDnsName(name)`.
`registration.NewBackend` accepts a string. `ContextCompactBeforeEvent` and
`McpElicitationRequest` are model values. Use `*Model` where your API needs a
pointer; Go accepts JSON null into pointer variables without invoking the
pointed-to model's decoder.

Receiver-side `effect.Modify<Target>Merge(value)` and
`effect.Modify<Target>Replace(value)` accept typed application values for all
nine modification targets above. `effect.Return(value)` and
`effect.InjectContextAppend(effect.Now, value)` (or `effect.NextTurn`) likewise
encode payloads and return `(*ahp.Effect, error)`; check errors before publishing
a response. Simple effects include `NewAllow`, `NewAsk`, `NewDeny`, `NewMessage`,
`NewFlowStop`, and `NewFlowContinue`. Raw `NewModify`, `NewReturn`, and
`NewInjectAppend` are advanced wire helpers. These constructors neither grant
capabilities nor establish that a payload satisfies the host application's schema.

Generated host inputs accept canonical messages with a role and ordered parts.
Use `event.ContentPartInput.Text` for inline text and
`event.ContentPartInput.Attachment` for an owned binary body. Encoding does not
read attachment bytes. Explicit host authorization, receiver disclosure policy,
size limits, and source ownership rules apply.

### Current composition coverage

The client composes object-valued input and workspace modifications, canonical
message and text-part list modifications, protocol permission/candidate decisions,
messages, injections, and bounded flow effects. Invalid capability grants fail
before delivery. Output modifications operate on `tool.after.items` as canonical
message lists. Application structures are serialized as inline text, not exposed
as native JSON output fields.

Attachments remain immutable across edits. Selected receivers receive their own
uploaded reference to the exact owned attachment. `Result.EffectiveValue(target)`
encodes accepted canonical target values on demand, and
`Result.Content("/canonical/item/path")` returns detached available attachment bytes.
Canonical message-list modifications use `merge` to append in order, preserving
duplicates, and `replace` to substitute the list. Text-part lists use the same
operations. Compaction instructions and summaries contain inline text parts.
Supplied compaction results contain a text-part list; supplied model results
contain a canonical message list. A returned summary is a pending candidate,
not installed context.

Elicitation request results retain an immutable `Snapshot` of the original
exchange. Pass it with `WithElicitationRequest(result.Snapshot)` for the
corresponding result boundary. Answer validation uses the pinned MCP schemas
and original requested form schema, without network schema loading. Correlation
is checked before body resolution. URL acceptance is consent, not evidence of
completion. AHP mode support is independent of effect support: `return`, `deny`, and result `modify`
require the matching explicit `capabilities.elicitation.form`
or `.url` grant. An absent mode or empty AHP elicitation object grants nothing;
MCP's empty-object form fallback does not apply. Passive delivery and
informational `message` effects do not decide or alter the interaction and do not
require this decision-mode grant. Application schemas for ordinary tools remain
the host's concern. At `user.elicitation.result`, `content` modifications operate on
the accepted form MCP answer object and preserve its result wrapper. At
`user.message.outbound`, `content` modifications operate on canonical message lists.

### Receiving hooks

`server.NewHandler` returns an ordinary `http.Handler` with intercept, observe,
and capabilities callbacks. Mount it in an application-owned mux and use normal
HTTP authentication middleware. `server.ServeStdio` adapts owned input/output
streams to the **same handler**; it is not a second protocol engine or backend
registry. The application owns listener startup, admission policy, and
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

Event and upload bindings are independent: uploads never inherit event
credentials. Authenticated interceptor delivery permits one challenge retry with
the same request identity/body and remaining context budget. Notifications and
uploads are not replayed. Redirects are never followed. Separately scoped
`auth` transports and `EventTransportResolver` support custom transport configuration;
deployment-specific TLS/workload mechanisms stay transport-owned. Borrowed HTTP
clients are never closed.

Content selection does not grant access. `client.ContentOptions` supplies
receiver-scoped disclosure decisions and host-owned content resolution.
`ContentAuthorization.Operation` is `"read"` for disclosure and `"write"` for
new or changed inline text. Authorize these operations explicitly in
`AuthorizeContent`; permitting a read does not permit a write. Incoming canonical
text requires body selection for its content category and explicit write
authorization. List replacement cannot overwrite receiver-hidden text. The
zero value does not disclose bodies or opaque application payloads; provide an
explicit projection policy for tool inputs and other opaque fields. Resolver
references are opaque handles, not URLs the SDK automatically fetches. Selected
uploads hash the original bytes. Before the first interceptor, Hooks plans all
matched, authorized attachment-body transfers and waits for their confirmed
receipts. `client.Options.MaxConcurrentUploads` bounds transfers across calls on
the same Hooks instance: zero uses the default of 8; negative values are invalid.
Interceptors still run in registration order. Upload failures follow the affected
subscription's failure policy when its delivery is reached; observation failures
do not change the settled decision.

Confirmed references are reused for the same attachment owner, backend, and
subscription during serial projection and settled observations. Sharing an
upload URL does not share references or credentials between receivers. A later
interceptor can remove an attachment after its planned upload; that upload is
not undone. Metadata-only delivery does not itself read bodies, and attachment
bodies with no authorized body demand remain unread. Inline text is projected
without uploads;
validating an elicitation exchange can require verified host bodies regardless
of receiver selection. Upload credentials are never inferred from event credentials.

### Owned attachments

Use `content.NewAttachment(data)` for a defensive copy of a byte slice, or
`content.NewLazyAttachment(open, cleanup)` for a context-aware reader factory.
`content.NewSource(reader)` (also `client.NewContentSource`) takes ownership of
an already opened reader. All three construct the same owned body type. Bind it
directly through the generated host input API:

```go
attachment := content.NewAttachment(pdfBytes)
messages := []*event.ModelVisibleItemInput{{
    ModelVisibleItem: ahp.ModelVisibleItem{ID: "review-1", Role: ahp.ModelVisibleItemRoleUser},
    Parts: []*event.ContentPartInput{
        {Text: &ahp.TextBodyPart{ID: "request-text", Text: "Review this report."}},
        {Attachment: &event.AttachmentBodyInput{
            AttachmentBodyPart: ahp.AttachmentBodyPart{ID: "report", MediaType: "application/pdf"},
            Body: attachment,
        }},
    },
}}
result, err := hooks.ModelRequestBefore(ctx, event.ModelRequestBeforeInput{
    Attempt: &ahp.ExecutionEventAttempt{ID: "attempt-1", Number: json.Number("1")},
    Model: &ahp.ExecutionEventModel{ID: "model-1", Provider: "example"},
    ItemsHost: &messages,
})
if result != nil { defer result.Close() }
if err != nil { return err }
// Check interruption and the settled decision before sending the model request.
```

Configure the `model.request.before` event grant and receiver content selections
on `hooks`. Metadata-only selection does not open a lazy attachment. See the
[standalone file example](examples/attachments/main.go). `WithContentSource` is
an advanced binding for a canonical part path, not needed for generated host inputs.

The attachment is the **sole byte owner**. Selection uploads borrow its immutable
buffer; successful results retain the same owner.
Lazy factories run at most once on actual body demand. Metadata-only/no-match
delivery does not open them. `MaxContentBytes` bounds materialization and live
attachment accounting; per-receiver upload limits are enforced separately.
Public reads return defensive copies, never shared mutable backing bytes.

Always `defer result.Close()` when an invocation returns a non-nil result.
`result.ReadContent(ctx, path)` evaluates unread content and works after invocation
completion and `Hooks.Close`. `result.Content(path)` reads only an already
materialized owner. Closing results disposes unopened sources and interrupts
active reads. Factories must honor their context and must not depend on resources
owned by Hooks; reader `Close` must unblock `Read`. Optional factory cleanup runs
once, including when unopened, and waits for active opening to finish. Admission
failure, cancellation and timeout retire invocation-owned resources.

An attachment may serve multiple slots and receivers in one invocation, but
cannot be reused across invocations. The optional `ContentOptions.Resolver`
converts a supplied external reference into a lazy attachment at its canonical
slot. Direct attachment bindings do not require a resolver.

Canonical list modifications preserve existing immutable attachment descriptors;
attachment bytes cannot be edited or replaced by an effect. MCP
elicitation snapshots retain the parsed original form contract for validating
the corresponding result boundary.

`Result.EffectiveValue(target)` and `Composition.EffectiveValue(target)` encode
available target values on demand. They do not open unread sources; use
`Result.ReadContent` to demand a body first. Call `Source.Close` to dispose a
source that is never submitted.

On the receiver, upload parsing verifies declared size and digest only at
successful EOF. Early close or a failed read cannot yield a verified receipt.
The application authorizes scope, stages and commits immutable storage, allocates
the receiver reference, and only then writes the upload response. The SDK does
not provide a content store or infer publication from verification.

`upload.Receipt(ref)` returns a `ContentUploadReceipt` with `ref`, `size`, and
`sha256` for `server.WriteUploadResponse`. Use `content.ReferenceFromReceipt(receipt)`
to explicitly construct the ref-only `ContentReference` carried by events. Body-selected
items do not carry outer size or digest metadata; metadata-only items and gaps may
disclose it. Resolve references within authenticated storage scope, not by trusting
event-provided lengths or hashes. Upload framing and receipt verification
check the exact bytes sent.

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

The generator source is protocol commit `9dc64148502ec3f9e16858025887a5dfd6241820`. From a protocol checkout at that commit, regenerate and verify with:

```sh
python3 tools/generate_sdk.py --go-sdk ../go-sdk
python3 tools/generate_sdk.py --go-sdk ../go-sdk --check
```

## License

Apache-2.0

### Typed composed payloads

Composed MCP transport payloads are typed models.
For example, `ExecutionEventMcpConnection.HTTP` contains
`Optional[ExecutionEventMcpConnectionHTTP]`; its `URL` and `Gaps` fields expose
strings and typed gap records. `Sse`, `Stdio`, and `CustomTransport` similarly
expose their schema-declared location fields. `ModelVisibleItem` exposes a canonical
`Role` and ordered `Parts` with typed content variants.

The structural decoder checks presence predicates such as “URL or gaps”; optional
Go fields are not permission to omit every alternative. Genuine application JSON, unknown variants, and extension values
use raw JSON for round-trip preservation.

### Go capability queries

Go exposes `req.Params.Capabilities.Supports(ahp.EffectDeny)` and
`capabilities.Supports(ahp.EffectName("vendor.custom"))`. The generated
`EffectNameDeny`, `EffectNameModify`, and the other `EffectName*` constants
identify effect families; `EffectDeny` aliases `EffectNameDeny`. Queries inspect
typed fields without serialization and accept the known and custom string representations.
Capability grant builders use the same family membership query for deduplication.

`Supports` reports only advertised family membership: it does not authorize
execution or imply a target, operation, delivery mode, or per-call grant. A nested
modify grant without the `modify` family returns false; a `modify` family alone
does not grant any modification operation. Use grant builders and host/request
validation for operation constraints.
