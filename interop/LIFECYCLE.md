# Go lifecycle integration adapter

Run from `go-sdk`:

- `go run ./cmd/lifecycle-server --config ABS_PATH`
- `go run ./cmd/lifecycle-client --config ABS_PATH`

## Observations

Observers receive the permission-filtered effective event with the same logical
event ID and no generic disposition or decision summary. Subscription identifiers
are harness-local routing metadata, never fields in protocol messages.
After short-circuiting, remaining uncalled matching intercept subscriptions get
`hooks/observe` under their existing permissions and selections. Already-called
interceptors get no automatic second copy; explicit observation subscriptions
remain independent. Interruption ends pending decisions immediately and does not
wait for observer uploads or processing. Upload readiness precedes each delivered
notification. There is no downgrade flag or `/view` fallback.

The receiver validates the complete notification and retains it unchanged as
`message` in its observed receipt, alongside event ID and event.
There is no `/view` endpoint or semantic oracle. `/mark`, `/wait`, `/release`,
`/wait-observed`, receipts and adversarial `/emit` are test rendezvous only.
Observers cannot change settlement; the deliberately malicious observer reply
in this test adapter is ignored by the client.

## Raw binary upload binding

`UploadContent(ctx, binding, subscription, ref, []byte)` posts raw octets to the
exact configured `binding.endpoint`, including path/query. HTTPS is required
except explicit IP-loopback HTTP test endpoints. Redirects are never followed.
The request has exact `Content-Length`, `application/octet-stream`, and
`AHP-Content-SHA256` over the exact bytes. The receiver allocates an immutable
reference and returns HTTP 201 with JSON `{ref,size,sha256}`. The sender validates
the descriptor against the uploaded byte count and digest before publishing any
dependent event. Subscription identifiers and sender-chosen references are not
upload headers. JSON, base64 wire bodies, chunking and content encoding are not
upload transports.

The shared lifecycle adapter configuration uses:

```json
{
  "upload": {
    "endpoint": "https://content.example.test/bytes?scope=one",
    "timeoutMs": 5000,
    "maxBytes": 1048576,
    "auth": {"type": "bearer", "tokenEnv": "AHP_INTEROP_UPLOAD_TOKEN"}
  }
}
```

The synthetic receiver has independent `uploadAuth: {token}` configuration and
advertises its absolute raw `uploadEndpoint` in readiness. That credential grants
the receiver's single content scope. Optional `subscriptions` are local policy
grants; an explicitly empty list denies upload access. No scope is inferred from
JSON-RPC IDs or message fields.
Stdio clients obtain that address from their child readiness; HTTP clients use
an explicit configured endpoint. No event credentials are inherited. Normal
upload APIs enforce configured maximum bytes and timeout. Negative fixture
framing can deliberately mismatch declared size/hash to exercise the receiver;
only the actual HTTP response counts as rejection evidence.

The per-subscription `uploads` map and optional `contentSelections` map remain
available for local explicit policies. Upload map entries without auth explicitly
permit anonymous access. Missing policy does not grant access. These optional
maps are not required by the matrix configuration.

Fixture upload steps require `bodyBase64`, decoded once to bytes before calling
the binary API. This is fixture encoding, not HTTP framing. The client tracks
successful confirmations and resolves local fixture aliases to receiver-assigned
references. Both observe and intercept references require matching byte count
and digest. Receivers independently enforce integrity and credential-derived
authorization, unrelated to JSON-RPC correlation IDs. Repeated uploads allocate
new immutable references. Storage is retained for this connection/process,
without expiry.

Content projection is per subscription. Category overrides media classification,
except reasoning always selects reasoning. Metadata removes body references;
omit removes descriptors. Selection cannot grant body permission or manufacture
missing content. Omitted `contentSelections` means the fixture supplies already
selected descriptors, still subject to upload authorization/readiness checks.
Opaque native data is not used to validate normalized content descriptors.

## Evaluator and lineage

Capabilities gate each effect, modification operation, injection delivery, and
flow operation. A bad effect rejects the whole staged response. Modifications
precede permission/result settlement; changed input invalidates a prior candidate
and prompt suppression. Deny beats ask, ask beats allow. The synthetic host's
optional `state.nativePermission` controls its native default; absent policy is
permissive in this adapter, not a production authorization claim. Applicable ask
survives a later allow, and native denial cannot be overridden. Multiple
continuations consume one allowance, accumulate instructions, and lose to stop.
Serial responses preserve already accepted flow, injection queues and continuation
instructions. A previously reserved continuation is not charged again on a later
response; an accepted stop cannot be cleared by an empty response. Queues are
cloned before staging, so a rejected response cannot mutate the accepted prefix.
Go settlement uses a serialized controller and a pure evaluator with no external
callbacks; cancellation cannot reenter publication through native authorization.
The real lifecycle regression verifies that post-publication interruption retains
accepted input, stop, injections and instructions while emitting interrupted.

Task/workspace/file payloads use canonical schemas rather than loose dictionaries
as validation contracts. Receivers additionally use Go `TaskLineage` to reject
source-local identity changes, cycles including late parent edges, mismatched
before/after task identity or operation, and actual no-op changes. Unknown parents
are valid for subscribers; producers can enable `RequireKnownParents`. No active
parent lifetime or fabricated before event is required. Task status values remain
native/open. Indivisible multi-task changes remain unresolved in the wire design.

This remains a synthetic interoperability host: no durable persistence, physical
backend cancellation, actual native agent execution, or production storage claim.
Lifecycle and core event transports both support HTTP none, bearer, OAuth,
workload identity, and mTLS using the same authentication implementation. Stdio
is process-trusted and rejects configured HTTP authentication. Upload bearer auth
is independently configured and works even with stdio events. Child process groups are killed and reaped on exit.

## Checks and integration dependency

```sh
go test ./interop -run 'TestObservationDisposition|TestBinaryUploadBinding|TestTaskLineage|TestPermissionAndAtomicFailure|TestLifecycleStdioCorrelation|TestContentProjection|TestCanonicalSettledTypedMessages|TestEffectiveOperationRequiresNativePolicy|TestCanonicalEvaluatorScenarios' -count=1
go test -race ./interop -run 'TestObservationDisposition|TestBinaryUploadBinding|TestTaskLineage|TestContentProjection' -count=1
go test ./...
```

Tests cover all five lifecycle HTTP authentication modes and process-trusted
stdio, exact intercepted/observed message capture, malformed raw upload framing,
and independent upload credentials.

Task/workspace before boundaries can settle a native default or denial; allow
and ask effects are not advertised there. No native task/workspace mutation or
supplied-result capability is claimed. Unsupported operations are rejected even
if a forged request claims support. Core static discovery lists the synthetic
tool and finish boundaries with gaps for other native application behavior.
The separate [catalogue suite](CATALOGUE.md) advertises typed observation coverage
and evaluates registrations against an actual discovery response.


Sender credential isolation is tested with an authenticated event connection and
a separate real anonymous upload receiver. With upload auth omitted, the receiver
captures no Authorization header and retains the exact raw bytes. This proves
sender noninheritance in addition to receiver rejection of incorrect credentials.

### Serial-chain wire coverage

Shared `chain` fixtures execute actual adapter transport calls, then automatically
notify remaining uncalled intercept subscriptions and explicit observers after
settlement. Cases cover deny/stop/compound deny+stop, fail-open continuation,
fail-closed short-circuiting, native observation, effective input, content
metadata/omit projection, and already-called subscription suppression. The held
observer-processing probe verifies interruption does not wait for observation
responses. See the protocol repo's `spec/draft/observation-disposition.md` and
`interop/observation-chain-scenarios.json`; helper unit tests alone are not this
integration evidence.
