# Catalogue, lineage and registration adapter

Use the existing lifecycle client/server commands with `suite: "catalogue"`.
Unknown suites and operations fail. The default lifecycle suite retains its
cancellation and upload behavior. HTTP none/bearer/OAuth/workload/mTLS and trusted
stdio use the same authentication, framing and cleanup implementations.

## Actual protocol exchanges

The client sends one canonical `hooks/capabilities` request over HTTP POST
`/capabilities` or stdio. The server validates it and returns a canonical response
with the same RPC ID. Both the client report's `discovery` and the receiver's
`discovery` receipt retain the actual response; the receipt also retains the
actual request. Registration consumes this received manifest, not fixture data.

This synthetic catalogue host advertises observe support for the 17 Execution
and five task/workspace/file event types. It additionally advertises supported
`tool.before` interception effects. Flow at that boundary is stop-only; continuation
is not advertised there. `hook.failure` is explicitly unsupported. Policy scopes
are user/project and disableable; managed enforcement is not claimed. Discovery
contains no self-asserted principal or identity evidence.

`notify` validates the complete supplied native-settled observation through both
the generated Go codec and canonical JSON Schema, checks normalized content
readiness and applies the Go source-local lineage tracker before actual sending.
No fake interception or decision-control message is constructed.

`rawNotify` is deliberately adversarial: it bypasses client-side semantic checks
only, not transport. The receiver validates the actual incoming message normally.
Schema failures return HTTP 400; lineage failures return 409. Stdio notifications
receive no reply. Rejection receipts contain the exact message, event ID and
`errorKind: schema|lineage`; rejected edges do not modify lineage. Valid receipts
contain the exact canonical message and its event metadata; subscription routing
remains local to the harness.

The ordinary `/wait-observed` barrier counts observed or rejected notifications
for synchronization. It does not return semantic decisions. There is no `/view`
endpoint or fixture-ID evaluation. Lineage persists for the entire connection,
including across fixture scenarios and negative probes.

## Go registration evaluator

The evaluator first runs the generated registration codec and canonical schema.
It then checks duplicate backend IDs, advertised transports/auth methods,
subscription event/mode coverage, enforceable policy scopes, and known timeout
limits. Required effects and modification target/operation pairs must be covered
by both a subscription and the actual discovery manifest. `ask` additionally
requires trusted host context `interactive: true`.

Registration content selection must satisfy the current canonical requirement
for explicit `content.default`; the evaluator never silently inserts a default.
The test context's environment can resolve configured bearer `tokenEnv` values.
Unresolved credential references or unprovisioned OAuth/mTLS/workload backend
configuration are rejected, even if the event connection independently succeeded.
The environment is trusted local host input, not a remote principal assertion.
No credential values appear in reports or diagnostics.

The client reports `{accepted: true|false}` from this Go evaluator. Expected
fixture answers are not read by the runtime. Policy endpoints in registrations
are not contacted; actual discovery comes from the connected host.

## Checks

From the workspace root, after shared fixture generation and SDK regeneration:

```sh
python-sdk/.venv/bin/python agent-hooks-protocol/interop/catalogue_matrix.py \
  --client go --server go --workers 2 --timeout 60 \
  --output /tmp/ahp-go-catalogue.json
(cd go-sdk && go test ./... && go test -race ./... && go vet ./...)
```

The self-pair runner covers all five HTTP authentication modes plus trusted stdio.
Local Go tests additionally cover manifest validation, registration rejection,
rejected-edge isolation, synthesized identities, model-response interception,
model-visible item roles, and exact hash length/format. The shared matrices live in the protocol repository.

### Receipt safety

Core interception receipts retain the exact canonical request in `message`,
including authenticated health probes; credentials remain transport headers,
not receipt payload fields.
