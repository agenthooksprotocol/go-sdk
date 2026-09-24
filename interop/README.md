# Go cross-language adapter

This is a **synthetic local test harness**, not a production agent integration.
The launch descriptor is `adapter.json`; run its commands from the SDK root:

```sh
go run ./cmd/interop server --config /absolute/server-config.json
go run ./cmd/interop client --config /absolute/client-config.json
```

The configuration, readiness, control endpoints, and reports follow
`../agent-hooks-protocol/interop/CONTRACT.md`. Both transports carry the complete
canonical JSON-RPC envelope (`hooks/intercept`, not a second wrapper). Stdio
capability discovery uses `hooks/capabilities`; HTTP uses `GET /capabilities`.
Stdio discovery requires `params.protocolVersion: "draft"` and returns the
canonical `result.protocolVersion` plus `result.manifest` envelope, validated by
both generated codecs and canonical schemas. HTTP discovery returns the
capabilities object. No legacy method aliases are accepted. Stdio requests and
responses are compacted into exactly one physical JSON line, including when
source fixtures use multiline pretty-printed JSON.

## Validation and application

- Generated Go codecs plus **live canonical JSON Schema draft 2020-12** validation
  with format assertions. Schemas default to
  `../agent-hooks-protocol/schema/draft` relative to SDK cwd. Set `schemaDir` in
  config or `AHP_SCHEMA_DIR` to use another absolute checkout location.
- Request/event and response correlation checks; unknown/unadvertised effects,
  unsupported modification operations, exhausted continuation allowances, and
  unadvertised injection delivery reject the **whole response**.
- Synthetic tool input supports `modify(input)` replace and shallow merge, with
  literal null and whole nested value replacement. `task`, when initially
  present, must remain a positive integer after each mutation.
- Input modifications precede result binding. Changed input invalidates previous
  candidates and stale allow decisions. Deny wins over ask and allow; ask remains
  pending; return does not bypass either. Messages and injections accumulate only
  after successful staging. Stop wins over continue; multiple continues consume
  one allowance and retain ordered instructions.
- `executed` describes the synthetic pending tool decision. This harness does not
  run shell commands, obtain native interactive approval, or invoke a real model.
  `ask` records an unresolved approval requirement and prevents execution/result
  selection. Injection records represent admitted current/next-turn context; no
  external scheduler is started. Only input modification is advertised.

## Authentication and isolation

HTTP none, bearer, OAuth client credentials, mTLS, and signed workload assertions
are implemented. OAuth calls the configured token endpoint; it does not synthesize
an access token. OAuth/workload verification pins HS256 and verifies signature,
issuer, audience, purpose, issuance, not-before (if supplied), and expiry.
`auth.clock` supports the shared fixed test clock; omitted clock uses wall time.
Signing keys and certificates must be supplied explicitly in server config.
mTLS verifies both peers against the supplied CA and requires a client certificate.
All are local public **TEST ONLY** identities, not production federation support.
Auth checks precede receipt recording and also protect discovery. Reports never
contain auth configuration; receipts may retain canonical messages, never
transport credentials.

Stdio uses process trust; combining HTTP auth with it reports `inapplicable`.
Unknown HTTP auth reports `unsupported`, never passed. Failed transport/discovery
or invalid request cannot satisfy a negative-response scenario. Validated normal
server replies and deliberately malformed negative fixture replies are distinct.

Reads are bounded to 4 MiB, HTTP exchanges to 15 seconds, per-scenario stdio calls
and server barriers to 20 seconds, and the CLI client to three minutes. Explicit
`POST /release` releases named scenario barriers. Clients kill and reap spawned
stdio servers; Unix uses a dedicated process group to include `go run` children.
Non-Unix cleanup currently kills the direct child only. Unix/macOS is the tested
launch environment. HTTP server lifetime is controlled through `/shutdown` or
SIGTERM; the controller must enforce an overall server watchdog.

## Tests

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```

Tests cover generated/canonical rejection, atomic staging/no input mutation,
central scenario application, actual HTTP exchanges under every supported auth
mode, bad credentials/untrusted mTLS rejection without receipts, real OAuth token
acquisition, JWT claim/signature rejection, actual stdio subprocess exchange and
cleanup. Transport tests include all central scenarios when the shared file is
present, plus SDK-local smoke cases.
Without the sibling central file, transport smoke tests still run and the central
application test explicitly skips. Tests require the sibling canonical schemas
and public test-only certificate fixtures. No shared scenarios are edited here.

## Catalogue extension

The lifecycle commands support `suite: "catalogue"` for authenticated Execution
observations, source-local lineage rejection and registration enforcement against
real discovery. See [CATALOGUE.md](CATALOGUE.md) for the wire and test contracts.
