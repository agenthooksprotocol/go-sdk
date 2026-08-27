# Agent Hooks Protocol Go SDK

Official, non-normative Go models and structural codecs for the [Agent Hooks Protocol](https://github.com/agenthooksprotocol/agent-hooks-protocol).

> [!WARNING]
> A successful structural parse is not canonical schema validation and must not be used alone for authorization or response classification. Validate security-sensitive messages against the canonical Draft 2020-12 schemas.

## Development

```sh
gofmt -w .
go vet ./...
go test ./...
```

`generated.go` and `ahp-codegen.lock.json` are maintained by schema-sync automation. Do not edit them manually.
