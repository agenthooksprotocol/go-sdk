# Agent Hooks Protocol SDK for Go

The active draft also provides MCP-aligned elicitation, automatic short-circuit
observation delivery, and before/after compaction controls. See the shared
[boundary API guide](https://github.com/agenthooksprotocol/agent-hooks-protocol/blob/main/docs/accepted-boundary-apis.md)
for entrypoints, upload binding, trusted-host obligations, and test scope.

Typed Go models and JSON codecs for the [Agent Hooks Protocol (AHP)](https://github.com/agenthooksprotocol/agent-hooks-protocol).

The SDK follows the current AHP `draft` schema snapshot and supports Go 1.22 or newer.

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
canonical schemas, shared scenarios, and public test certificates. CI pins the
fixture revision and validates against this SDK's bundled schema snapshot. See
[the adapter guide](interop/README.md) and [lifecycle guide](interop/LIFECYCLE.md)
for transport, authentication, upload, and synthetic-host boundaries.

Generated code lives in `generated.go`. Its provenance is recorded in `ahp-codegen.lock.json`; schema changes are made in the [protocol repository](https://github.com/agenthooksprotocol/agent-hooks-protocol), not by editing the generated file.

## License

Apache-2.0
