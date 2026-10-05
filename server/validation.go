package server

import canonicalpkg "github.com/agenthooksprotocol/go-sdk/internal/canonical"

func canonical(kind string, data []byte) bool {
	return canonicalpkg.Validate(kind, data) == nil
}
