package server

import (
	"encoding/json"
	"errors"

	ahp "github.com/agenthooksprotocol/go-sdk"
	canonicalpkg "github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

// snapshotConfiguration detaches caller-owned slices and maps before serving.
// RawMessage preserves exact numeric settings and unknown extension fields.
func snapshotConfiguration(configuration *ahp.Configuration) (json.RawMessage, error) {
	if configuration == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(configuration)
	if err != nil || canonicalpkg.Validate("configuration", encoded) != nil {
		return nil, errors.New("server: invalid configuration")
	}
	return json.RawMessage(encoded), nil
}
