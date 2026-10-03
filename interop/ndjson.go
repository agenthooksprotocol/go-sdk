package interop

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ndjson preserves JSON values while removing physical newlines and indentation.
// Validation is separate: malformed JSON must never become multiple wire frames.
func ndjson(raw []byte) ([]byte, error) {
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, fmt.Errorf("invalid JSON frame")
	}
	compact.WriteByte('\n')
	return compact.Bytes(), nil
}
