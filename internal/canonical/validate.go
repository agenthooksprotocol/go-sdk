// Package canonical validates protocol documents against bundled draft schemas.
// It never resolves remote schema references or validates application schemas.
package canonical

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"sync"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// schemas.json is emitted by the SDK generator from canonical source artifacts.
//
//go:embed schemas.json
var schemaData []byte

var schemas = sync.OnceValues(func() (map[string]*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true
	compiler.LoadURL = func(string) (io.ReadCloser, error) { return nil, errors.New("unavailable bundled schema") }
	var docs []json.RawMessage
	if err := json.Unmarshal(schemaData, &docs); err != nil {
		return nil, err
	}
	for _, doc := range docs {
		var metadata struct {
			ID string `json:"$id"`
		}
		if err := json.Unmarshal(doc, &metadata); err != nil {
			return nil, err
		}
		if err := compiler.AddResource(metadata.ID, bytes.NewReader(doc)); err != nil {
			return nil, err
		}
	}
	roots := []string{"registration", "capabilities", "intercept-request", "intercept-response", "observe-notification", "capabilities-request", "capabilities-response", "content-reference", "content-upload", "content-item", "common"}
	out := make(map[string]*jsonschema.Schema, len(roots)+5)
	for _, name := range roots {
		s, err := compiler.Compile("https://agenthooksprotocol.org/schemas/draft/" + name + ".schema.json")
		if err != nil {
			return nil, err
		}
		out[name] = s
	}
	for _, name := range []string{"request", "notification", "successResponse", "errorResponse", "jsonRpcId"} {
		s, err := compiler.Compile("https://agenthooksprotocol.org/schemas/draft/common.schema.json#/$defs/" + name)
		if err != nil {
			return nil, err
		}
		out[name] = s
	}
	for _, name := range []string{"request", "result"} {
		s, err := compiler.Compile("https://agenthooksprotocol.org/schemas/draft/mcp-elicitation.schema.json#/$defs/" + name)
		if err != nil {
			return nil, err
		}
		out["mcp-elicitation#"+name] = s
	}
	return out, nil
})

// Load compiles bundled schemas once without network access.
func Load() error { _, err := schemas(); return err }

// Validate checks exactly one UTF-8 protocol JSON document. Errors deliberately
// exclude payload values and schema-validation internals from public diagnostics.
func Validate(kind string, data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("protocol JSON is not UTF-8")
	}
	all, err := schemas()
	if err != nil {
		return errors.New("bundled protocol schemas unavailable")
	}
	schema, ok := all[kind]
	if !ok {
		return errors.New("unknown protocol document kind")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid protocol JSON")
	}
	if schema.Validate(value) != nil {
		return errors.New("invalid " + kind + " protocol document")
	}
	return nil
}

// ValidateFormAnswer checks the pinned MCP primitive form vocabulary, not arbitrary
// application JSON Schema. It never resolves $schema or applies default values.
func ValidateFormAnswer(schema, value any) error {
	bad := errors.New("invalid MCP form answer")
	// Validate the vocabulary first; callers cannot smuggle arbitrary schemas into
	// this evaluator. Round-trip with UseNumber to retain exact numeric bounds.
	raw, err := json.Marshal(map[string]any{"message": "", "requestedSchema": schema})
	if err != nil || Validate("mcp-elicitation#request", raw) != nil {
		return bad
	}
	var request map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&request) != nil {
		return bad
	}
	raw, err = json.Marshal(value)
	if err != nil {
		return bad
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return bad
	}
	form := request["requestedSchema"].(map[string]any)
	content, ok := value.(map[string]any)
	if !ok {
		return bad
	}
	if required, ok := form["required"].([]any); ok {
		for _, key := range required {
			if _, exists := content[key.(string)]; !exists {
				return bad
			}
		}
	}
	properties, _ := form["properties"].(map[string]any)
	for key, field := range properties {
		if submitted, present := content[key]; present && !validFormField(field.(map[string]any), submitted) {
			return bad
		}
	}
	return nil
}

func formNumber(value any) *big.Rat {
	n, ok := value.(json.Number)
	if !ok {
		return nil
	}
	r, ok := new(big.Rat).SetString(string(n))
	if !ok {
		return nil
	}
	return r
}

func formBounds(n *big.Rat, field map[string]any, minimum, maximum string) bool {
	if lo := formNumber(field[minimum]); lo != nil && n.Cmp(lo) < 0 {
		return false
	}
	if hi := formNumber(field[maximum]); hi != nil && n.Cmp(hi) > 0 {
		return false
	}
	return true
}

func validFormField(field map[string]any, value any) bool {
	switch field["type"] {
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number", "integer":
		n := formNumber(value)
		return n != nil && (field["type"] != "integer" || n.IsInt()) && formBounds(n, field, "minimum", "maximum")
	case "string":
		s, ok := value.(string)
		if !ok || !formBounds(big.NewRat(int64(utf8.RuneCountInString(s)), 1), field, "minLength", "maxLength") {
			return false
		}
		if format, ok := field["format"].(string); ok {
			check := jsonschema.Formats[format]
			if check == nil || !check(s) {
				return false
			}
		}
		return formEnum(field, s)
	case "array":
		values, ok := value.([]any)
		if !ok || !formBounds(big.NewRat(int64(len(values)), 1), field, "minItems", "maxItems") {
			return false
		}
		items := field["items"].(map[string]any)
		for _, value := range values {
			s, ok := value.(string)
			if !ok || !formEnum(items, s) {
				return false
			}
		}
		return true
	}
	return false
}

func formEnum(field map[string]any, value string) bool {
	if choices, ok := field["enum"].([]any); ok {
		found := false
		for _, choice := range choices {
			if choice == value {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	for _, keyword := range []string{"oneOf", "anyOf"} {
		if choices, ok := field[keyword].([]any); ok {
			matches := 0
			for _, choice := range choices {
				if choice.(map[string]any)["const"] == value {
					matches++
				}
			}
			if matches == 0 || (keyword == "oneOf" && matches != 1) {
				return false
			}
		}
	}
	return true
}
