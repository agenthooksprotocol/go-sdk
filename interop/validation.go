// Package interop implements the synthetic cross-language pending-boundary adapter.
package interop

import (
	"encoding/json"
	"fmt"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"os"
	"path/filepath"
)

type Object = map[string]any

func obj(v any) Object  { m, _ := v.(map[string]any); return m }
func str(v any) string  { s, _ := v.(string); return s }
func array(v any) []any { a, _ := v.([]any); return a }
func has(xs any, value string) bool {
	for _, x := range array(xs) {
		if x == value {
			return true
		}
	}
	return false
}
func clone(v any) any { b, _ := json.Marshal(v); var x any; _ = json.Unmarshal(b, &x); return x }

type Validator struct{ schemas map[string]*jsonschema.Schema }

func NewValidator(dir string) (*Validator, error) {
	if dir == "" {
		dir = os.Getenv("AHP_SCHEMA_DIR")
	}
	if dir == "" {
		dir = "../agent-hooks-protocol/schema/draft"
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat = true
	entries, err := filepath.Glob(filepath.Join(dir, "*.schema.json"))
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("canonical schemas unavailable")
	}
	for _, path := range entries {
		b, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		var s Object
		if e = json.Unmarshal(b, &s); e != nil {
			return nil, e
		}
		f, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		e = c.AddResource(str(s["$id"]), f)
		f.Close()
		if e != nil {
			return nil, e
		}
	}
	v := &Validator{schemas: map[string]*jsonschema.Schema{}}
	for _, name := range []string{"intercept-request", "intercept-response", "capabilities", "capabilities-request", "capabilities-response", "registration"} {
		s, e := c.Compile("https://agenthooksprotocol.org/schemas/draft/" + name + ".schema.json")
		if e != nil {
			return nil, e
		}
		v.schemas[name] = s
	}
	return v, nil
}
func (v *Validator) Validate(kind string, b []byte) (Object, error) {
	// Generated codecs enforce the schema IR's structural contract; the canonical
	// validator additionally enforces constraints not represented by that IR.
	ok := false
	switch kind {
	case "registration":
		ok = ahp.ParseRegistration(b).OK
	case "intercept-request":
		ok = ahp.ParseInterceptRequest(b).OK
	case "intercept-response":
		ok = ahp.ParseInterceptResponse(b).OK
	case "capabilities-request":
		ok = ahp.ParseCapabilitiesRequest(b).OK
	case "capabilities-response":
		ok = ahp.ParseCapabilitiesResponse(b).OK
	case "capabilities":
		ok = ahp.ParseCapabilities(b).OK
	}
	if !ok {
		return nil, fmt.Errorf("generated %s codec rejected document", kind)
	}
	var m Object
	if e := json.Unmarshal(b, &m); e != nil {
		return nil, e
	}
	if e := v.schemas[kind].Validate(m); e != nil {
		return nil, fmt.Errorf("canonical %s validation failed", kind)
	}
	if kind == "intercept-request" && m["id"] != obj(obj(m["params"])["event"])["id"] {
		return nil, fmt.Errorf("request/event correlation mismatch")
	}
	return m, nil
}

// validateEffectShape closes effect objects even when callers use a structural
// codec without additionalProperties enforcement. Extension data is permitted
// only through the draft's explicit deny.extensions member.
func validateEffectShape(effect Object) error {
	fields := map[string]bool{"type": true}
	var allowed []string
	switch effect["type"] {
	case "deny":
		allowed = []string{"reason", "code", "extensions"}
	case "allow", "ask":
	case "message":
		allowed = []string{"text"}
	case "return":
		allowed = []string{"value"}
	case "modify":
		allowed = []string{"target", "operation", "value"}
	case "inject":
		allowed = []string{"target", "operation", "deliverAt", "value"}
	case "flow":
		switch effect["operation"] {
		case "stop":
			allowed = []string{"operation", "reason"}
		case "continue":
			allowed = []string{"operation", "instruction"}
		default:
			return fmt.Errorf("unsupported flow operation")
		}
	default:
		return fmt.Errorf("unsupported effect")
	}
	for _, field := range allowed {
		fields[field] = true
	}
	for field := range effect {
		if !fields[field] {
			return fmt.Errorf("unknown effect field")
		}
	}
	raw, err := json.Marshal(effect)
	if err != nil || !ahp.ParseEffect(raw).OK {
		return fmt.Errorf("invalid effect")
	}
	return nil
}
