package client

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strings"
	"unicode"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

// FormFieldOptions adds metadata to a field identified by its JSON name.
// Empty numeric bounds mean absent. Enum enables string single-select or
// []string multi-select; arrays without a nonempty enum are unsupported.
// Bounds are exact JSON numbers, not floating-point approximations.
type FormFieldOptions struct {
	Title, Description   string
	Enum                 []string
	Format               ahp.McpElicitationStringSchemaFormat
	Minimum, Maximum     json.Number
	MinLength, MaxLength json.Number
	MinItems, MaxItems   json.Number
}

// FormContractOption configures a reflected form declaration.
type FormContractOption func(map[string]FormFieldOptions) error

// WithFormField configures one JSON field. Duplicate options are rejected.
func WithFormField(name string, metadata FormFieldOptions) FormContractOption {
	if metadata.Enum != nil {
		metadata.Enum = append([]string{}, metadata.Enum...)
	}
	return func(fields map[string]FormFieldOptions) error {
		if _, exists := fields[name]; exists {
			return fmt.Errorf("duplicate form metadata for %q", name)
		}
		fields[name] = metadata
		return nil
	}
}

// FormContract derives MCP's restricted form schema from one flat struct T.
// Fields are required unless tagged omitempty. Pointers, interfaces, embedded
// fields, custom JSON codecs, nested objects and unconstrained arrays are rejected.
// An omitted optional field decodes to its Go zero value; null is never allowed.
// Contracts are immutable and safe for concurrent use.
type FormContract[T any] struct {
	schema  ahp.McpElicitationElicitRequestFormParamsRequestedSchema
	names   map[string]struct{}
	indices map[string]int
}

// FormAnswer represents a validated generated MCP result. Answer is available
// only when Available is true (accept with form content). Decline and cancel
// have no answer. Form contracts do not accept URL-mode confirmations.
type FormAnswer[T any] struct {
	Result    ahp.McpElicitationElicitResult
	Answer    T
	Available bool
}

// NewFormContract constructs a contract without creating a second wire schema.
// Supported Go fields are strings (including named strings), bools, integer and
// floating-point types, json.Number, and enum-constrained slices of strings.
func NewFormContract[T any](options ...FormContractOption) (*FormContract[T], error) {
	return newFormContract[T](reflect.TypeFor[T](), options...)
}

func newFormContract[T any](t reflect.Type, options ...FormContractOption) (*FormContract[T], error) {
	if t.Kind() != reflect.Struct || formCustomCodec(t) {
		return nil, errors.New("form declaration must be a plain struct")
	}
	metadata := map[string]FormFieldOptions{}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("nil form option")
		}
		if err := option(metadata); err != nil {
			return nil, err
		}
	}
	c := &FormContract[T]{names: map[string]struct{}{}, indices: map[string]int{}, schema: ahp.McpElicitationElicitRequestFormParamsRequestedSchema{
		Type:       ahp.McpElicitationElicitRequestFormParamsRequestedSchemaTypeObject,
		Properties: map[string]*ahp.McpElicitationPrimitiveSchemaDefinition{},
	}}
	required := []string{}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := strings.Split(field.Tag.Get("json"), ",")
		if tag[0] == "-" {
			continue
		}
		if field.Anonymous || field.PkgPath != "" {
			return nil, fmt.Errorf("form field %s must be exported and nonembedded", field.Name)
		}
		name := tag[0]
		if name == "" {
			name = field.Name
		}
		// encoding/json silently ignores invalid names; do not allow that ambiguity.
		if !formJSONName(name) {
			return nil, fmt.Errorf("invalid form JSON field name %q", name)
		}
		optional := false
		for _, flag := range tag[1:] {
			if flag == "omitempty" && !optional {
				optional = true
			} else {
				return nil, fmt.Errorf("unsupported JSON option on %s", field.Name)
			}
		}
		if _, exists := c.names[name]; exists {
			return nil, fmt.Errorf("ambiguous form field %q", name)
		}
		c.names[name] = struct{}{}
		c.indices[name] = i
		if !optional {
			required = append(required, name)
		}
		union, err := formPrimitive(field.Type, metadata[name])
		if err != nil {
			return nil, fmt.Errorf("form field %s: %w", name, err)
		}
		raw, err := json.Marshal(union)
		if err != nil {
			return nil, fmt.Errorf("form field %s: invalid schema metadata", name)
		}
		_ = raw
		c.schema.Properties[name] = &union
	}
	for name := range metadata {
		if _, ok := c.names[name]; !ok {
			return nil, fmt.Errorf("unknown form metadata field %q", name)
		}
	}
	c.schema.Required = ahp.Some(required)
	raw, err := json.Marshal(map[string]any{"message": "", "requestedSchema": c.schema})
	if err != nil || canonical.Validate("mcp-elicitation#request", raw) != nil {
		return nil, errors.New("invalid MCP form schema")
	}
	return c, nil
}

func formJSONName(name string) bool {
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", r) {
			return false
		}
	}
	return name != ""
}

func formCustomCodec(t reflect.Type) bool {
	return t.Implements(reflect.TypeFor[encoding.TextMarshaler]()) || reflect.PointerTo(t).Implements(reflect.TypeFor[encoding.TextMarshaler]()) ||
		t.Implements(reflect.TypeFor[encoding.TextUnmarshaler]()) || reflect.PointerTo(t).Implements(reflect.TypeFor[encoding.TextUnmarshaler]()) ||
		t.Implements(reflect.TypeFor[json.Marshaler]()) || reflect.PointerTo(t).Implements(reflect.TypeFor[json.Marshaler]()) ||
		t.Implements(reflect.TypeFor[json.Unmarshaler]()) || reflect.PointerTo(t).Implements(reflect.TypeFor[json.Unmarshaler]())
}

func formOptionalNumber(n json.Number) ahp.Optional[json.Number] {
	if n == "" {
		return ahp.Optional[json.Number]{}
	}
	return ahp.Some(n)
}
func formOptionalString(s string) ahp.Optional[string] {
	if s == "" {
		return ahp.Optional[string]{}
	}
	return ahp.Some(s)
}

func formCheckBounds(lo, hi json.Number, count bool) error {
	var lower, upper *big.Rat
	for i, n := range []json.Number{lo, hi} {
		if n == "" {
			continue
		}
		if _, err := json.Marshal(n); err != nil {
			return errors.New("invalid numeric constraint")
		}
		r, ok := new(big.Rat).SetString(string(n))
		if !ok || (count && (!r.IsInt() || r.Sign() < 0)) {
			return errors.New("invalid numeric constraint")
		}
		if i == 0 {
			lower = r
		} else {
			upper = r
		}
	}
	if lower != nil && upper != nil && lower.Cmp(upper) > 0 {
		return errors.New("minimum exceeds maximum")
	}
	return nil
}

func formPrimitive(t reflect.Type, m FormFieldOptions) (ahp.McpElicitationPrimitiveSchemaDefinition, error) {
	var u ahp.McpElicitationPrimitiveSchemaDefinition
	if formCustomCodec(t) {
		return u, errors.New("custom JSON codecs are unsupported")
	}
	for _, pair := range []struct {
		lo, hi json.Number
		count  bool
	}{{m.Minimum, m.Maximum, false}, {m.MinLength, m.MaxLength, true}, {m.MinItems, m.MaxItems, true}} {
		if err := formCheckBounds(pair.lo, pair.hi, pair.count); err != nil {
			return u, err
		}
	}
	seen := map[string]bool{}
	for _, value := range m.Enum {
		if seen[value] {
			return u, errors.New("duplicate enum value")
		}
		seen[value] = true
	}
	title, description := formOptionalString(m.Title), formOptionalString(m.Description)
	numeric := m.Minimum != "" || m.Maximum != ""
	length := m.MinLength != "" || m.MaxLength != ""
	items := m.MinItems != "" || m.MaxItems != ""
	hasEnum := m.Enum != nil
	kind := t.Kind()
	if t == reflect.TypeFor[json.Number]() {
		kind = reflect.Float64
	}
	switch kind {
	case reflect.String:
		if numeric || items || (hasEnum && (length || m.Format != "")) {
			return u, errors.New("constraints do not apply to string shape")
		}
		if hasEnum {
			if len(m.Enum) == 0 {
				return u, errors.New("enum must not be empty")
			}
			u.McpElicitationUntitledSingleSelectEnumSchema = ahp.Some(&ahp.McpElicitationUntitledSingleSelectEnumSchema{Type: "string", Title: title, Description: description, Enum: append([]string(nil), m.Enum...)})
		} else {
			format := ahp.Optional[ahp.McpElicitationStringSchemaFormat]{}
			if m.Format != "" {
				format = ahp.Some(m.Format)
			}
			u.McpElicitationStringSchema = ahp.Some(&ahp.McpElicitationStringSchema{Type: "string", Title: title, Description: description, Format: format, MinLength: formOptionalNumber(m.MinLength), MaxLength: formOptionalNumber(m.MaxLength)})
		}
	case reflect.Bool:
		if numeric || length || items || hasEnum || m.Format != "" {
			return u, errors.New("constraints do not apply to boolean")
		}
		u.McpElicitationBooleanSchema = ahp.Some(&ahp.McpElicitationBooleanSchema{Type: "boolean", Title: title, Description: description})
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		if length || items || hasEnum || m.Format != "" {
			return u, errors.New("constraints do not apply to number")
		}
		typ := ahp.McpElicitationNumberSchemaTypeInteger
		if kind == reflect.Float32 || kind == reflect.Float64 {
			typ = ahp.McpElicitationNumberSchemaTypeNumber
		}
		if typ == ahp.McpElicitationNumberSchemaTypeInteger {
			var err error
			m.Minimum, m.Maximum, err = formIntegerBounds(t, m.Minimum, m.Maximum)
			if err != nil {
				return u, err
			}
		}
		u.McpElicitationNumberSchema = ahp.Some(&ahp.McpElicitationNumberSchema{Type: typ, Title: title, Description: description, Minimum: formOptionalNumber(m.Minimum), Maximum: formOptionalNumber(m.Maximum)})
	case reflect.Slice:
		if t.Elem().Kind() != reflect.String || t.Elem() == reflect.TypeFor[json.Number]() || formCustomCodec(t.Elem()) || len(m.Enum) == 0 || numeric || length || m.Format != "" {
			return u, errors.New("only enum-constrained string slices are supported")
		}
		u.McpElicitationUntitledMultiSelectEnumSchema = ahp.Some(&ahp.McpElicitationUntitledMultiSelectEnumSchema{Type: "array", Title: title, Description: description, Items: ahp.McpElicitationUntitledMultiSelectEnumSchemaItems{Type: "string", Enum: append([]string(nil), m.Enum...)}, MinItems: formOptionalNumber(m.MinItems), MaxItems: formOptionalNumber(m.MaxItems)})
	default:
		return u, errors.New("unsupported or nullable form field type")
	}
	return u, nil
}

// Integer width is part of the answer declaration, so the requested schema
// carries those exact bounds as well as any narrower field metadata constraints.
func formIntegerBounds(t reflect.Type, minimum, maximum json.Number) (json.Number, json.Number, error) {
	bits := uint(t.Bits())
	upper := new(big.Int).Lsh(big.NewInt(1), bits)
	lower := big.NewInt(0)
	if t.Kind() >= reflect.Int && t.Kind() <= reflect.Int64 {
		upper.Rsh(upper, 1)
		lower.Neg(new(big.Int).Set(upper))
	}
	upper.Sub(upper, big.NewInt(1))
	lo, hi := json.Number(lower.String()), json.Number(upper.String())
	if minimum != "" {
		bound, _ := new(big.Rat).SetString(string(minimum))
		if bound.Cmp(new(big.Rat).SetInt(lower)) > 0 {
			lo = minimum
		}
	}
	if maximum != "" {
		bound, _ := new(big.Rat).SetString(string(maximum))
		if bound.Cmp(new(big.Rat).SetInt(upper)) < 0 {
			hi = maximum
		}
	}
	if err := formCheckBounds(lo, hi, false); err != nil {
		return "", "", errors.New("form constraints exceed integer representation")
	}
	return lo, hi, nil
}

// RequestedSchema returns an independent generated wire schema, suitable for
// McpElicitationElicitRequestFormParams.RequestedSchema. Mutating it does not
// change the contract's validation behavior.
func (c *FormContract[T]) RequestedSchema() ahp.McpElicitationElicitRequestFormParamsRequestedSchema {
	out := c.schema
	out.Properties = make(map[string]*ahp.McpElicitationPrimitiveSchemaDefinition, len(c.schema.Properties))
	for name, primitive := range c.schema.Properties {
		var copied ahp.McpElicitationPrimitiveSchemaDefinition
		_ = json.Unmarshal(sdkJSON(primitive), &copied)
		out.Properties[name] = &copied
	}
	out.Required.Value = append([]string{}, c.schema.Required.Value...)
	return out
}

// DecodeResult validates an entire MCP ElicitResult before decoding accepted
// content. It rejects undeclared keys (including case-insensitive Go aliases),
// null, missing required fields, invalid constraints and nonaccept content.
// json.Number values retain their exact wire spelling.
func (c *FormContract[T]) DecodeResult(raw []byte) (FormAnswer[T], error) {
	var out FormAnswer[T]
	if c == nil {
		return out, errors.New("nil form contract")
	}
	if err := canonical.Validate("mcp-elicitation#result", raw); err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out.Result); err != nil {
		return FormAnswer[T]{}, errors.New("invalid MCP form result")
	}
	if _, err := formObjectRaw(raw); err != nil {
		return FormAnswer[T]{}, errors.New("ambiguous form result")
	}
	if out.Result.Action != ahp.McpElicitationElicitResultActionAccept {
		if out.Result.Content.Present {
			return FormAnswer[T]{}, errors.New("nonaccept form result must omit content")
		}
		return out, nil
	}
	envelope, err := formObjectRaw(raw)
	if err != nil {
		return FormAnswer[T]{}, errors.New("invalid MCP form result")
	}
	contentRaw := envelope["content"]
	// In form mode an accepted result without content denotes an empty answer.
	// Validate that temporary object without changing the original envelope.
	if !out.Result.Content.Present {
		contentRaw = json.RawMessage(`{}`)
	}
	out.Answer, err = c.DecodeAnswers(contentRaw)
	if err != nil {
		return FormAnswer[T]{}, err
	}
	projection, projectionErr := convertWire[ahp.ElicitResult[T]](out.Result)
	if projectionErr != nil {
		return FormAnswer[T]{}, errors.New("form result cannot be represented by declaration")
	}
	if projection.Content.Present {
		out.Answer = projection.Content.Value
	}
	out.Available = true
	return out, nil
}

// Request builds the generated MCP request from the same answer declaration.
func (c *FormContract[T]) Request(message string) (ahp.McpElicitationElicitRequestFormParams, error) {
	if c == nil {
		return ahp.McpElicitationElicitRequestFormParams{}, errors.New("nil form contract")
	}
	return ahp.McpElicitationElicitRequestFormParams{Message: message, Mode: ahp.Some(ahp.McpElicitationElicitRequestFormParamsMode("form")), RequestedSchema: c.RequestedSchema()}, nil
}

// DecodeAnswers validates just the structured content against the same contract.
// Supplied zero-valued optional fields remain valid; the raw MCP result separately
// preserves their presence. Numeric values must survive decoding without rounding.
func (c *FormContract[T]) DecodeAnswers(raw []byte) (T, error) {
	var answer T
	if c == nil {
		return answer, errors.New("nil form contract")
	}
	if _, err := formObjectRaw(raw); err != nil {
		return answer, errors.New("ambiguous form content")
	}
	content, err := contractJSON(raw)
	if err != nil {
		return answer, errors.New("invalid form content")
	}
	object, ok := content.(map[string]any)
	if !ok {
		return answer, errors.New("form content must be an object")
	}
	for name := range object {
		if _, ok := c.names[name]; !ok {
			return answer, errors.New("unknown form answer field")
		}
	}
	if err := canonical.ValidateFormAnswer(c.schema, object); err != nil {
		return answer, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&answer); err != nil {
		return answer, errors.New("form answer cannot be represented by declaration")
	}
	reflected := reflect.ValueOf(answer)
	for name, value := range object {
		encoded, err := json.Marshal(reflected.Field(c.indices[name]).Interface())
		if err != nil {
			return answer, errors.New("form field cannot be encoded")
		}
		roundtrip, err := contractJSON(encoded)
		if err != nil || !contractPreserves(value, roundtrip) {
			return answer, errors.New("form field cannot be represented without data loss")
		}
	}
	return answer, nil
}

// formObjectRaw rejects duplicate object keys before encoding/json can erase them.
func formObjectRaw(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("expected object")
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, errors.New("expected field name")
		}
		if _, exists := fields[name]; exists {
			return nil, errors.New("duplicate field")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		fields[name] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return fields, nil
}
