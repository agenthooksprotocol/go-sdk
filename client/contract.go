package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/event"
	"github.com/agenthooksprotocol/go-sdk/internal/inputsources"
)

// Codec declares a caller-owned value contract. Zero Encode and Decode functions
// use encoding/json with UseNumber. Validate is optional. Decoding rejects any
// round trip that drops or changes supplied data, including unknown fields.
// Custom types can preserve extensions in their own MarshalJSON/UnmarshalJSON.
// Callbacks must be deterministic and must not mutate their decoded values.
// Validation errors deliberately exclude payloads and caller error text.
type Codec[T any] struct {
	Decode   func(json.RawMessage) (T, error)
	Encode   func(T) (json.RawMessage, error)
	Validate func(T) error
}

func JSONCodec[T any](validate func(T) error) Codec[T] { return Codec[T]{Validate: validate} }

func (c Codec[T]) DecodeJSON(raw json.RawMessage) (T, error) {
	var value T
	original, err := contractJSON(raw)
	if err != nil {
		return value, errors.New("invalid declared JSON value")
	}
	if c.Decode != nil {
		value, err = c.Decode(bytes.Clone(raw))
	} else {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		err = decoder.Decode(&value)
	}
	if err != nil {
		return value, errors.New("declared value cannot be decoded")
	}
	var encoded json.RawMessage
	if c.Encode != nil {
		encoded, err = c.Encode(value)
	} else {
		encoded, err = json.Marshal(value)
	}
	if err != nil {
		return value, errors.New("declared value cannot be encoded")
	}
	roundtrip, err := contractJSON(encoded)
	if err != nil || !contractPreserves(original, roundtrip) {
		return value, errors.New("declared codec drops or changes supplied data")
	}
	if c.Validate != nil && c.Validate(value) != nil {
		return value, errors.New("declared value validation failed")
	}
	return value, nil
}

func contractJSON(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("expected exactly one JSON value")
	}
	return value, nil
}

// The wire value remains authoritative. Encoded defaults may add members, but
// every supplied member (including null and exact numbers) must survive.
func contractPreserves(original, encoded any) bool {
	if object, ok := original.(map[string]any); ok {
		next, ok := encoded.(map[string]any)
		if !ok {
			return false
		}
		for key, value := range object {
			other, exists := next[key]
			if !exists || !contractPreserves(value, other) {
				return false
			}
		}
		return true
	}
	if array, ok := original.([]any); ok {
		next, ok := encoded.([]any)
		if !ok || len(array) != len(next) {
			return false
		}
		for i, value := range array {
			if !contractPreserves(value, next[i]) {
				return false
			}
		}
		return true
	}
	return compositionEqual(original, encoded)
}

type declaredValidator func(json.RawMessage) error

type declaredContracts struct {
	targets    map[string]declaredValidator
	hostValues map[string]declaredValidator
	result     declaredValidator
	provenance declaredValidator
}

func codecValidator[T any](codec Codec[T]) declaredValidator {
	return func(raw json.RawMessage) error { _, err := codec.DecodeJSON(raw); return err }
}

func configureDeclared(cfg *interceptConfig) *declaredContracts {
	if cfg.declared == nil {
		cfg.declared = &declaredContracts{targets: map[string]declaredValidator{}, hostValues: map[string]declaredValidator{}}
	}
	return cfg.declared
}

// WithTargetCodec validates a whole effective target, after temporary shallow
// merge and before atomic publication. It never attempts to decode a patch as T.
// The target must match the boundary and be available in its prepared values.
func WithTargetCodec[T any](target string, codec Codec[T]) InterceptOption {
	return func(cfg *interceptConfig) { configureDeclared(cfg).targets[target] = codecValidator(codec) }
}

// WithHostValueCodec validates an explicitly selected caller-owned event value.
// path is a JSON Pointer, e.g. /params, /task/change, /task/prior, /native, or an
// opaque permission/discovery field. Missing optional values stay absent. Without
// this option these values are forwarded opaquely, not interpreted recursively.
func WithHostValueCodec[T any](path string, codec Codec[T]) InterceptOption {
	return func(cfg *interceptConfig) { configureDeclared(cfg).hostValues[path] = codecValidator(codec) }
}

// WithReturnCodec declares the entire candidate/return value contract.
func WithReturnCodec[T any](codec Codec[T]) InterceptOption {
	return func(cfg *interceptConfig) { configureDeclared(cfg).result = codecValidator(codec) }
}

// WithProvenanceCodec validates provenance only when a candidate supplies it.
// Replacement candidates do not inherit provenance from the previous candidate.
func WithProvenanceCodec[T any](codec Codec[T]) InterceptOption {
	return func(cfg *interceptConfig) { configureDeclared(cfg).provenance = codecValidator(codec) }
}

func (d *declaredContracts) validateDeclaration(kind string) error {
	if d == nil {
		return nil
	}
	for target := range d.targets {
		if target == "" || target != compositionTargets[kind] {
			return errors.New("declared target does not match boundary")
		}
	}
	return nil
}

func (d *declaredContracts) validateTarget(target string, value any) error {
	if d == nil || d.targets[target] == nil {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return errors.New("invalid declared target")
	}
	return d.targets[target](raw)
}

func (d *declaredContracts) validateCandidate(state map[string]any) error {
	if d == nil {
		return nil
	}
	candidate := sdkObj(state["candidate"])
	if candidate == nil {
		return nil
	}
	if d.result != nil {
		if err := d.result(sdkJSON(candidate["value"])); err != nil {
			return err
		}
	}
	if provenance, exists := candidate["provenance"]; exists && d.provenance != nil {
		return d.provenance(sdkJSON(provenance))
	}
	return nil
}

func (d *declaredContracts) validateHost(event map[string]any) error {
	if d == nil {
		return nil
	}
	for path, validate := range d.hostValues {
		value, exists, err := contractAt(event, path)
		if err != nil {
			return err
		}
		if exists {
			if err := validate(sdkJSON(value)); err != nil {
				return err
			}
		}
	}
	return nil
}

func contractAt(root any, path string) (any, bool, error) {
	if path == "" {
		return root, true, nil
	}
	if !strings.HasPrefix(path, "/") {
		return nil, false, errors.New("declared host path must be a JSON Pointer")
	}
	tokens := strings.Split(path[1:], "/")
	for index, token := range tokens {
		for i := 0; i < len(token); i++ {
			if token[i] == '~' {
				if i+1 >= len(token) || (token[i+1] != '0' && token[i+1] != '1') {
					return nil, false, errors.New("invalid declared JSON Pointer")
				}
				i++
			}
		}
		tokens[index] = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
	}
	value := root
	for _, token := range tokens {
		switch current := value.(type) {
		case map[string]any:
			var exists bool
			value, exists = current[token]
			if !exists {
				return nil, false, nil
			}
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(current) || strconv.Itoa(index) != token {
				return nil, false, nil
			}
			value = current[index]
		default:
			return nil, false, nil
		}
	}
	return value, true, nil
}

// ToolContract keeps the result contract independent of argument type A.
type ToolContract[A, R any] struct {
	Arguments Codec[A]
	Result    Codec[R]
}

type ToolDecision[A, R, P any] struct {
	*Result
	Input          A
	InputAvailable bool
	// Absent is no candidate. Present with a nil Value is a candidate whose value
	// is literal JSON null, permitted only when the declared R codec accepts it.
	Candidate ahp.Optional[ahp.Candidate[R, P]]
}

// ToolBefore is the declared-contract companion to the Hooks convenience method.
// The runtime contract argument infers both A and R without generic methods.
func ToolBefore[A, R any](ctx context.Context, hooks *Hooks, input event.ToolBeforeInput[A], contract ToolContract[A, R], options ...InterceptOption) (*ToolDecision[A, R, json.RawMessage], error) {
	return ToolBeforeWithProvenance(ctx, hooks, input, contract, JSONCodec[json.RawMessage](nil), options...)
}

func ToolBeforeWithProvenance[A, R, P any](ctx context.Context, hooks *Hooks, input event.ToolBeforeInput[A], contract ToolContract[A, R], provenance Codec[P], options ...InterceptOption) (*ToolDecision[A, R, P], error) {
	// Declared contracts cannot be overridden by later convenience options.
	options = append(options, WithTargetCodec("input", contract.Arguments), WithReturnCodec(contract.Result), WithProvenanceCodec(provenance))
	result, err := hooks.intercept(ctx, "tool.before", inputsources.PrepareToolBefore(input), options...)
	return decodeToolDecision(result, err, contract, provenance)
}

func decodeToolDecision[A, R, P any](result *Result, err error, contract ToolContract[A, R], provenance Codec[P]) (*ToolDecision[A, R, P], error) {
	if result == nil {
		return nil, err
	}
	out := &ToolDecision[A, R, P]{Result: result}
	complete := false
	defer func() {
		if !complete {
			result.Interrupted = true
			result.Permission = "none"
			out.InputAvailable = false
			out.Candidate = ahp.Optional[ahp.Candidate[R, P]]{}
		}
	}()
	if e := result.requireSettledEvent("tool.before"); e != nil {
		return out, errors.Join(err, e)
	}
	decodedInput, errDecode := contract.Arguments.DecodeJSON(sdkJSON(result.Event.ToolBeforeEvent.Value.Tool.Input))
	out.Input = decodedInput
	if errDecode != nil {
		result.Interrupted = true
		result.Permission = "none"
		return out, errors.Join(err, &DecodeError{Err: errDecode})
	}
	state, stateErr := sdkMap(result.state)
	if stateErr != nil {
		return out, stateErr
	}
	candidate := sdkObj(state["candidate"])
	if candidate != nil {
		value, decodeErr := contract.Result.DecodeJSON(sdkJSON(candidate["value"]))
		if decodeErr != nil {
			return out, errors.Join(err, &DecodeError{Err: decodeErr})
		}
		rawCandidate, decodeErr := convertWire[ahp.Candidate[json.RawMessage, json.RawMessage]](candidate)
		if decodeErr != nil {
			return out, decodeErr
		}
		typed := ahp.Candidate[R, P]{Value: value, AdditionalProperties: rawCandidate.AdditionalProperties}
		if raw, exists := candidate["provenance"]; exists {
			p, decodeErr := provenance.DecodeJSON(sdkJSON(raw))
			if decodeErr != nil {
				return out, errors.Join(err, &DecodeError{Err: decodeErr})
			}
			typed.Provenance = ahp.Some(p)
		}
		out.Candidate = ahp.Some(typed)
	}
	out.InputAvailable = true
	complete = true
	return out, err
}
