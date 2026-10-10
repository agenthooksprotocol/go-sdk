package client

import (
	"encoding/json"
	"errors"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
	"reflect"
)

type interceptConfig struct {
	sources            map[string]*ContentSource
	hostSources        map[string]bool
	ownedSources       []*ContentSource
	claimedSources     map[*ContentSource]bool
	transferredSources map[*ContentSource]bool
	instructionsAbsent bool
	targets            map[string]ModificationTarget
	elicitation        *ElicitationRequest
	instructions       *ahp.ContentItem
	initial            *ahp.InterceptRequestParamsState
	capabilities       *ahp.Capabilities
}

// InterceptOption configures one occurrence. Repeated setters use the last value.
type InterceptOption func(*interceptConfig)

// ModificationTarget explicitly binds an ambiguous native target to a canonical
// event location. Path must be /items (a collection), /items/N (one body),
// /message/text or /message/payload (or an indexed child), or /params for a
// model request's opaque parameters. Collection effects carry an array of body
// values, even when empty or singleton; scalar effects carry one body value.
// Existing items retain identity. Templates supplies host-owned descriptors by
// output index for newly added items; no body/reference is invented for a missing
// template. This is an SDK mapping contract, not an extra AHP wire field.
type ModificationTarget struct {
	Path      string
	Templates []ahp.ContentItem
}

// WithModificationTarget selects the host's canonical representation of a native
// target. The SDK validates paths against the concrete event graph, not arbitrary
// application JSON. Compaction, elicitation and workspace use their fixed mapping.
func WithModificationTarget(target string, binding ModificationTarget) InterceptOption {
	return func(o *interceptConfig) {
		if o.targets == nil {
			o.targets = map[string]ModificationTarget{}
		}
		o.targets[target] = binding
	}
}

// WithElicitationRequest supplies an immutable original request snapshot for a
// correlated result occurrence. It does not create a registry or authorize UI.
func WithElicitationRequest(snapshot *ElicitationRequest) InterceptOption {
	return func(o *interceptConfig) { o.elicitation = snapshot }
}

// WithCompactionInstructions supplies a host-owned descriptor when optional
// instructions were absent. A metadata-only template starts without instructions;
// the first replacement creates bytes with that identity. A supplied body reference
// is resolved and verified. The SDK never invents content identity or metadata.
func WithCompactionInstructions(item ahp.ContentItem) InterceptOption {
	return func(o *interceptConfig) { o.instructions = &item }
}

// WithInitialState supplies the already accepted native decision for this boundary.
// It neither grants authority nor asserts execution. Values are copied at dispatch.
func WithInitialState(state ahp.InterceptRequestParamsState) InterceptOption {
	return func(o *interceptConfig) { o.initial = &state }
}

// WithCapabilities narrows, but cannot expand, the configured manifest.
func WithCapabilities(caps ahp.Capabilities) InterceptOption {
	return func(o *interceptConfig) { o.capabilities = &caps }
}

func resolveOptions(base map[string]any, opts []InterceptOption) (map[string]any, map[string]any, bool, error) {
	cfg := interceptConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	caps := base
	if cfg.capabilities != nil {
		var err error
		caps, err = sdkMap(cfg.capabilities)
		if err != nil {
			return nil, nil, false, err
		}
		if !sdkNarrow(base, caps) {
			return nil, nil, false, errors.New("capabilities exceed manifest")
		}
	}
	if canonical.Validate("capabilities", sdkJSON(caps)) != nil || !ahp.ParseCapabilities(sdkJSON(caps)).OK {
		return nil, nil, false, errors.New("invalid capabilities")
	}
	state := map[string]any{"permission": "none", "candidate": nil}
	if cfg.initial != nil {
		var err error
		state, err = sdkMap(cfg.initial)
		if err != nil {
			return nil, nil, false, err
		}
	}
	return caps, state, cfg.initial != nil, nil
}

// Narrow recognized capability structure only. Unknown fields confer no authority.
func sdkNarrow(base, next any) bool {
	switch n := next.(type) {
	case map[string]any:
		b := sdkObj(base)
		if b == nil {
			return false
		}
		for k, v := range n {
			if k != "effects" && k != "modify" && k != "flow" && k != "inject" && k != "elicitation" && k != "input" && k != "output" && k != "prompt" && k != "request" && k != "response" && k != "content" && k != "instructions" && k != "summary" && k != "workspace" && k != "replace" && k != "merge" && k != "operations" && k != "remainingContinuations" && k != "context" && k != "append" && k != "deliverAt" && k != "form" && k != "url" && k != "supported" {
				continue
			}
			if !sdkNarrow(b[k], v) {
				return false
			}
		}
		return true
	case []any:
		for _, v := range n {
			if !sdkHas(base, v) {
				return false
			}
		}
		return true
	case bool:
		return !n || base == true
	case json.Number:
		b, ok := base.(json.Number)
		return ok && sdkNumberNarrow(b, n)
	case float64:
		b, ok := sdkNumber(base)
		return ok && n <= b
	default:
		return reflect.DeepEqual(base, next)
	}
}

// DecodeError means protocol acceptance succeeded but the effective input cannot
// be represented by the application's type. The returned Result remains usable.
type DecodeError struct{ Err error }

func (e *DecodeError) Error() string {
	return "accepted effective input cannot be decoded into application type"
}
func (e *DecodeError) Unwrap() error { return e.Err }

type ToolBeforeResult[T any] struct {
	*Result
	Input          T
	InputAvailable bool
}

func decodeToolBefore[T any](result *Result, err error) (*ToolBeforeResult[T], error) {
	if result == nil {
		return nil, err
	}
	out := &ToolBeforeResult[T]{Result: result}
	var input T
	if e := json.Unmarshal(result.EffectiveInput, &input); e != nil {
		return out, errors.Join(err, &DecodeError{Err: e})
	}
	out.Input = input
	out.InputAvailable = true
	return out, err
}
