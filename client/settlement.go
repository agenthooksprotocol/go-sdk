package client

import (
	"fmt"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

// SettlementDecodeError means canonical settlement could not be projected into
// schema-owned consumer models. Accepted responses remain available for audit,
// but the result is interrupted and cannot authorize execution.
type SettlementDecodeError struct{ Err error }

func (e *SettlementDecodeError) Error() string { return "settled protocol data cannot be decoded" }
func (e *SettlementDecodeError) Unwrap() error { return e.Err }

// Candidate retains the complete candidate envelope. Exactly one field is
// populated according to the originating boundary. Opaque is caller-owned data;
// use a declared return codec or ToolBefore for its application contract.
type Candidate struct {
	Messages    *ahp.MessagesCandidate
	Text        *ahp.TextCandidate
	Elicitation *ahp.ElicitResultCandidate
	Opaque      *ahp.InterceptRequestParamsStateCandidateValue
}

// decodeSettlement validates all schema-owned projections before publishing any
// of them. Raw reducer output is private to the SDK.
func (r *Result) decodeSettlement(name string) (err error) {
	defer func() {
		if err != nil {
			// Keep raw accepted settlement, but never expose partial typed views or
			// a consumer execution grant when projection failed.
			r.Interrupted = true
			r.Permission = "none"
			r.Event = nil
			r.Candidate = ahp.Null[Candidate]()
			r.Instructions = ahp.Optional[[]string]{}
			r.Injections = ahp.Optional[[]*ahp.InjectEffect]{}
		}
	}()
	event := ahp.ParseEvent(r.eventWire)
	if !event.OK {
		return &SettlementDecodeError{Err: fmt.Errorf("invalid settled event")}
	}
	kind, _, err := eventIdentity(&event.Value)
	if err != nil || kind != name {
		return &SettlementDecodeError{Err: fmt.Errorf("settled event identity mismatch")}
	}
	candidate := ahp.Null[Candidate]()
	if r.state.Candidate.Valid {
		raw := r.state.Candidate.Value
		value := Candidate{}
		switch name {
		case "model.request.before":
			decoded, e := convertWire[ahp.MessagesCandidate](raw)
			if e != nil {
				return &SettlementDecodeError{Err: e}
			}
			value.Messages = &decoded
		case "context.compact.before":
			decoded, e := convertWire[ahp.TextCandidate](raw)
			if e != nil {
				return &SettlementDecodeError{Err: e}
			}
			value.Text = &decoded
		case "user.elicitation.request":
			decoded, e := convertWire[ahp.ElicitResultCandidate](raw)
			if e != nil {
				return &SettlementDecodeError{Err: e}
			}
			value.Elicitation = &decoded
		default:
			value.Opaque = &raw
		}
		candidate = ahp.NonNull(value)
	}
	r.Instructions = r.state.Instructions
	r.Injections = r.state.Injections
	r.Flow = r.state.Flow
	r.StateExtras = r.state.AdditionalProperties
	r.Event = &event.Value
	r.Candidate = candidate
	return nil
}

// requireSettledEvent prevents application projections from claiming usable
// values when canonical settlement failed. Accepted envelopes stay available.
func (r *Result) requireSettledEvent(name string) error {
	kind, _, err := eventIdentity(r.Event)
	if err != nil || kind != name {
		r.Interrupted = true
		r.Permission = "none"
		return &SettlementDecodeError{Err: fmt.Errorf("settled %s event is unavailable", name)}
	}
	return nil
}
