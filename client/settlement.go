package client

import (
	"fmt"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

// SettlementDecodeError means canonical settlement could not be projected into
// schema-owned consumer models. Raw accepted data remains available for audit,
// but the result is interrupted and cannot authorize execution.
type SettlementDecodeError struct{ Err error }

func (e *SettlementDecodeError) Error() string { return "settled protocol data cannot be decoded" }
func (e *SettlementDecodeError) Unwrap() error { return e.Err }

// SettledCandidate retains the complete candidate envelope. Exactly one field is
// populated according to the originating boundary. Opaque is caller-owned data;
// use a declared return codec or ToolBefore for its application contract.
type SettledCandidate struct {
	Messages    *ahp.MessagesCandidate
	Text        *ahp.TextCandidate
	Elicitation *ahp.ElicitResultCandidate
	Opaque      *ahp.InterceptRequestParamsStateCandidateValue
}

// decodeSettlement validates all schema-owned projections before publishing any
// of them. Raw reducer output remains separate from the consumer facade.
func (r *Result) decodeSettlement(name string) (err error) {
	defer func() {
		if err != nil {
			// Keep raw accepted settlement, but never expose partial typed views or
			// a consumer execution grant when projection failed.
			r.Interrupted = true
			r.Permission = "none"
			r.SettledEvent = nil
			r.SettledCandidate = ahp.Null[SettledCandidate]()
		}
	}()
	event := ahp.ParseEvent(r.Event)
	if !event.OK {
		return &SettlementDecodeError{Err: fmt.Errorf("invalid settled event")}
	}
	kind, _, err := eventIdentity(&event.Value)
	if err != nil || kind != name {
		return &SettlementDecodeError{Err: fmt.Errorf("settled event identity mismatch")}
	}
	candidate := ahp.Null[SettledCandidate]()
	if r.State.Candidate.Valid {
		raw := r.State.Candidate.Value
		value := SettledCandidate{}
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
	r.SettledEvent = &event.Value
	r.SettledCandidate = candidate
	return nil
}
