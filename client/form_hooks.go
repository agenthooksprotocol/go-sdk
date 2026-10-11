package client

import (
	"context"
	"encoding/json"
	"errors"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/event"
)

// FormHookResult keeps the complete protocol result (including opaque metadata)
// alongside a typed form answer. Candidate is present for intercepted requests;
// Answer is present for disclosed correlated result bodies. Decline and cancel
// wrappers are present but their FormAnswer.Available is false.
type FormHookResult[T any] struct {
	*Result
	Candidate ahp.Optional[FormAnswer[T]]
	Answer    ahp.Optional[FormAnswer[T]]
}

func formResultCodec[T any](form *FormContract[T]) Codec[FormAnswer[T]] {
	return Codec[FormAnswer[T]]{
		Decode: func(raw json.RawMessage) (FormAnswer[T], error) { return form.DecodeResult(raw) },
		Encode: func(answer FormAnswer[T]) (json.RawMessage, error) { return json.Marshal(answer.Result) },
	}
}

// ElicitForm derives requestedSchema and validates candidates from one T. The
// caller supplies requester/correlation metadata and a canonical inline body
// descriptor with its own identity; only that descriptor's request text is
// replaced. Unsupported form declarations fail at NewFormContract construction.
func ElicitForm[T any](ctx context.Context, hooks *Hooks, input event.UserElicitationRequestInput, form *FormContract[T], message string, options ...InterceptOption) (*FormHookResult[T], error) {
	if form == nil || input.Elicitation.Mode != "form" {
		return nil, &AdmissionError{Kind: "input", Err: errors.New("form contract requires form mode")}
	}
	descriptor := input.Elicitation.Request
	if !descriptor.Present || descriptor.Value == nil || !descriptor.Value.TextBodyPart.Present || descriptor.Value.TextBodyPart.Value == nil {
		return nil, &AdmissionError{Kind: "input", Err: errors.New("form request requires caller-owned inline body descriptor")}
	}
	request, err := form.Request(message)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	part := *descriptor.Value
	body := *part.TextBodyPart.Value
	body.Text = string(raw)
	part.TextBodyPart = ahp.Some(&body)
	input.Elicitation.Request = ahp.Some(&part)
	options = append(options, WithReturnCodec(formResultCodec(form)))
	result, err := hooks.UserElicitationRequest(ctx, input, options...)
	if result == nil {
		return nil, err
	}
	out := &FormHookResult[T]{Result: result}
	state, stateErr := sdkMap(result.State)
	if stateErr != nil {
		return out, stateErr
	}
	if candidate := sdkObj(state["candidate"]); candidate != nil {
		answer, decodeErr := form.DecodeResult(sdkJSON(candidate["value"]))
		if decodeErr != nil {
			return out, errors.Join(err, &DecodeError{Err: decodeErr})
		}
		out.Candidate = ahp.Some(answer)
	}
	return out, err
}

// ElicitFormResult validates disclosed result content and staged answer edits
// before publication. Snapshot binds the original request identity and schema.
// The supplied form must describe that original request; it cannot replace its
// schema. Without a disclosed result body no typed Answer is claimed.
func ElicitFormResult[T any](ctx context.Context, hooks *Hooks, input event.UserElicitationResultInput, form *FormContract[T], snapshot *ElicitationRequest, options ...InterceptOption) (*FormHookResult[T], error) {
	if form == nil || input.Elicitation.Mode != "form" {
		return nil, &AdmissionError{Kind: "input", Err: errors.New("form contract requires form mode")}
	}
	if snapshot == nil || !snapshot.requestValid || !compositionEqual(compositionObject(sdkJSON(snapshot.requestedSchema)), compositionObject(sdkJSON(form.RequestedSchema()))) {
		return nil, &AdmissionError{Kind: "input", Err: errors.New("form declaration does not match original request")}
	}
	options = append(options, WithElicitationRequest(snapshot), func(cfg *interceptConfig) {
		configureDeclared(cfg).targets["content"] = func(raw json.RawMessage) error {
			// The canonical MCP validator has already checked the enclosing action.
			// Nonaccept wrappers have no content; nil is an internal unavailable value.
			if string(raw) == "null" {
				return nil
			}
			_, err := form.DecodeAnswers(raw)
			return err
		}
	})
	result, err := hooks.UserElicitationResult(ctx, input, options...)
	if result == nil {
		return nil, err
	}
	out := &FormHookResult[T]{Result: result}
	var settled ahp.UserElicitationResultEvent
	if decodeErr := json.Unmarshal(result.Event, &settled); decodeErr != nil {
		return out, decodeErr
	}
	descriptor := settled.Elicitation.Result
	if descriptor.Present && descriptor.Value != nil && descriptor.Value.TextBodyPart.Present && descriptor.Value.TextBodyPart.Value != nil {
		answer, decodeErr := form.DecodeResult([]byte(descriptor.Value.TextBodyPart.Value.Text))
		if decodeErr != nil {
			return out, errors.Join(err, &DecodeError{Err: decodeErr})
		}
		out.Answer = ahp.Some(answer)
	}
	return out, err
}
