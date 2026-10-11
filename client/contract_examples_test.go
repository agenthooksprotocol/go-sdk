package client_test

import (
	"context"
	"encoding/json"
	"errors"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/client"
	"github.com/agenthooksprotocol/go-sdk/event"
)

// This compile-only application example checks that the public generic API needs
// no private types or independently maintained application schema declaration.
func compileDeclaredToolAPI(ctx context.Context, hooks *client.Hooks) error {
	type Arguments struct {
		Count int         `json:"count"`
		Exact json.Number `json:"exact"`
	}
	type Answer struct {
		Text string `json:"text"`
	}
	type Provenance struct {
		Host string `json:"host"`
	}
	contract := client.ToolContract[Arguments, Answer]{Arguments: client.JSONCodec(func(a Arguments) error {
		if a.Count < 1 {
			return errors.New("positive count required")
		}
		return nil
	}), Result: client.JSONCodec[Answer](nil)}
	input := event.ToolBeforeInput[Arguments]{CallID: "call-example", Path: "execute", Name: "task", Origin: "native", Input: Arguments{Count: 1, Exact: "9007199254740993"}}
	result, err := client.ToolBefore(ctx, hooks, input, contract)
	if result != nil {
		defer result.Close()
		var _ Arguments = result.Input
		if result.Candidate.Present {
			var _ Answer = result.Candidate.Value.Value
		}
	}
	if err != nil {
		return err
	}
	associated, err := client.ToolBeforeWithProvenance(ctx, hooks, input, contract, client.JSONCodec[Provenance](nil))
	if associated != nil {
		defer associated.Close()
		if associated.Candidate.Present && associated.Candidate.Value.Provenance.Present {
			var _ Provenance = associated.Candidate.Value.Provenance.Value
		}
	}
	return err
}

func compileSingleDeclarationFormAPI(ctx context.Context, hooks *client.Hooks, input event.UserElicitationRequestInput) error {
	type Answer struct {
		Name   string `json:"name"`
		Choice string `json:"choice"`
	}
	form, err := client.NewFormContract[Answer](client.WithFormField("name", client.FormFieldOptions{MinLength: "1"}), client.WithFormField("choice", client.FormFieldOptions{Enum: []string{"a", "b"}}))
	if err != nil {
		return err
	}
	var _ ahp.McpElicitationElicitRequestFormParamsRequestedSchema = form.RequestedSchema()
	result, err := client.ElicitForm(ctx, hooks, input, form, "Choose an answer")
	if result != nil {
		defer result.Close()
		if result.Candidate.Present && result.Candidate.Value.Available {
			var _ Answer = result.Candidate.Value.Answer
		}
	}
	return err
}
