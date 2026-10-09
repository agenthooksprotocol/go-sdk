package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/event"
)

// Exercise the named public APIs, not just the composition helper. Missing AHP
// mode grants must fail before resolution, uploads, backend exchange, or effects.
func TestPublicElicitationModeAdmission(t *testing.T) {
	for _, mode := range []string{"form", "url"} {
		for _, operation := range []string{"return", "deny", "modify"} {
			if mode == "url" && operation == "modify" {
				continue
			} // URL answers have no content.
			for _, grant := range []string{"absent", "empty", "opposite", "explicit"} {
				t.Run(mode+"/"+operation+"/"+grant, func(t *testing.T) {
					stage := "request"
					original := elicitationForm // MCP omitted mode means form, NOT an AHP grant.
					answer := `{"action":"accept","content":{"x":"a"}}`
					if mode == "url" {
						original = `{"mode":"url","message":"open","url":"https://example.test","elicitationId":"opaque"}`
						answer = `{"action":"accept"}`
					}
					if operation == "modify" {
						stage = "result"
					}
					caps := map[string]any{"effects": []any{operation}}
					if operation == "modify" {
						caps["modify"] = map[string]any{"content": map[string]any{"replace": true, "merge": true}}
					}
					switch grant {
					case "empty":
						caps["elicitation"] = map[string]any{}
					case "opposite":
						opposite := "url"
						if mode == "url" {
							opposite = "form"
						}
						caps["elicitation"] = map[string]any{opposite: map[string]any{}}
					case "explicit":
						caps["elicitation"] = map[string]any{mode: map[string]any{}}
					}
					c, transports := testClient(t, "fail-open")
					setDispatchBoundary(c, "user.elicitation."+stage, caps)
					reads, uploads := 0, 0
					c.opts.Content.Resolver = func(_ context.Context, ref string) (io.ReadCloser, error) {
						reads++
						raw := original
						if ref == "result" {
							raw = answer
						}
						return io.NopCloser(strings.NewReader(raw)), nil
					}
					c.opts.UploadClient = &http.Client{Transport: contentTestRoundTripper(func(*http.Request) (*http.Response, error) {
						uploads++
						return nil, fmt.Errorf("unexpected upload for metadata subscription")
					})}
					effect := map[string]any{"type": operation}
					switch operation {
					case "return":
						effect["value"] = json.RawMessage(answer)
					case "deny":
						effect["reason"] = "host declines"
					case "modify":
						effect["target"] = "content"
						effect["operation"] = "replace"
						effect["value"] = map[string]any{"x": "a"}
					}
					transports[0].reply = func(map[string]any) []any { return []any{effect} }
					var result *Result
					var err error
					var inputBefore, inputAfter []byte
					capsBefore := string(sdkJSON(caps))
					if stage == "request" {
						inputMap := elicitationDispatchInput(stage, mode, original)
						input := event.UserElicitationRequestInput{ID: ahp.Some("request-id"), Time: ahp.Some("2026-01-01T00:00:00Z"), Session: ahp.Some(&ahp.Session{ID: "session"})}
						if err := json.Unmarshal(sdkJSON(inputMap["elicitation"]), &input.Elicitation); err != nil {
							t.Fatal(err)
						}
						input.Session = ahp.Optional[*ahp.Session]{Present: true, Value: &ahp.Session{ID: "session"}}
						inputBefore = sdkJSON(input)
						result, err = c.UserElicitationRequest(context.Background(), input)
						inputAfter = sdkJSON(input)
					} else {
						request, bodies := elicitationFixture("request", mode, original)
						request["source"] = c.opts.Source
						snapshot, snapshotErr := prepareElicitation(request, nil, elicitationOwners(request, bodies))
						if snapshotErr != nil {
							t.Fatal(snapshotErr)
						}
						input := event.UserElicitationResultInput{ID: ahp.Some("result-id"), Time: ahp.Some("2026-01-01T00:00:00Z")}
						inputMap := elicitationDispatchInput(stage, mode, answer)
						if err := json.Unmarshal(sdkJSON(inputMap["elicitation"]), &input.Elicitation); err != nil {
							t.Fatal(err)
						}
						input.ParentEventID = ahp.Optional[string]{Present: true, Value: "request-id"}
						input.Session = ahp.Optional[*ahp.Session]{Present: true, Value: &ahp.Session{ID: "session"}}
						inputBefore = sdkJSON(input)
						result, err = c.UserElicitationResult(context.Background(), input, WithElicitationRequest(snapshot))
						inputAfter = sdkJSON(input)
					}
					if string(inputBefore) != string(inputAfter) || string(sdkJSON(caps)) != capsBefore {
						t.Fatal("mutated caller input or grants")
					}
					if grant != "explicit" {
						if err == nil || !strings.Contains(err.Error(), "elicitation mode is not advertised") || result != nil || reads != 0 || uploads != 0 || len(transports[0].calls) != 0 {
							t.Fatalf("missing grant reached I/O or published: result=%+v err=%v reads=%d uploads=%d exchanges=%d", result, err, reads, uploads, len(transports[0].calls))
						}
					} else {
						if err != nil || result == nil {
							t.Fatalf("explicit grant rejected: %v", err)
						}
						waitObservations(t, result)
						if len(result.Errors) != 0 || len(result.Response.Effects) != 1 || len(transports[0].calls) != 1 {
							t.Fatalf("explicit grant did not accept decision: %+v", result)
						}
					}
				})
			}
		}
	}
}

func TestPublicElicitationInformationalDeliveryWithoutModeGrant(t *testing.T) {
	for _, effects := range [][]any{{}, {"message"}} {
		t.Run(fmt.Sprint(effects), func(t *testing.T) {
			c, transports := testClient(t, "fail-open")
			setDispatchBoundary(c, "user.elicitation.request", map[string]any{"effects": effects})
			inputMap := elicitationDispatchInput("request", "form", elicitationForm)
			delete(sdkObj(inputMap["elicitation"]), "request") // Deliberate metadata-only delivery.
			input := event.UserElicitationRequestInput{ID: ahp.Some("request-id"), Time: ahp.Some("2026-01-01T00:00:00Z"), Session: ahp.Some(&ahp.Session{ID: "session"})}
			if err := json.Unmarshal(sdkJSON(inputMap["elicitation"]), &input.Elicitation); err != nil {
				t.Fatal(err)
			}
			if len(effects) != 0 {
				transports[0].reply = func(map[string]any) []any {
					return []any{map[string]any{"type": "message", "text": "informational only"}}
				}
			}
			result, err := c.UserElicitationRequest(context.Background(), input)
			if err != nil || result == nil {
				t.Fatalf("informational delivery required a decision grant: %v", err)
			}
			waitObservations(t, result)
			if len(result.Errors) != 0 || len(result.Response.Effects) != len(effects) {
				t.Fatalf("informational delivery failed: %+v", result)
			}
		})
	}
}
