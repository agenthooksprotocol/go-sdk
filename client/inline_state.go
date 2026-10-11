package client

import (
	"context"
	"encoding/json"
	"errors"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

// projectReceiverState operates on generated candidate/injection payloads. Opaque
// provenance, unknown metadata and generic tool values never supply owner claims.
func (c *Hooks) projectReceiverState(ctx context.Context, event, state, sub map[string]any, backendID string, prepared *preparedBoundary) (map[string]any, error) {
	decoded, err := convertWire[ahp.InterceptRequestParamsState](state)
	if err != nil {
		return nil, err
	}
	kind := compositionString(event["type"])
	projectList := func(value any, textParts bool) (any, error) {
		field := "items"
		if textParts {
			field = "instructions"
		}
		wrapper := map[string]any{field: compositionValue(value)}
		indexed := prepared.clone()
		indexed.sources = map[string]*ContentSource{}
		if messages, ok := value.(*ahp.CanonicalMessages); ok {
			for nextPath, part := range canonicalAttachments(messages, "/"+field) {
				var owner *ContentSource
				for oldPath, source := range prepared.sources {
					if wireEqual(part, preparedAt(event, oldPath)) {
						if owner != nil && owner != source {
							owner = nil
							break
						}
						owner = source
					}
				}
				if owner != nil {
					indexed.sources[nextPath] = owner
				} else if part.AttachmentBodyPart.Present && part.AttachmentBodyPart.Value != nil {
					body := part.AttachmentBodyPart.Value
					*part = ahp.ContentItem{AttachmentGapPart: ahp.Some(&ahp.AttachmentGapPart{Category: body.Category, ID: body.ID, Kind: "attachment", MediaType: body.MediaType, Selection: "body", Synthesized: body.Synthesized, AdditionalProperties: body.AdditionalProperties, Gap: ahp.AttachmentGapPartGap{Reason: "unavailable"}})}
				}
			}
			wrapper[field] = compositionValue(messages)
		}
		safe, err := c.projectContentSlots(context.WithValue(ctx, preparedContextKey{}, indexed), wrapper, sub, backendID, schemaGraphSlots(value, "/"+field))
		if err != nil {
			return nil, err
		}
		if textParts {
			parts, err := convertWire[ahp.TextParts](safe[field])
			return &parts, err
		}
		messages, err := convertWire[ahp.CanonicalMessages](safe[field])
		return &messages, err
	}
	if decoded.Candidate.Valid {
		value, err := stateCandidate(kind, decoded)
		if err != nil {
			return nil, err
		}
		switch payload := value.(type) {
		case *ahp.CanonicalMessages:
			safe, err := projectList(payload, false)
			if err != nil {
				return nil, err
			}
			decoded.Candidate.Value.Value = sdkJSON(safe)
		case *ahp.TextParts:
			safe, err := projectList(payload, true)
			if err != nil {
				return nil, err
			}
			decoded.Candidate.Value.Value = sdkJSON(safe)
		default:
			if c.opts.Content.ProjectOpaque == nil {
				decoded.Candidate = ahp.Null[ahp.InterceptRequestParamsStateCandidateValue]()
			} else {
				scope := ContentAuthorization{Operation: "read", BackendID: backendID, Subscription: contentClone(sub).(map[string]any)}
				scope.SubscriptionID, _ = sub["id"].(string)
				opaque, err := contractJSON(decoded.Candidate.Value.Value)
				if err != nil {
					return nil, err
				}
				safe, err := c.opts.Content.ProjectOpaque(ctx, scope, "/state/candidate/value", opaque)
				if err != nil {
					return nil, err
				}
				raw, err := json.Marshal(safe)
				if err != nil {
					return nil, err
				}
				decoded.Candidate.Value.Value = raw
			}
		}
	}
	for _, injection := range decoded.Injections.Value {
		if injection == nil {
			return nil, errors.New("nil injection")
		}
		safe, err := projectList(injection.Value, false)
		if err != nil {
			return nil, err
		}
		injection.Value = safe.(*ahp.CanonicalMessages)
	}
	if decoded.Instructions.Present {
		parts := ahp.TextParts{}
		for _, text := range decoded.Instructions.Value {
			parts = append(parts, &ahp.TextPart{TextBodyPart: ahp.Some(&ahp.TextBodyPart{ID: "continuation", Kind: "text", MediaType: "text/plain", Selection: "body", Text: text})})
		}
		safe, err := projectList(&parts, true)
		if err != nil {
			return nil, err
		}
		visible := []string{}
		for _, part := range *safe.(*ahp.TextParts) {
			if part != nil && part.TextBodyPart.Present && part.TextBodyPart.Value != nil {
				visible = append(visible, part.TextBodyPart.Value.Text)
			}
		}
		decoded.Instructions = ahp.Some(visible)
	}
	return sdkMap(decoded)
}
