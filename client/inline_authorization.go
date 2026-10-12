package client

import (
	"context"
	"errors"
	ahp "github.com/agenthooksprotocol/go-sdk"
)

// authorizeInlineEffects visits only generated contextual payload variants.
// Opaque tool values and additional-property bags cannot name attachment owners
// or acquire text-write authority merely by resembling protocol JSON.
func (c *Hooks) authorizeInlineEffects(ctx context.Context, event, projected, sub map[string]any, backendID string, response ahp.InterceptResponse) (ahp.InterceptResponse, error) {
	kind := compositionString(event["type"])
	decoded := ahp.ResponseForRequest(kind, sdkJSON(response))
	if !decoded.OK {
		return ahp.InterceptResponse{}, errors.New("invalid correlated response")
	}
	effects, err := contextualEffects(decoded.Value)
	if err != nil {
		return ahp.InterceptResponse{}, err
	}
	for _, effect := range effects {
		if effect.kind == "modify" && kind == "user.elicitation.result" {
			delivered, err := convertWire[ahp.Event](projected)
			if err != nil {
				return ahp.InterceptResponse{}, err
			}
			descriptor := delivered.UserElicitationResultEvent.Value.Elicitation.Result
			if !descriptor.Present || descriptor.Value == nil || !descriptor.Value.TextBodyPart.Present || descriptor.Value.TextBodyPart.Value == nil {
				return ahp.InterceptResponse{}, errors.New("elicitation answer edit requires authorized body disclosure")
			}
			body := *descriptor.Value.TextBodyPart.Value
			body.Text = string(sdkJSON(effect.value))
			if err := c.authorizeInlineWrite(ctx, compositionObject(sdkJSON(body)), sub, backendID); err != nil {
				return ahp.InterceptResponse{}, err
			}
			continue
		}
		path, list := inlineTargetPath(event, effect.target)
		if effect.kind == "inject" {
			path, list = "/items", true
		}
		if effect.kind == "return" {
			switch effect.value.(type) {
			case *ahp.CanonicalMessages:
				path, list = "/items", true
			case *ahp.TextParts:
				path, list = "/instructions", true
			}
		}
		if !list || (effect.kind != "modify" && effect.kind != "inject" && effect.kind != "return") {
			continue
		}
		if effect.kind == "modify" && !effect.merge && inlineHasHiddenText(inlineAt(projected, path)) {
			return ahp.InterceptResponse{}, errors.New("cannot replace a list containing withheld text")
		}
		switch value := effect.value.(type) {
		case *ahp.CanonicalMessages:
			originalAttachments, err := eventAttachments(event)
			if err != nil {
				return ahp.InterceptResponse{}, err
			}
			visibleAttachments, err := eventAttachments(projected)
			if err != nil {
				return ahp.InterceptResponse{}, err
			}
			for _, part := range canonicalAttachments(value, path) {
				matched := false
				for oldPath, shown := range visibleAttachments {
					if !attachmentBodyAvailable(shown) || !wireEqual(part, shown) {
						continue
					}
					restored, err := convertWire[ahp.ContentItem](originalAttachments[oldPath])
					if err != nil {
						return ahp.InterceptResponse{}, err
					}
					*part = restored
					matched = true
					break
				}
				if !matched {
					return ahp.InterceptResponse{}, errors.New("attachment edit is not an authorized existing owner")
				}
			}
			for _, message := range *value {
				if message == nil {
					continue
				}
				for _, part := range message.Parts {
					if err := c.authorizeCanonicalText(ctx, part, sub, backendID); err != nil {
						return ahp.InterceptResponse{}, err
					}
				}
			}
		case *ahp.TextParts:
			for _, part := range *value {
				if part == nil {
					continue
				}
				content := ahp.ContentItem{TextBodyPart: part.TextBodyPart, TextGapPart: part.TextGapPart, TextMetadataPart: part.TextMetadataPart, TextOmittedPart: part.TextOmittedPart, Unknown: part.Unknown}
				if err := c.authorizeCanonicalText(ctx, &content, sub, backendID); err != nil {
					return ahp.InterceptResponse{}, err
				}
			}
		}
	}
	accepted := ahp.ParseInterceptResponse(sdkJSON(decoded.Value))
	if !accepted.OK {
		return ahp.InterceptResponse{}, errors.New("invalid authorized effects")
	}
	return accepted.Value, nil
}

func (c *Hooks) authorizeCanonicalText(ctx context.Context, part *ahp.ContentItem, sub map[string]any, backendID string) error {
	if part == nil {
		return nil
	}
	if part.TextBodyPart.Present {
		return c.authorizeInlineWrite(ctx, compositionObject(sdkJSON(part.TextBodyPart.Value)), sub, backendID)
	}
	if part.TextGapPart.Present || part.TextMetadataPart.Present || part.TextOmittedPart.Present {
		return errors.New("inline text write requires an authorized body")
	}
	return nil
}

func attachmentBodyAvailable(part *ahp.ContentItem) bool {
	return part != nil && part.AttachmentBodyPart.Present && part.AttachmentBodyPart.Value != nil
}
func wireEqual(a, b any) bool {
	left, _ := contractJSON(sdkJSON(a))
	right, _ := contractJSON(sdkJSON(b))
	return compositionEqual(left, right)
}

// authorizeInlineWrite is a host-local authorization callback boundary. Serialized
// Item is a pre-disclosure descriptor, never an opaque field traversal.
func (c *Hooks) authorizeInlineWrite(ctx context.Context, part, sub map[string]any, backendID string) error {
	selection := sdkObj(sub["content"])
	mode, _ := selection["default"].(string)
	if categoryMode, ok := selection[contentCategory(part)].(string); ok {
		mode = categoryMode
	}
	if mode != "body" || part["selection"] != "body" || c.opts.Content.AuthorizeContent == nil {
		return errors.New("inline text write is not authorized")
	}
	scope, err := contentAuthorization("write", backendID, sub)
	if err != nil {
		return err
	}
	scope.Item, err = contentDescriptor(part, "body")
	if err != nil {
		return err
	}
	allowed, err := c.opts.Content.AuthorizeContent(ctx, scope)
	if err != nil {
		return err
	}
	if !allowed {
		return errors.New("inline text write is not authorized")
	}
	return nil
}

func eventAttachments(event map[string]any) (map[string]*ahp.ContentItem, error) {
	slots, err := schemaSourceSlots(event)
	if err != nil {
		return nil, err
	}
	attachments := map[string]*ahp.ContentItem{}
	for path := range slots {
		part, err := convertWire[ahp.ContentItem](preparedAt(event, path))
		if err != nil {
			return nil, err
		}
		if part.AttachmentBodyPart.Present || part.AttachmentGapPart.Present || part.AttachmentMetadataPart.Present || part.AttachmentOmittedPart.Present {
			attachments[path] = &part
		}
	}
	return attachments, nil
}
