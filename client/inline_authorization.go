package client

import (
	"context"
	"errors"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"reflect"
)

// authorizeInlineEffects checks write authority against the receiver's delivery
// view. Accepted effects are then composed atomically against complete host state.
func (c *Hooks) authorizeInlineEffects(ctx context.Context, event, projected, sub map[string]any, backendID string, response ahp.InterceptResponse) (ahp.InterceptResponse, error) {
	raw, err := ahp.EncodeInterceptResponse(response)
	if err != nil {
		return ahp.InterceptResponse{}, err
	}
	envelope := compositionObject(raw)
	for _, rawEffect := range sdkArray(sdkObj(envelope["result"])["effects"]) {
		effect := sdkObj(rawEffect)
		target, _ := effect["target"].(string)
		if effect["type"] == "modify" && event["type"] == "user.elicitation.result" && target == "content" {
			item := preparedAt(projected, "/elicitation/result")
			if item == nil || item["selection"] != "body" || item["text"] == nil || item["gap"] != nil {
				return ahp.InterceptResponse{}, errors.New("elicitation answer edit requires authorized body disclosure")
			}
			writeItem := contentClone(item).(map[string]any)
			writeItem["text"] = string(sdkJSON(effect["value"]))
			if err := c.authorizeInlineWrite(ctx, writeItem, sub, backendID); err != nil {
				return ahp.InterceptResponse{}, err
			}
			continue
		}

		path, list := inlineTargetPath(event, target)
		typ := effect["type"]
		if typ == "inject" {
			path, list = "/items", true
		}
		if typ == "return" {
			switch event["type"] {
			case "model.request.before":
				path, list = "/items", true
			case "context.compact.before":
				path, list = "/instructions", true
			}
		}
		if !list || (typ != "modify" && typ != "inject" && typ != "return") || (typ == "modify" && !inlineListTarget(compositionString(event["type"]), target)) {
			continue
		}

		delivered := inlineAt(projected, path)
		if typ == "modify" && effect["operation"] == "replace" && inlineHasHiddenText(delivered) {
			return ahp.InterceptResponse{}, errors.New("cannot replace a list containing withheld text")
		}
		incoming := effect["value"]
		// Unchanged receiver-visible attachment receipts name the original owner,
		// not a new attachment. Preserve that owner's canonical descriptor locally.
		oldAttachments := inlineAttachments(inlineAt(event, path), path)
		projectedAttachments := inlineAttachments(delivered, path)
		for _, part := range inlineAttachments(incoming, path) {
			found := false
			for oldPath, visible := range projectedAttachments {
				if reflect.DeepEqual(part, visible) && visible["selection"] == "body" && visible["gap"] == nil {
					original := oldAttachments[oldPath]
					for key := range part {
						delete(part, key)
					}
					for key, value := range original {
						part[key] = contentClone(value)
					}
					found = true
					break
				}
			}
			if !found {
				return ahp.InterceptResponse{}, errors.New("attachment edit is not an authorized existing owner")
			}
		}
		var parts []map[string]any
		for _, raw := range sdkArray(incoming) {
			item := sdkObj(raw)
			if item["kind"] == "text" {
				parts = append(parts, item)
			}
			for _, rawPart := range sdkArray(item["parts"]) {
				part := sdkObj(rawPart)
				if part["kind"] == "text" {
					parts = append(parts, part)
				}
			}
		}
		for _, part := range parts {
			if err := c.authorizeInlineWrite(ctx, part, sub, backendID); err != nil {
				return ahp.InterceptResponse{}, err
			}
		}

	}
	parsed := ahp.ParseInterceptResponse(sdkJSON(envelope))
	if !parsed.OK {
		return ahp.InterceptResponse{}, errors.New("invalid authorized effects")
	}
	return parsed.Value, nil
}

// authorizeInlineWrite grants no authority from the receiver's content shape.
// Both category selection and a host-local write decision are required.
func (c *Hooks) authorizeInlineWrite(ctx context.Context, part, sub map[string]any, backendID string) error {
	selection := sdkObj(sub["content"])
	mode, _ := selection["default"].(string)
	if categoryMode, ok := selection[contentCategory(part)].(string); ok {
		mode = categoryMode
	}
	if mode != "body" || part["selection"] != "body" || c.opts.Content.AuthorizeContent == nil {
		return errors.New("inline text write is not authorized")
	}
	scope := ContentAuthorization{Operation: "write", BackendID: backendID, Subscription: contentClone(sub).(map[string]any), Item: contentClone(part).(map[string]any)}
	scope.SubscriptionID, _ = sub["id"].(string)
	allowed, err := c.opts.Content.AuthorizeContent(ctx, scope)
	if err != nil {
		return err
	}
	if !allowed {
		return errors.New("inline text write is not authorized")
	}
	return nil
}
