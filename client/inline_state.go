package client

import (
	"context"
	"reflect"
)

// projectReceiverState protects content-bearing cumulative decisions exactly as
// event content. The complete state remains host-owned for serial composition.
func (c *Hooks) projectReceiverState(ctx context.Context, event, state, sub map[string]any, backendID string, prepared *preparedBoundary) (map[string]any, error) {
	out := contentClone(state).(map[string]any)
	projectList := func(value any, textParts bool) (any, error) {
		field, kind := "items", "model.request.before"
		if textParts {
			field, kind = "instructions", "context.compact.before"
		}
		wrapper := map[string]any{"type": kind, field: contentClone(value)}
		indexed := prepared.clone()
		indexed.sources = map[string]*ContentSource{}
		for nextPath, part := range inlineAttachments(wrapper[field], "/"+field) {
			var owner *ContentSource
			for oldPath, source := range prepared.sources {
				if reflect.DeepEqual(part, preparedAt(event, oldPath)) {
					if owner != nil && owner != source {
						owner = nil
						break
					}
					owner = source
				}
			}
			if owner != nil {
				indexed.sources[nextPath] = owner
			} else {
				// A reference supplied through state is not a new authorization/source claim.
				delete(part, "body")
				part["selection"] = "body"
				part["gap"] = map[string]any{"reason": "unavailable"}
			}
		}
		safe, err := c.projectContent(context.WithValue(ctx, preparedContextKey{}, indexed), wrapper, sub, backendID)
		if err != nil {
			return nil, err
		}
		return safe[field], nil
	}
	if candidate := sdkObj(out["candidate"]); candidate != nil {
		switch event["type"] {
		case "model.request.before", "context.compact.before":
			safe, err := projectList(candidate["value"], event["type"] == "context.compact.before")
			if err != nil {
				return nil, err
			}
			candidate["value"] = safe
		default:
			// Non-content candidates are host-native JSON, never recursively inspected.
			if c.opts.Content.ProjectOpaque == nil {
				out["candidate"] = nil
			} else {
				scope := ContentAuthorization{Operation: "read", BackendID: backendID, Subscription: contentClone(sub).(map[string]any)}
				scope.SubscriptionID, _ = sub["id"].(string)
				safe, err := c.opts.Content.ProjectOpaque(ctx, scope, "/state/candidate/value", candidate["value"])
				if err != nil {
					return nil, err
				}
				candidate["value"] = contentClone(safe)
			}
		}
	}
	for _, raw := range sdkArray(out["injections"]) {
		injection := sdkObj(raw)
		safe, err := projectList(injection["value"], false)
		if err != nil {
			return nil, err
		}
		injection["value"] = safe
	}
	// Continuation instructions have a string-only wire slot. Withhold the slot
	// when text disclosure is unavailable instead of inventing string gap markers.
	if instructions := sdkArray(out["instructions"]); instructions != nil {
		parts := make([]any, len(instructions))
		for i, text := range instructions {
			parts[i] = map[string]any{"id": "continuation", "kind": "text", "mediaType": "text/plain", "selection": "body", "text": text}
		}
		safe, err := projectList(parts, true)
		if err != nil {
			return nil, err
		}
		visible := []any{}
		for _, raw := range sdkArray(safe) {
			part := sdkObj(raw)
			if text, ok := part["text"]; ok {
				visible = append(visible, text)
			}
		}
		out["instructions"] = visible
	}
	return out, nil
}
