package client

import (
	"errors"
	"fmt"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
	"reflect"
	"strings"
)

// inlineTargetPath identifies canonical edit containers, not native payloads.
func inlineTargetPath(event map[string]any, target string) (string, bool) {
	kind, _ := event["type"].(string)
	if target != compositionTargets[kind] {
		return "", false
	}
	switch target {
	case "instructions", "summary":
		return "/" + target, true
	case "prompt", "request", "response", "output":
		if kind == "user.message.inbound" || kind == "user.message.outbound" {
			return "/message/messages", true
		}
		return "/items", true
	case "content":
		if kind == "user.elicitation.result" {
			return "/elicitation/result", true
		}
		return "/message/messages", true
	}
	return "", false
}
func inlineListTarget(kind, target string) bool {
	_, ok := inlineTargetPath(map[string]any{"type": kind}, target)
	return ok && !(kind == "user.elicitation.result" && target == "content")
}
func inlineAt(event map[string]any, path string) any {
	if strings.HasPrefix(path, "/message/") {
		return sdkObj(event["message"])[strings.TrimPrefix(path, "/message/")]
	}
	if strings.HasPrefix(path, "/elicitation/") {
		return sdkObj(event["elicitation"])[strings.TrimPrefix(path, "/elicitation/")]
	}
	return event[strings.TrimPrefix(path, "/")]
}
func inlineSet(event map[string]any, path string, value any) {
	if strings.HasPrefix(path, "/message/") {
		sdkObj(event["message"])[strings.TrimPrefix(path, "/message/")] = value
		return
	}
	event[strings.TrimPrefix(path, "/")] = value
}

// inlineAttachments visits only canonical list entries and message.parts. It does not inspect
// descriptor-shaped opaque application objects.
func inlineAttachments(value any, path string) map[string]map[string]any {
	found := map[string]map[string]any{}
	for i, raw := range sdkArray(value) {
		message := sdkObj(raw)
		if message["kind"] == "attachment" {
			found[fmt.Sprintf("%s/%d", path, i)] = message
		}
		for j, rawPart := range sdkArray(message["parts"]) {
			part := sdkObj(rawPart)
			if part["kind"] == "attachment" {
				found[fmt.Sprintf("%s/%d/parts/%d", path, i, j)] = part
			}
		}
	}
	return found
}
func (p *preparedBoundary) validateInlineAttachments(event map[string]any, path string, value any) error {
	old := inlineAttachments(inlineAt(event, path), path)
	next := inlineAttachments(value, path)
	owners := map[string]*ContentSource{}
	for nextPath, item := range next {
		matched := false
		var owner *ContentSource
		for oldPath, previous := range old {
			if reflect.DeepEqual(item, previous) {
				candidate := p.sources[oldPath]
				if matched && candidate != owner {
					return errors.New("ambiguous attachment identity refers to distinct owners")
				}
				matched = true
				owner = candidate
			}
		}
		if !matched {
			return errors.New("attachment modification must preserve an existing immutable descriptor")
		}
		if owner != nil {
			owners[nextPath] = owner
		}
	}

	for oldPath := range old {
		delete(p.sources, oldPath)
	}
	for nextPath, source := range owners {
		p.sources[nextPath] = source
	}
	return nil
}

func inlineHasHiddenText(value any) bool {
	for _, raw := range sdkArray(value) {
		item := sdkObj(raw)
		if item["gap"] != nil || (item["kind"] == "text" && item["selection"] != "body") {
			return true
		}
		for _, rawPart := range sdkArray(item["parts"]) {
			part := sdkObj(rawPart)
			if part["gap"] != nil || (part["kind"] == "text" && part["selection"] != "body") {
				return true
			}
		}
	}
	return false
}

func validateSuppliedValue(kind string, value any) error {
	switch kind {
	case "context.compact.before":
		if err := canonical.Validate("content-item#textParts", sdkJSON(value)); err != nil {
			return errors.New("compaction summary must be a canonical text-part list")
		}
	case "model.request.before":
		if err := canonical.Validate("content-item#messages", sdkJSON(value)); err != nil {
			return errors.New("supplied model result must be canonical messages")
		}
	}
	return nil
}
