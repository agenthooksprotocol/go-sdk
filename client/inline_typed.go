package client

import (
	"encoding/json"
	"fmt"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

// knownInlineTextParts uses the originating request's canonical container, never
// array-shape guesses. Unknown union variants and additional properties remain
// opaque: in particular, a text part's unknown "parts" member grants no writes.
// Contextual effect payload unions can replace this decoding step once generated.
func knownInlineTextParts(path string, value any) ([]map[string]any, error) {
	var parts []map[string]any
	appendPart := func(v any) { parts = append(parts, compositionObject(sdkJSON(v))) }
	if path == "/instructions" || path == "/summary" {
		var texts ahp.TextParts
		if err := json.Unmarshal(sdkJSON(value), &texts); err != nil {
			return nil, err
		}
		for _, p := range texts {
			if p == nil {
				continue
			}
			switch {
			case p.TextBodyPart.Present:
				appendPart(p.TextBodyPart.Value)
			case p.TextGapPart.Present:
				appendPart(p.TextGapPart.Value)
			case p.TextMetadataPart.Present:
				appendPart(p.TextMetadataPart.Value)
			case p.TextOmittedPart.Present:
				appendPart(p.TextOmittedPart.Value)
			}
		}
		return parts, nil
	}
	var messages ahp.CanonicalMessages
	if err := json.Unmarshal(sdkJSON(value), &messages); err != nil {
		return nil, err
	}
	for _, message := range messages {
		if message == nil {
			continue
		}
		for _, p := range message.Parts {
			if p == nil {
				continue
			}
			switch {
			case p.TextBodyPart.Present:
				appendPart(p.TextBodyPart.Value)
			case p.TextGapPart.Present:
				appendPart(p.TextGapPart.Value)
			case p.TextMetadataPart.Present:
				appendPart(p.TextMetadataPart.Value)
			case p.TextOmittedPart.Present:
				appendPart(p.TextOmittedPart.Value)
			}
		}
	}
	return parts, nil
}

func canonicalAttachments(messages *ahp.CanonicalMessages, path string) map[string]*ahp.ContentItem {
	found := map[string]*ahp.ContentItem{}
	if messages == nil {
		return found
	}
	for i, message := range *messages {
		if message == nil {
			continue
		}
		for j, part := range message.Parts {
			if part != nil && (part.AttachmentBodyPart.Present || part.AttachmentGapPart.Present || part.AttachmentMetadataPart.Present || part.AttachmentOmittedPart.Present) {
				found[fmt.Sprintf("%s/%d/parts/%d", path, i, j)] = part
			}
		}
	}
	return found
}
