package interop

import (
	"fmt"
	"strings"
)

// ProjectContent never grants access. BodyAllowed must come from receiver or
// host policy, not from event fields or a subscriber's requested selection.
func ProjectContent(event Object, selection map[string]string, bodyAllowed bool) (Object, error) {
	projected := obj(clone(event))
	if selection == nil {
		return projected, nil
	} // already selected wire fixture
	if selection["default"] == "" {
		return nil, fmt.Errorf("selection requires default")
	}
	for key, mode := range selection {
		switch key {
		case "default", "text", "reasoning", "images", "audio", "video", "files":
		default:
			continue // Unknown configuration fields have no selection authority.
		}
		if mode != "body" && mode != "metadata" && mode != "omit" {
			return nil, fmt.Errorf("invalid content selection")
		}
	}
	items := []any{}
	for _, raw := range array(projected["items"]) {
		item := obj(raw)
		category := str(item["category"])
		if item["kind"] == "reasoning" {
			category = "reasoning"
		} else if category == "" {
			media := str(item["mediaType"])
			switch {
			case strings.HasPrefix(media, "text/"):
				category = "text"
			case strings.HasPrefix(media, "image/"):
				category = "images"
			case strings.HasPrefix(media, "audio/"):
				category = "audio"
			case strings.HasPrefix(media, "video/"):
				category = "video"
			default:
				category = "files"
			}
		}
		mode, ok := selection[category]
		if !ok {
			mode = selection["default"]
		}
		if mode == "omit" {
			continue
		}
		if mode == "body" && !bodyAllowed {
			return nil, fmt.Errorf("unauthorized content body selection")
		}
		if mode == "metadata" {
			delete(item, "body")
			delete(item, "gap")
			item["selection"] = "metadata"
		}
		// Projection cannot manufacture an unavailable body; an existing metadata
		// descriptor stays metadata, or the producer supplies an explicit gap.
		items = append(items, item)
	}
	if _, ok := projected["items"]; ok {
		projected["items"] = items
	}
	return projected, nil
}
