package client

import (
	"bytes"
	"strconv"
)

// Content returns detached effective body bytes at a canonical event item path
// (for example /instructions, /summary, or /items/0). Only bodies resolved by
// this occurrence are available. A result's opaque internal references are not
// receiver references and must never be copied into an outbound wire message.
func (r *Result) Content(path string) ([]byte, bool) {
	if r == nil {
		return nil, false
	}
	raw, ok := r.content[path]
	return bytes.Clone(raw), ok
}

func preparedContent(event map[string]any, p *preparedBoundary) map[string][]byte {
	out := map[string][]byte{}
	var walk func(any, string)
	walk = func(value any, path string) {
		switch v := value.(type) {
		case map[string]any:
			if contentItemPath(path) {
				if raw, ok := p.bodies[compositionString(sdkObj(v["body"])["ref"])]; ok {
					out[path] = raw
				}
				return
			}
			for key, child := range v {
				walk(child, path+"/"+key)
			}
		case []any:
			for i, child := range v {
				walk(child, path+"/"+strconv.Itoa(i))
			}
		}
	}
	walk(event, "")
	return out
}
