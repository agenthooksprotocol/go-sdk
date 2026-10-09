package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
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
	r.contentMu.Lock()
	defer r.contentMu.Unlock()
	if r.contentClosed {
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
				if v["body"] == nil {
					if raw, ok := p.sources[path].Available(); ok {
						out[path] = raw
					}
				}
				if raw, ok := p.bodies[compositionString(sdkObj(v["body"])["ref"])]; ok {
					out[path] = bytes.Clone(raw)
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

// ReadContent returns detached effective bytes, evaluating an unread attachment
// on demand. It remains usable after Hooks.Close. Legacy Content is non-reading.
func (r *Result) ReadContent(ctx context.Context, path string) ([]byte, error) {
	if r == nil || ctx == nil {
		return nil, errors.New("nil result or context")
	}
	r.contentMu.Lock()
	if r.contentClosed {
		r.contentMu.Unlock()
		return nil, errors.New("result is closed")
	}
	raw, ok := r.content[path]
	source, item := r.attachments[path], r.attachmentItems[path]
	budget, limit := r.attachmentBudget, r.attachmentLimit
	r.contentMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ok {
		return bytes.Clone(raw), nil
	}
	if source == nil {
		return nil, errors.New("content is unavailable")
	}
	raw, err := budget.snapshot(ctx, source, limit, limit)
	if err != nil {
		return nil, err
	}
	if err := contentMatches(item, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// Close releases retained bytes and unopened lazy attachments. It is idempotent
// and interrupts a concurrent attachment read. Results must not be copied.
func (r *Result) Close() error {
	if r == nil {
		return nil
	}
	r.contentMu.Lock()
	r.contentClosed = true
	r.content = nil
	sources := r.attachments
	r.contentMu.Unlock()
	var err error
	for _, source := range sources {
		err = errors.Join(err, source.Retire())
	}
	return err
}

func (r *Result) retainAttachments(cfg interceptConfig, ctx context.Context, limit int64) {
	var event map[string]any
	if json.Unmarshal(r.Event, &event) != nil {
		return
	}
	r.attachments = map[string]*ContentSource{}
	r.attachmentItems = map[string]map[string]any{}
	if limit == 0 {
		limit = 4 << 20
	}
	if limit == math.MaxInt64 {
		limit--
	}
	r.attachmentLimit = limit
	r.attachmentBudget, _ = ctx.Value(contentSourceBudgetKey{}).(*contentSourceBudget)
	if r.attachmentBudget == nil {
		r.attachmentBudget = &contentSourceBudget{seen: map[*ContentSource]bool{}}
	}
	for path, source := range cfg.sources {
		item := preparedAt(event, path)
		if !source.IsAttachment() || item == nil || item["body"] != nil {
			continue
		}
		r.attachments[path] = source
		r.attachmentItems[path] = item
		cfg.transferredSources[source] = true
	}
}
