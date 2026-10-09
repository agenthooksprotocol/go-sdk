package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/agenthooksprotocol/go-sdk/internal/ownedcontent"
	"math"
)

// Content returns a defensive copy of already materialized effective content at
// a canonical item path. It never opens a lazy attachment. Use ReadContent to
// demand unread content. Successful results own their attachments until Close.
func (r *Result) Content(path string) ([]byte, bool) {
	if r == nil {
		return nil, false
	}
	r.contentMu.Lock()
	if r.contentClosed {
		r.contentMu.Unlock()
		return nil, false
	}
	source := r.attachments[path]
	item := r.attachmentItems[path]
	budget, limit := r.attachmentBudget, r.attachmentLimit
	r.contentMu.Unlock()
	if _, ok := ownedcontent.Available(source); !ok {
		return nil, false
	}
	raw, err := budget.snapshot(context.Background(), source, limit, limit)
	if err != nil || contentMatches(item, raw) != nil {
		return nil, false
	}
	return bytes.Clone(raw), true
}

// ReadContent reads the effective attachment owner, returning a defensive copy.
// There is no result body store: selected upload and returned content share the
// same owner. The result remains usable after Hooks.Close.
func (r *Result) ReadContent(ctx context.Context, path string) ([]byte, error) {
	if r == nil || ctx == nil {
		return nil, errors.New("nil result or context")
	}
	r.contentMu.Lock()
	if r.contentClosed {
		r.contentMu.Unlock()
		return nil, errors.New("result is closed")
	}
	source, item := r.attachments[path], r.attachmentItems[path]
	budget, limit := r.attachmentBudget, r.attachmentLimit
	r.contentMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
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
	return bytes.Clone(raw), nil
}

// Close releases effective owners, including unopened sources, and interrupts
// active reads. It is idempotent. Results must not be copied.
func (r *Result) Close() error {
	if r == nil {
		return nil
	}
	r.contentMu.Lock()
	r.contentClosed = true
	sources := r.attachments
	r.contentMu.Unlock()
	var err error
	for _, source := range sources {
		err = errors.Join(err, source.Retire())
	}
	return err
}

func (r *Result) retainAttachments(cfg interceptConfig, ctx context.Context, prepared *preparedBoundary, limit int64) {
	if prepared == nil {
		return
	}
	var event map[string]any
	if json.Unmarshal(r.Event, &event) != nil {
		return
	}
	r.attachments = map[string]*ContentSource{}
	r.attachmentItems = map[string]map[string]any{}
	r.effectiveTargets = map[string][]string{}
	r.effectiveBindings = map[string]ModificationTarget{}
	for target, paths := range prepared.slots {
		r.effectiveTargets[target] = append([]string(nil), paths...)
	}
	for target, binding := range prepared.bindings {
		r.effectiveBindings[target] = binding
	}
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
	for path, source := range prepared.sources {
		item := preparedAt(event, path)
		if source == nil || item == nil {
			continue
		}
		r.attachments[path] = source
		r.attachmentItems[path] = item
		cfg.transferredSources[source] = true
	}
}

// EffectiveValue encodes an already available effective text/JSON or native
// target on demand. It replaces the former retained EffectiveValues byte map.
// Call ReadContent first to demand an unread attachment. No encoded value is cached.
func (r *Result) EffectiveValue(target string) (json.RawMessage, error) {
	if r == nil {
		return nil, errors.New("nil result")
	}
	r.contentMu.Lock()
	if r.contentClosed {
		r.contentMu.Unlock()
		return nil, errors.New("result is closed")
	}
	p := &preparedBoundary{sources: r.attachments, slots: r.effectiveTargets, bindings: r.effectiveBindings, limit: r.attachmentLimit, snapshot: r.Snapshot}
	r.contentMu.Unlock()
	var event map[string]any
	if err := json.Unmarshal(r.Event, &event); err != nil {
		return nil, err
	}
	values, err := p.values(event)
	if err != nil {
		return nil, err
	}
	value, ok := values[target]
	if !ok {
		return nil, errors.New("effective target is unavailable")
	}
	return sdkJSON(value), nil
}
