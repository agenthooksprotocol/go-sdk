package client

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/internal/ownedcontent"
)

// ContentSource is an owned single-occurrence stream. It is not a wire reference.
type ContentSource = content.Source

// NewContentSource wraps an owned reader without reading or uploading bytes.
func NewContentSource(reader io.ReadCloser) *ContentSource { return content.NewSource(reader) }

type contentSourcesContextKey struct{}

// WithContentSource binds an owned stream to an existing canonical content item.
// The item supplies identity and media metadata; it must not have a body reference.
// Prefer generated named input source fields when available. This path-based
// option is the advanced escape hatch, not a wire field or a content reference.
func WithContentSource(path string, source *ContentSource) InterceptOption {
	return func(cfg *interceptConfig) {
		if cfg.sources == nil {
			cfg.sources = map[string]*ContentSource{}
		}
		cfg.sources[path] = source
		cfg.ownedSources = append(cfg.ownedSources, source)
	}
}

// withHostContentSource is the generated boundary's internal source collection.
// A supplied wire descriptor never changes the exact owner selected for delivery.
func withHostContentSource(path string, source *ContentSource) InterceptOption {
	return func(cfg *interceptConfig) {
		WithContentSource(path, source)(cfg)
		if cfg.hostSources == nil {
			cfg.hostSources = map[string]bool{}
		}
		cfg.hostSources[path] = true
	}
}

func contentSourceConfig(options []InterceptOption) interceptConfig {
	cfg := interceptConfig{claimedSources: map[*ContentSource]bool{}, transferredSources: map[*ContentSource]bool{}}
	for _, option := range options {
		if option != nil {
			option(&cfg)
		}
	}
	return cfg
}

func (cfg interceptConfig) closeSources() {
	for _, source := range cfg.ownedSources {
		if cfg.transferredSources[source] || (source.Claimed() && !cfg.claimedSources[source]) {
			continue
		}
		_ = source.Retire()
	}
}

func (cfg interceptConfig) bindSources(ctx context.Context, event map[string]any) (context.Context, error) {
	seen := map[*ContentSource]bool{}
	for path, source := range cfg.sources {
		item := preparedAt(event, path)
		if !canonicalPartPath(event, path) || item == nil {
			return ctx, errors.New("content source requires an existing canonical content item")
		}
		if item["kind"] != "attachment" {
			return ctx, errors.New("owned sources require immutable attachment parts")
		}
		if item["body"] != nil {
			return ctx, errors.New("content source conflicts with an existing body reference")
		}
		if source == nil {
			return ctx, errors.New("content source requires a reader")
		}
		if !seen[source] && !source.Claim() {
			return ctx, errors.New("content source already belongs to an occurrence")
		}
		cfg.claimedSources[source] = true
		seen[source] = true
	}
	ctx = context.WithValue(ctx, contentSourcesContextKey{}, cfg.sources)
	return context.WithValue(ctx, contentSourceBudgetKey{}, &contentSourceBudget{seen: map[*ContentSource]bool{}}), nil
}

type contentSourceBudgetKey struct{}

// One operation has a shared bounded owner budget, including concurrent
// observation fan-out. Byte storage remains solely in each attachment owner.
type contentSourceBudget struct {
	mu      sync.Mutex
	used    int64
	seen    map[*ContentSource]bool
	pending *ContentSource
	active  int
	changed chan struct{}
}

func (b *contentSourceBudget) snapshot(ctx context.Context, source *ContentSource, limit, total int64) ([]byte, error) {
	// Different owners retain the aggregate admission order. Same-owner callers
	// join its materializer instead of waiting behind a mutex held across I/O.
	for {
		b.mu.Lock()
		if err := ctx.Err(); err != nil {
			b.mu.Unlock()
			return nil, err
		}
		// Confirmed owners are already charged once. Their immutable bytes
		// do not compete with a different pending owner's admission.
		if b.seen[source] {
			b.mu.Unlock()
			return ownedcontent.Borrow(source, ctx, limit)
		}
		if b.active == 0 || b.pending == source {
			break
		}
		changed := b.changed
		b.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if b.active == 0 {
		b.pending = source
		b.changed = make(chan struct{})
	}
	b.active++
	if !b.seen[source] && total-b.used < limit {
		limit = total - b.used
	}
	b.mu.Unlock()
	raw, err := ownedcontent.Borrow(source, ctx, limit)
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil && !b.seen[source] {
		if int64(len(raw)) > total-b.used {
			raw, err = nil, errors.New("content exceeds occurrence byte limit")
		} else {
			if b.seen == nil {
				b.seen = map[*ContentSource]bool{}
			}
			b.seen[source] = true
			b.used += int64(len(raw))
		}
	}
	b.active--
	if b.active == 0 {
		b.pending = nil
		close(b.changed)
	}
	return raw, err
}

// forget removes accounting for an owner retired after an edit transaction.
// This index never owns bytes; each live attachment owns its own snapshot.
func (b *contentSourceBudget) forget(source *ContentSource) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.seen[source] {
		raw, _ := ownedcontent.Available(source)
		b.used -= int64(len(raw))
		delete(b.seen, source)
	}
}

// reconcile accounts all materialized effective owners, including eager inputs,
// preparation reads and edits. It owns no buffers and never opens lazy sources.
func (b *contentSourceBudget) reconcile(sources map[string]*ContentSource, limit int64) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	seen := map[*ContentSource]bool{}
	var used int64
	for _, source := range sources {
		if seen[source] {
			continue
		}
		raw, available := ownedcontent.Available(source)
		if !available {
			continue
		}
		if int64(len(raw)) > limit-used {
			return errors.New("content exceeds occurrence byte limit")
		}
		seen[source] = true
		used += int64(len(raw))
	}
	b.seen, b.used = seen, used
	return nil
}
