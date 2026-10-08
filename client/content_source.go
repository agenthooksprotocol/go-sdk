package client

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/agenthooksprotocol/go-sdk/content"
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

func contentSourceConfig(options []InterceptOption) interceptConfig {
	cfg := interceptConfig{}
	for _, option := range options {
		if option != nil {
			option(&cfg)
		}
	}
	return cfg
}

func (cfg interceptConfig) closeSources() {
	for _, source := range cfg.ownedSources {
		_ = source.Retire()
	}
}

func (cfg interceptConfig) bindSources(ctx context.Context, event map[string]any) (context.Context, error) {
	seen := map[*ContentSource]bool{}
	for path, source := range cfg.sources {
		item := preparedAt(event, path)
		if !contentItemPath(path) || item == nil {
			return ctx, errors.New("content source requires an existing canonical content item")
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
		seen[source] = true
	}
	ctx = context.WithValue(ctx, contentSourcesContextKey{}, cfg.sources)
	return context.WithValue(ctx, contentSourceBudgetKey{}, &contentSourceBudget{seen: map[*ContentSource]bool{}}), nil
}

type contentSourceBudgetKey struct{}

// One operation has a single bounded source cache, even during concurrent
// observation fan-out. Each source consumes the shared budget only once.
type contentSourceBudget struct {
	mu   sync.Mutex
	used int64
	seen map[*ContentSource]bool
}

func (b *contentSourceBudget) snapshot(ctx context.Context, source *ContentSource, limit, total int64) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !b.seen[source] && total-b.used < limit {
		limit = total - b.used
	}
	raw, err := source.Snapshot(ctx, limit)
	if err != nil {
		return nil, err
	}
	if !b.seen[source] {
		b.seen[source] = true
		b.used += int64(len(raw))
	}
	return raw, nil
}
