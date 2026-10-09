package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/agenthooksprotocol/go-sdk/internal/ownedcontent"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

type preparedTestReader struct {
	io.Reader
	closes     *atomic.Int32
	closeError error
}

func (r *preparedTestReader) Close() error { r.closes.Add(1); return r.closeError }

func TestPreparedIntegrityLimitsAndOwnership(t *testing.T) {
	for _, mode := range []string{"valid", "body-size", "body-hash", "item-size", "item-hash", "invalid-UTF8", "invalid-JSON", "total-limit", "close-error"} {
		t.Run(mode, func(t *testing.T) {
			raw := []byte(` {"x":1} `)
			media := "application/json"
			if mode == "invalid-UTF8" {
				raw = []byte{255}
				media = "text/plain"
			}
			if mode == "invalid-JSON" {
				raw = []byte(`{"x":`)
			}
			item, bodies := targetTestItem("one", media, string(raw))
			second, more := targetTestItem("two", media, string(raw))
			for k, v := range more {
				bodies[k] = v
			}
			switch mode {
			case "body-size":
				sdkObj(item["body"])["size"] = 1
			case "body-hash":
				sdkObj(item["body"])["sha256"] = strings.Repeat("0", 64)
			case "item-size":
				item["size"] = 1
			case "item-hash":
				item["sha256"] = strings.Repeat("0", 64)
			}
			event := targetTestEvent(t, []any{item, second})
			closes := &atomic.Int32{}
			c := targetTestClient(bodies)
			c.opts.MaxContentBytes = 128
			if mode == "total-limit" {
				c.opts.MaxContentBytes = int64(len(raw))
			}
			c.opts.Content.Resolver = func(_ context.Context, ref string) (io.ReadCloser, error) {
				var err error
				if mode == "close-error" {
					err = errors.New("close failed")
				}
				return &preparedTestReader{Reader: bytes.NewReader(bodies[ref]), closes: closes, closeError: err}, nil
			}
			cfg := interceptConfig{}
			WithModificationTarget("output", ModificationTarget{Path: "/items"})(&cfg)
			prepared, err := c.prepareBoundary(context.Background(), event, targetTestCaps("output"), cfg)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				original := bytes.Clone(preparedTestBytes(prepared, "/items/0"))
				bodies["urn:test:one"][0] = 'x'
				if !bytes.Equal(preparedTestBytes(prepared, "/items/0"), original) {
					t.Fatal("resolver bytes retained by alias")
				}
				if closes.Load() != 2 {
					t.Fatal("readers not closed", closes.Load())
				}
			} else if err == nil {
				t.Fatal("invalid prepared body admitted")
			}
			if closes.Load() == 0 && mode != "body-size" && mode != "body-hash" && mode != "item-size" && mode != "item-hash" {
				t.Fatal("reader ownership lost")
			}
		})
	}
}

type preparedBlockingReader struct {
	started, done chan struct{}
	once          sync.Once
	closes        atomic.Int32
}

func (r *preparedBlockingReader) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.done
	return 0, io.ErrClosedPipe
}
func (r *preparedBlockingReader) Close() error {
	if r.closes.Add(1) == 1 {
		close(r.done)
	}
	return nil
}
func TestPreparedCancellationClosesReaderOnce(t *testing.T) {
	item, bodies := targetTestItem("one", "text/plain", "abc")
	event := targetTestEvent(t, []any{item})
	reader := &preparedBlockingReader{started: make(chan struct{}), done: make(chan struct{})}
	c := targetTestClient(bodies)
	c.opts.Content.Resolver = func(context.Context, string) (io.ReadCloser, error) { return reader, nil }
	cfg := interceptConfig{}
	WithModificationTarget("output", ModificationTarget{Path: "/items/0"})(&cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.prepareBoundary(ctx, event, targetTestCaps("output"), cfg); done <- err }()
	<-reader.started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock owned reader")
	}
	if reader.closes.Load() != 1 {
		t.Fatal("reader closed more than once")
	}
}

func TestPreparedAbsentInstructionsTemplate(t *testing.T) {
	event := map[string]any{"id": "test", "source": "urn:test", "time": "2026-01-01T00:00:00Z", "type": "context.compact.before", "trigger": "manual", "items": []any{}}
	parsed := ahp.ParseContentItem([]byte(`{"id":"host-owned-instructions","kind":"message","mediaType":"text/plain","selection":"metadata"}`))
	if !parsed.OK {
		t.Fatal(parsed.Diagnostics)
	}
	cfg := interceptConfig{}
	WithCompactionInstructions(parsed.Value)(&cfg)
	c := &Client{opts: Options{Content: ContentOptions{Resolver: func(context.Context, string) (io.ReadCloser, error) {
		t.Fatal("bodyless template resolved")
		return nil, nil
	}}}}
	prepared, err := c.prepareBoundary(context.Background(), event, targetTestCaps("instructions"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	values, err := prepared.values(event)
	if err != nil || values["instructions"] != nil {
		t.Fatal(values, err)
	}
	accepted := targetTestCompose(t, event, "instructions", prepared, `[{"type":"modify","target":"instructions","operation":"replace","value":"new instructions"}]`)
	effective := compositionObject(accepted.Event)
	item := sdkObj(effective["instructions"])
	if item["id"] != "host-owned-instructions" || item["selection"] != "metadata" || item["body"] != nil {
		t.Fatal(item)
	}
	raw := preparedTestBytes(accepted.prepared, "/instructions")
	if string(raw) != "new instructions" {
		t.Fatal(string(raw))
	}
	if len(prepared.sources) != 0 {
		t.Fatal("staging mutated original bodyless template")
	}
}

func preparedTestBytes(p *preparedBoundary, path string) []byte {
	raw, _ := ownedcontent.Available(p.sources[path])
	return raw
}

func TestPreparedCanonicalOwnerIndex(t *testing.T) {
	item, bodies := targetTestItem("one", "application/json", ` {"n":1} `)
	event := targetTestEvent(t, []any{item})
	p := targetTestPrepare(t, event, "output", bodies, ModificationTarget{Path: "/items/0"})
	original := p.sources["/items/0"]
	staged := p.clone()
	if staged.sources["/items/0"] != original || !p.owned[original] {
		t.Fatal("clone did not share attachment owner")
	}
	edited := contentClone(event).(map[string]any)
	if err := staged.apply(edited, "output", map[string]any{"n": 2}); err != nil {
		t.Fatal(err)
	}
	replacement := staged.sources["/items/0"]
	if replacement == original || p.sources["/items/0"] != original {
		t.Fatal("staging mutated the original slot index")
	}
	if !p.owned[replacement] || !staged.owned[original] || len(p.owned) != 2 {
		t.Fatal("clones lost shared lifecycle tracking")
	}
	descriptor := preparedAt(edited, "/items/0")
	if descriptor["selection"] != "metadata" || descriptor["body"] != nil || descriptor["id"] != "one" {
		t.Fatal("edit published a transport reference or lost host metadata", descriptor)
	}
	if string(preparedTestBytes(p, "/items/0")) != ` {"n":1} ` {
		t.Fatal("edit rewrote original owner bytes")
	}
	delete(edited, "items")
	staged.prune(edited)
	if len(staged.sources) != 0 || len(p.owned) != 2 {
		t.Fatal("pruning lost obsolete owners needed for final cleanup")
	}
	for owner := range p.owned {
		_ = owner.Retire()
	}
}

func TestPreparedReferenceOwnersRemainLazy(t *testing.T) {
	item, bodies := targetTestItem("one", "text/plain", "original")
	event := targetTestEvent(t, []any{item})
	var opens atomic.Int32
	c := targetTestClient(bodies)
	resolver := c.opts.Content.Resolver
	c.opts.Content.Resolver = func(ctx context.Context, ref string) (io.ReadCloser, error) {
		opens.Add(1)
		return resolver(ctx, ref)
	}
	p, err := c.prepareBoundary(context.Background(), event, nil, interceptConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for owner := range p.owned {
			_ = owner.Retire()
		}
	}()
	owner := p.sources["/items/0"]
	if owner == nil || !p.owned[owner] || opens.Load() != 0 {
		t.Fatal("inbound reference did not become a lazy canonical owner")
	}
	clone := p.clone()
	for _, source := range []*ContentSource{owner, clone.sources["/items/0"]} {
		raw, err := ownedcontent.Borrow(source, context.Background(), p.limit)
		if err != nil || string(raw) != "original" {
			t.Fatal(string(raw), err)
		}
	}
	if opens.Load() != 1 {
		t.Fatal("shared owner reopened inbound resolver", opens.Load())
	}
}

func TestPreparedEagerAttachmentsEnforceLimitsWithoutProjection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		payloads  []string
		wantError bool
	}{
		{"oversized-owner", []string{"123456789"}, true},
		{"aggregate", []string{"12345", "67890"}, true},
		{"exact-limit", []string{"1234", "5678"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := interceptConfig{sources: map[string]*ContentSource{}}
			items := make([]any, len(tc.payloads))
			for i, payload := range tc.payloads {
				item, _ := targetTestItem("item", "text/plain", "")
				item["selection"] = "metadata"
				delete(item, "body")
				items[i] = item
				source := ownedcontent.NewAttachment([]byte(payload))
				defer source.Retire()
				cfg.sources[fmt.Sprintf("/items/%d", i)] = source
			}
			WithModificationTarget("output", ModificationTarget{Path: "/items"})(&cfg)
			event := targetTestEvent(t, items)
			c := &Client{opts: Options{MaxContentBytes: 8}}
			// No receiver selection or upload runs: preparation itself must enforce limits.
			p, err := c.prepareBoundary(context.Background(), event, targetTestCaps("output"), cfg)
			if tc.wantError {
				if err == nil || p != nil {
					t.Fatal("oversized eager owners passed preparation")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.values(event); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPreparedValuesCheckLimitsBeforeDecoding(t *testing.T) {
	for _, tc := range []struct {
		name     string
		payloads []string
	}{
		{"oversized-owner", []string{"123456789"}},
		{"aggregate", []string{"12345", "67890"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &preparedBoundary{sources: map[string]*ContentSource{}, slots: map[string][]string{}, limit: 8}
			items := make([]any, len(tc.payloads))
			for i, payload := range tc.payloads {
				path := fmt.Sprintf("/items/%d", i)
				source := ownedcontent.NewAttachment([]byte(payload))
				defer source.Retire()
				p.sources[path] = source
				p.slots["output"] = append(p.slots["output"], path)
				items[i] = map[string]any{"id": path, "kind": "data", "mediaType": "application/json", "selection": "metadata"}
			}
			values, err := p.values(targetTestEvent(t, items))
			if err == nil || values != nil || !strings.Contains(err.Error(), "byte limit") {
				t.Fatal("values bypassed owner bounds", values, err)
			}
		})
	}
}
