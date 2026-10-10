package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/internal/ownedcontent"
	"io"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func preparedOwnerText(id, text string) map[string]any {
	return map[string]any{"id": id, "kind": "text", "mediaType": "text/plain", "selection": "body", "text": text}
}
func preparedOwnerAttachment(id string) map[string]any {
	return map[string]any{"id": id, "kind": "attachment", "mediaType": "application/octet-stream", "selection": "metadata"}
}
func preparedOwnerMessage(id string, parts ...any) map[string]any {
	return map[string]any{"id": id, "role": "assistant", "parts": parts}
}
func preparedOwnerEvent(items ...any) map[string]any {
	return map[string]any{"id": "test", "source": "urn:test", "time": "2026-01-01T00:00:00Z", "type": "model.response.after", "model": map[string]any{"id": "model", "provider": "test"}, "attempt": map[string]any{"id": "attempt", "number": 1}, "execution": map[string]any{"status": "executed"}, "finishReason": "stop", "items": items}
}
func preparedOwnerCaps(target string) map[string]any {
	return map[string]any{"effects": []any{"modify"}, "modify": map[string]any{target: map[string]any{"replace": true, "merge": true}}}
}
func preparedOwnerPrepare(t *testing.T, event map[string]any, target string, cfg interceptConfig) *preparedBoundary {
	t.Helper()
	p, err := (&Client{opts: Options{Content: ContentOptions{AuthorizeContent: contentTestAllow}}}).prepareBoundary(context.Background(), event, preparedOwnerCaps(target), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func preparedOwnerCompose(t *testing.T, event map[string]any, target string, p *preparedBoundary, values ...any) (*Composition, error) {
	t.Helper()
	req := ahp.ParseInterceptRequest(sdkJSON(map[string]any{"jsonrpc": "2.0", "id": "test", "method": "hooks/intercept", "params": map[string]any{"protocolVersion": "draft", "event": event, "capabilities": preparedOwnerCaps(target)}}))
	if !req.OK {
		t.Fatal(req.Diagnostics)
	}
	effects := []any{}
	for _, v := range values {
		effects = append(effects, map[string]any{"type": "modify", "target": target, "operation": "replace", "value": v})
	}
	return composePrepared(req.Value, compositionTestResponse(t, string(sdkJSON(effects))), p)
}
func preparedTestBytes(p *preparedBoundary, path string) []byte {
	raw, _ := ownedcontent.Available(p.sources[path])
	return raw
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

type preparedTestReader struct {
	io.Reader
	closes     *atomic.Int32
	closeError error
}

func (r *preparedTestReader) Close() error { r.closes.Add(1); return r.closeError }

func TestPreparedIntegrityLimitsAndOwnership(t *testing.T) {
	for _, text := range []string{"plain", ` {"x":1} `, `{"x":`} {
		t.Run(text, func(t *testing.T) {
			event := preparedOwnerEvent(preparedOwnerMessage("one", preparedOwnerText("text", text)))
			c := &Client{opts: Options{Content: ContentOptions{Resolver: func(context.Context, string) (io.ReadCloser, error) { t.Fatal("inline text resolved"); return nil, nil }}}}
			p, err := c.prepareBoundary(context.Background(), event, preparedOwnerCaps("response"), interceptConfig{})
			if err != nil {
				t.Fatal(err)
			}
			values, err := p.values(event)
			if err != nil || !reflect.DeepEqual(values["response"], event["items"]) || len(p.sources) != 0 || len(p.owned) != 0 {
				t.Fatal("inline text changed or acquired owners", values, err)
			}
			accepted, err := preparedOwnerCompose(t, event, "response", p, []any{preparedOwnerMessage("one", preparedOwnerText("text", "edited"))})
			if err != nil {
				t.Fatal(err)
			}
			if len(accepted.prepared.sources) != 0 || len(accepted.prepared.owned) != 0 {
				t.Fatal("text edit allocated owners")
			}
		})
	}
	for _, mode := range []string{"size", "hash"} {
		t.Run(mode, func(t *testing.T) {
			metadata := map[string]any{}
			if mode == "size" {
				metadata["size"] = 1
			} else {
				metadata["sha256"] = strings.Repeat("0", 64)
			}
			if err := contentMatches(metadata, []byte("binary")); err == nil {
				t.Fatal("invalid immutable metadata accepted")
			}
		})
	}
	for _, mode := range []string{"valid", "binary-non-UTF8", "binary-non-JSON", "close-error", "total-limit"} {
		t.Run(mode, func(t *testing.T) {
			raw := []byte("immutable")
			if mode == "binary-non-UTF8" {
				raw = []byte{255}
			}
			if mode == "binary-non-JSON" {
				raw = []byte(`{"x":`)
			}
			var closes atomic.Int32
			var closeErr error
			if mode == "close-error" {
				closeErr = errors.New("close failed")
			}
			owner := ownedcontent.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
				return &preparedTestReader{Reader: bytes.NewReader(raw), closes: &closes, closeError: closeErr}, nil
			}, nil)
			defer owner.Retire()
			cfg := interceptConfig{}
			WithContentSource("/items/0/parts/0", owner)(&cfg)
			p := preparedOwnerPrepare(t, preparedOwnerEvent(preparedOwnerMessage("one", preparedOwnerAttachment("binary"))), "response", cfg)
			if closes.Load() != 0 {
				t.Fatal("preparation eagerly opened binary")
			}
			limit := p.limit
			if mode == "total-limit" {
				limit = 1
			}
			snapshot, err := ownedcontent.Borrow(owner, context.Background(), limit)
			bad := mode == "close-error" || mode == "total-limit"
			if (err != nil) != bad {
				t.Fatal("unexpected binary snapshot error", err)
			}
			if closes.Load() != 1 {
				t.Fatal("reader not closed once", closes.Load())
			}
			if !bad {
				original := bytes.Clone(snapshot)
				raw[0] = 'x'
				if !bytes.Equal(preparedTestBytes(p, "/items/0/parts/0"), original) {
					t.Fatal("resolver bytes retained by alias")
				}
			}
		})
	}

}
func TestPreparedCancellationClosesReaderOnce(t *testing.T) {
	reader := &preparedBlockingReader{started: make(chan struct{}), done: make(chan struct{})}
	source := ownedcontent.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) { return reader, nil }, nil)
	defer source.Retire()
	cfg := interceptConfig{}
	WithContentSource("/items/0/parts/0", source)(&cfg)
	event := preparedOwnerEvent(preparedOwnerMessage("one", preparedOwnerAttachment("binary")))
	p := preparedOwnerPrepare(t, event, "response", cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = context.WithValue(ctx, preparedContextKey{}, p)
	c := &Client{opts: Options{Content: ContentOptions{AuthorizeContent: contentTestAllow}}}
	done := make(chan error, 1)
	go func() {
		_, err := c.projectContent(ctx, event, contentTestSubscription("http://unused.invalid"), "backend")
		done <- err
	}()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("selected attachment was not opened")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock reader")
	}
	if reader.closes.Load() != 1 {
		t.Fatal("reader close count", reader.closes.Load())
	}
}
func TestPreparedAbsentInstructionsTemplate(t *testing.T) {
	event := map[string]any{"id": "test", "source": "urn:test", "time": "2026-01-01T00:00:00Z", "type": "context.compact.before", "trigger": "manual", "items": []any{}}
	p := preparedOwnerPrepare(t, event, "instructions", interceptConfig{})
	values, err := p.values(event)
	if err != nil || len(sdkArray(values["instructions"])) != 0 {
		t.Fatal(values, err)
	}
	parts := []any{preparedOwnerText("instructions", "new instructions")}
	accepted, err := preparedOwnerCompose(t, event, "instructions", p, parts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(compositionObject(accepted.Event)["instructions"], parts) || len(p.sources) != 0 || len(accepted.prepared.owned) != 0 {
		t.Fatal("instructions not inline")
	}
}
func TestPreparedCanonicalOwnerIndex(t *testing.T) {
	source := ownedcontent.NewAttachment([]byte("immutable"))
	defer source.Retire()
	part := preparedOwnerAttachment("binary")
	event := preparedOwnerEvent(preparedOwnerMessage("one", part, preparedOwnerText("text", ` {"n":1} `)))
	cfg := interceptConfig{}
	WithContentSource("/items/0/parts/0", source)(&cfg)
	p := preparedOwnerPrepare(t, event, "response", cfg)
	staged := p.clone()
	edited := contentClone(event).(map[string]any)
	next := []any{preparedOwnerMessage("one", preparedOwnerText("text", "edited"), part)}
	if err := staged.apply(edited, "response", next); err != nil {
		t.Fatal(err)
	}
	if p.sources["/items/0/parts/0"] != source || staged.sources["/items/0/parts/1"] != source || len(staged.sources) != 1 || len(p.owned) != 0 {
		t.Fatal("reorder lost owner or allocated text owner")
	}
	if string(preparedTestBytes(staged, "/items/0/parts/1")) != "immutable" {
		t.Fatal("edit rewrote bytes")
	}
	if err := staged.apply(edited, "response", []any{}); err != nil {
		t.Fatal(err)
	}
	if len(staged.sources) != 0 || p.sources["/items/0/parts/0"] != source {
		t.Fatal("removal mutated original index")
	}
}
func TestPreparedReferenceOwnersRemainLazy(t *testing.T) {
	var opens atomic.Int32
	part := preparedOwnerAttachment("binary")
	part["selection"] = "body"
	part["body"] = map[string]any{"ref": "urn:original"}
	event := preparedOwnerEvent(preparedOwnerMessage("one", part))
	c := &Client{opts: Options{Content: ContentOptions{Resolver: func(context.Context, string) (io.ReadCloser, error) {
		opens.Add(1)
		return io.NopCloser(strings.NewReader("original")), nil
	}}}}
	p, err := c.prepareBoundary(context.Background(), event, nil, interceptConfig{})
	if err != nil {
		t.Fatal(err)
	}
	owner := p.sources["/items/0/parts/0"]
	if owner == nil || !p.owned[owner] || opens.Load() != 0 {
		t.Fatal("reference not lazy")
	}
	defer owner.Retire()
	for _, source := range []*ContentSource{owner, p.clone().sources["/items/0/parts/0"]} {
		raw, err := ownedcontent.Borrow(source, context.Background(), p.limit)
		if err != nil || string(raw) != "original" {
			t.Fatal(string(raw), err)
		}
	}
	if opens.Load() != 1 {
		t.Fatal("clone reopened reference", opens.Load())
	}
}
func TestPreparedEagerAttachmentsEnforceLimitsWithoutProjection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		payloads []string
		bad      bool
	}{{"within", []string{"1234", "5678"}, false}, {"single", []string{"123456789"}, true}, {"aggregate", []string{"12345", "67890"}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := interceptConfig{}
			items := []any{}
			for i, raw := range tc.payloads {
				source := ownedcontent.NewAttachment([]byte(raw))
				defer source.Retire()
				WithContentSource(fmt.Sprintf("/items/%d/parts/0", i), source)(&cfg)
				items = append(items, preparedOwnerMessage(fmt.Sprint(i), preparedOwnerAttachment(fmt.Sprint(i))))
			}
			event := preparedOwnerEvent(items...)
			p, err := (&Client{opts: Options{MaxContentBytes: 8}}).prepareBoundary(context.Background(), event, preparedOwnerCaps("response"), cfg)
			if (err != nil) != tc.bad {
				t.Fatal("unexpected bounds", err)
			}
			if !tc.bad {
				if _, err := p.values(event); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
func TestPreparedValuesCheckLimitsBeforeDecoding(t *testing.T) {
	for _, payloads := range [][]string{{"123456789"}, {"12345", "67890"}} {
		p := &preparedBoundary{sources: map[string]*ContentSource{}, slots: map[string][]string{"response": {"/items"}}, limit: 8}
		items := []any{}
		for i, raw := range payloads {
			source := ownedcontent.NewAttachment([]byte(raw))
			defer source.Retire()
			p.sources[fmt.Sprintf("/items/%d/parts/0", i)] = source
			items = append(items, preparedOwnerMessage(fmt.Sprint(i), preparedOwnerAttachment(fmt.Sprint(i))))
		}
		values, err := p.values(preparedOwnerEvent(items...))
		if err == nil || values != nil || !strings.Contains(err.Error(), "byte limit") {
			t.Fatal("values bypassed bounds", values, err)
		}
	}
}
