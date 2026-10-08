package client

import (
	"bytes"
	"context"
	"errors"
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
				original := bytes.Clone(prepared.bodies["urn:test:one"])
				bodies["urn:test:one"][0] = 'x'
				if !bytes.Equal(prepared.bodies["urn:test:one"], original) {
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
	if item["id"] != "host-owned-instructions" || item["selection"] != "body" {
		t.Fatal(item)
	}
	raw := accepted.prepared.bodies[compositionString(sdkObj(item["body"])["ref"])]
	if string(raw) != "new instructions" {
		t.Fatal(string(raw))
	}
	if len(prepared.bodies) != 0 {
		t.Fatal("staging mutated original bodyless template")
	}
}
