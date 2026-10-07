package client

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type cancellationPipeReader struct {
	*io.PipeReader
	started chan struct{}
	once    sync.Once
	closes  atomic.Int32
}

func (r *cancellationPipeReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.PipeReader.Read(p)
}
func (r *cancellationPipeReader) Close() error { r.closes.Add(1); return r.PipeReader.Close() }
func cancellationPipe(t *testing.T) (*cancellationPipeReader, *io.PipeWriter) {
	t.Helper()
	r, w := io.Pipe()
	t.Cleanup(func() { _ = w.Close() })
	return &cancellationPipeReader{PipeReader: r, started: make(chan struct{})}, w
}
func cancellationContent(c *Client, reader *cancellationPipeReader) {
	c.opts.Content.AuthorizeContent = contentTestAllow
	c.opts.Content.Resolver = func(context.Context, string) (io.ReadCloser, error) { return reader, nil }
	for i := range c.backends {
		for _, sub := range c.backends[i].subscriptions {
			sub["content"] = map[string]any{"default": "body"}
			sub["upload"] = map[string]any{"endpoint": "https://unused.invalid/upload", "timeoutMs": 1000, "maxBytes": 4096}
		}
	}
}
func cancellationInput() map[string]any {
	item, _ := targetTestItem("nonmodifiable", "text/plain", "waiting")
	input := testInput()
	input["items"] = []any{item}
	return input
}

func TestContentProjectionDeadlineClosesOwnedReader(t *testing.T) {
	reader, writer := cancellationPipe(t)
	c := &Client{}
	cancellationContent(c, reader)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := c.projectContent(ctx, cancellationInput(), contentTestSubscription("https://unused.invalid/upload"), "receiver")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		_ = writer.Close()
		t.Fatal("projection retained a blocked reader after deadline")
	}
	if reader.closes.Load() != 1 {
		t.Fatalf("reader closed %d times", reader.closes.Load())
	}
}

func TestContentInterceptDeadlineClosesNonmodifiableReader(t *testing.T) {
	// Advance the deadline only once admission has reached blocking I/O. With
	// wall-clock time, race instrumentation can exhaust the deadline before
	// projection begins and legitimately route the interceptor to observation.
	synctest.Test(t, func(t *testing.T) {
		c, transports := testClient(t, "fail-open")
		reader, writer := cancellationPipe(t)
		cancellationContent(c, reader)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		type completion struct {
			result *Result
			err    error
		}
		done := make(chan completion, 1)
		go func() { r, err := c.intercept(ctx, "tool.before", cancellationInput()); done <- completion{r, err} }()
		select {
		case out := <-done:
			if !errors.Is(out.err, context.DeadlineExceeded) || out.result == nil || !out.result.Interrupted {
				t.Fatalf("lost interruption result: %+v %v", out.result, out.err)
			}
			waitObservations(t, out.result)
		case <-time.After(time.Second):
			_ = writer.Close()
			t.Fatal("intercept preparation ignored deadline")
		}
		select {
		case <-reader.started:
		default:
			t.Fatal("deadline expired before the content read began")
		}
		if reader.closes.Load() != 1 {
			t.Fatalf("reader closed %d times", reader.closes.Load())
		}
		transports[0].mu.Lock()
		calls := len(transports[0].calls)
		transports[0].mu.Unlock()
		if calls != 0 {
			t.Fatal("incomplete content reached interceptor")
		}

	})
}

func TestContentObservationDeadlineReleasesReaderAndCapacity(t *testing.T) {
	c, transports := testClient(t, "fail-open")
	reader, writer := cancellationPipe(t)
	cancellationContent(c, reader)
	c.backends[0].subscriptions[0]["mode"] = "observe"
	c.opts.ObservationTimeout = 50 * time.Millisecond
	result, err := c.intercept(context.Background(), "tool.before", cancellationInput())
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	failures, err := result.Observations.Wait(wait)
	if err != nil {
		_ = writer.Close()
		t.Fatal("observation deadline did not release work", err)
	}
	if len(failures) != 1 || !errors.Is(failures[0].Err, context.DeadlineExceeded) {
		t.Fatal(failures)
	}
	if reader.closes.Load() != 1 {
		t.Fatalf("reader closed %d times", reader.closes.Load())
	}
	if len(c.observations) != 0 {
		t.Fatal("observation capacity leaked")
	}
	transports[0].mu.Lock()
	calls := len(transports[0].calls)
	transports[0].mu.Unlock()
	if calls != 0 {
		t.Fatal("incomplete content reached observer")
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		_ = writer.Close()
		t.Fatal("client close retained canceled observation")
	}
}
