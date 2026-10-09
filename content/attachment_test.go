package content

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLazyAttachmentFanout(t *testing.T) {
	var opens, closes atomic.Int32
	a := NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
		opens.Add(1)
		return io.NopCloser(strings.NewReader("original")), nil
	}, func() error { closes.Add(1); return nil })
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := a.Snapshot(context.Background(), 32)
			if err != nil || string(b) != "original" {
				t.Errorf("%q %v", b, err)
			}
			if len(b) > 0 {
				b[0] = 'X'
			}
		}()
	}
	wg.Wait()
	_ = a.Retire()
	if opens.Load() != 1 || closes.Load() != 1 {
		t.Fatal(opens.Load(), closes.Load())
	}
}

func TestLazyAttachmentOpenCancellation(t *testing.T) {
	for _, closeSource := range []bool{false, true} {
		started := make(chan struct{})
		var cleanup atomic.Int32
		a := NewLazyAttachment(func(ctx context.Context) (io.ReadCloser, error) { close(started); <-ctx.Done(); return nil, ctx.Err() }, func() error { cleanup.Add(1); return nil })
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		done := make(chan error, 1)
		go func() { _, err := a.Snapshot(ctx, 64); done <- err }()
		<-started
		if closeSource {
			_ = a.Retire()
		} else {
			cancel()
		}
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("cancellation succeeded")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("open was not interrupted")
		}
		cancel()
		_ = a.Retire()
		if cleanup.Load() != 1 {
			t.Fatal("cleanup", cleanup.Load())
		}
	}
}

func TestLazyAttachmentOpenError(t *testing.T) {
	calls, cleanup := 0, 0
	want := errors.New("open failed")
	a := NewLazyAttachment(func(context.Context) (io.ReadCloser, error) { calls++; return nil, want }, func() error { cleanup++; return nil })
	for i := 0; i < 2; i++ {
		if _, err := a.Snapshot(context.Background(), 2); !errors.Is(err, want) {
			t.Fatal(err)
		}
	}
	_ = a.Retire()
	if calls != 1 || cleanup != 1 {
		t.Fatal(calls, cleanup)
	}
}

func TestLazyAttachmentReadTimeout(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	var cleanup atomic.Int32
	a := NewLazyAttachment(func(context.Context) (io.ReadCloser, error) { return r, nil }, func() error { cleanup.Add(1); return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := a.Snapshot(ctx, 64); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	_ = a.Retire()
	if cleanup.Load() != 1 {
		t.Fatal("timeout did not clean up")
	}
}

func TestLazyAttachmentCleanupJoinsOpener(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var opening atomic.Bool
	a := NewLazyAttachment(func(ctx context.Context) (io.ReadCloser, error) {
		opening.Store(true)
		close(started)
		<-ctx.Done()
		<-release
		opening.Store(false)
		return nil, ctx.Err()
	}, func() error {
		if opening.Load() {
			t.Error("cleanup ran before opener returned")
		}
		return nil
	})
	read := make(chan error, 1)
	go func() { _, err := a.Snapshot(context.Background(), 64); read <- err }()
	<-started
	closed := make(chan error, 1)
	go func() { closed <- a.Retire() }()
	select {
	case <-closed:
		t.Fatal("retirement did not join opener")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := <-read; err == nil {
		t.Fatal("closed read succeeded")
	}
}

func TestLazyAttachmentConcurrentClaim(t *testing.T) {
	for i := 0; i < 100; i++ {
		a := NewLazyAttachment(func(context.Context) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("x")), nil }, nil)
		if !a.Claim() {
			t.Fatal("initial claim failed")
		}
		done := make(chan struct{})
		go func() { defer close(done); _, _ = a.Snapshot(context.Background(), 2) }()
		if a.Claim() {
			t.Fatal("reuse accepted")
		}
		<-done
		_ = a.Retire()
	}
}
