package ownedcontent

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

func awaitWaiters(t *testing.T, s *Source, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.lifetime.RLock()
		n := s.waiters
		s.lifetime.RUnlock()
		if n == count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("did not observe %d materialization waiters", count)
}

type overlapReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	closes  atomic.Int32
	err     error
}

func (r *overlapReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	if r.err != nil {
		return 0, r.err
	}
	return strings.NewReader("shared").Read(p)
}
func (r *overlapReader) Close() error { r.closes.Add(1); return nil }

func TestOverlappingBorrowSharesError(t *testing.T) {
	want := errors.New("read failed")
	r := &overlapReader{started: make(chan struct{}), release: make(chan struct{}), err: want}
	s := NewSource(r)
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, err := Borrow(s, context.Background(), 64); results <- err }()
	}
	<-r.started
	awaitWaiters(t, s, 2)
	close(r.release)
	for i := 0; i < 2; i++ {
		if err := <-results; err != want {
			t.Fatalf("shared error = %v", err)
		}
	}
	if _, err := Borrow(s, context.Background(), 64); err != want {
		t.Fatalf("cached error = %v", err)
	}
	if _, ok := Available(s); ok {
		t.Fatal("failed owner available")
	}
	if err := s.Retire(); err != nil {
		t.Fatal(err)
	}
	if r.closes.Load() != 1 {
		t.Fatal("reader close count", r.closes.Load())
	}
}

func TestOverlappingBorrowCancellationPreservesOtherWaiters(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	var cleanup atomic.Int32
	s := NewLazyAttachment(func(context.Context) (io.ReadCloser, error) { return r, nil }, func() error { cleanup.Add(1); return nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancelled := make(chan error, 1)
	go func() { _, err := Borrow(s, ctx, 64); cancelled <- err }()
	values := make(chan []byte, 2)
	for i := 0; i < 2; i++ {
		go func() {
			raw, err := Borrow(s, context.Background(), 64)
			if err != nil {
				t.Error(err)
			}
			values <- raw
		}()
	}
	awaitWaiters(t, s, 3)
	cancel()
	select {
	case err := <-cancelled:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("individual cancellation blocked")
	}
	if cleanup.Load() != 0 {
		t.Fatal("individual cancellation cleaned up shared owner")
	}
	if _, err := w.Write([]byte("shared")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	a, b := <-values, <-values
	if string(a) != "shared" || string(b) != "shared" || &a[0] != &b[0] {
		t.Fatal("borrowers did not share backing storage")
	}
	cached, ok := Available(s)
	if !ok || &cached[0] != &a[0] {
		t.Fatal("owner is not sole cached backing")
	}
	detached, err := s.Snapshot(context.Background(), 64)
	if err != nil {
		t.Fatal(err)
	}
	detached[0] = 'X'
	if string(cached) != "shared" {
		t.Fatal("snapshot mutated owner")
	}
	_ = s.Retire()
	if cleanup.Load() != 1 {
		t.Fatal("cleanup count", cleanup.Load())
	}
}

func TestLastWaiterCancellationJoinsAndIsTerminal(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var opens, cleanup atomic.Int32
	s := NewLazyAttachment(func(ctx context.Context) (io.ReadCloser, error) {
		opens.Add(1)
		close(started)
		<-ctx.Done()
		<-release
		return nil, ctx.Err()
	}, func() error { cleanup.Add(1); return nil })
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := Borrow(s, ctx, 64); result <- err }()
	<-started
	cancel()
	select {
	case <-result:
		t.Fatal("last cancellation did not join opener")
	case <-time.After(20 * time.Millisecond):
	}
	retired := make(chan error, 1)
	go func() { retired <- s.Retire() }()
	close(release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := <-retired; err != nil {
		t.Fatal(err)
	}
	if cleanup.Load() != 1 || opens.Load() != 1 {
		t.Fatal("cleanup/open counts", cleanup.Load(), opens.Load())
	}
	s.lifetime.RLock()
	cancelled, pending := s.cancelled, !s.ready.Load()
	s.lifetime.RUnlock()
	if !cancelled || pending {
		t.Fatal("cancelled owner remains pending")
	}
}

func TestCancelledOwnerDoesNotReopen(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	s := NewSource(r)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := Borrow(s, ctx, 64); result <- err }()
	awaitWaiters(t, s, 1)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := Borrow(s, context.Background(), 64); !errors.Is(err, context.Canceled) {
		t.Fatal("terminal cancellation", err)
	}
	if _, ok := Available(s); ok {
		t.Fatal("cancelled owner available")
	}
	_ = s.Retire()
}
