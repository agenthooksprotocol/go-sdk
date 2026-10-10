package ownedcontent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"sync/atomic"
)

// Source is an owned, single-occurrence readable body, not a wire reference.
// Construction does not read it. Passing it to a boundary transfers ownership to
// the SDK, including when the boundary fails or no receiver selects its body.
// Close must unblock Read: cancellation may close the reader concurrently.
// A source must not be reused across occurrences or read by its caller after transfer.
type Source struct {
	lifetime  sync.RWMutex
	retired   bool
	cancelled bool
	done      chan struct{}
	cancel    context.CancelFunc
	waiters   int
	reader    io.ReadCloser
	opener    func(context.Context) (io.ReadCloser, error)
	cleanup   func() error
	once      sync.Once // retained for eager construction
	closeOnce sync.Once
	claimed   atomic.Bool
	closed    atomic.Bool
	ready     atomic.Bool
	raw       []byte
	err       error
	closeErr  error
}

// NewSource wraps a reader without consuming bytes or uploading anything.
// Call Close if the source is never passed to a boundary.
func NewSource(reader io.ReadCloser) *Source { return &Source{reader: reader} }

// closeReader is called by the materializer, or retirement of an idle owner.
func (s *Source) closeReader() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		if s.reader != nil {
			s.closeErr = s.reader.Close()
		}
		if s.cleanup != nil {
			s.closeErr = errors.Join(s.closeErr, s.cleanup())
		}
	})
	return s.closeErr
}

// Close disposes this owner, including cached bytes and unopened factories.
// Do not call it after transferring ownership to a boundary; close its result.
func (s *Source) Close() error { return s.Retire() }

// Retire interrupts and joins active materialization before releasing storage.
func (s *Source) Retire() error {
	if s == nil {
		return nil
	}
	s.lifetime.Lock()
	s.retired = true
	done := s.done
	if s.cancel != nil {
		s.cancel()
	}
	if done == nil {
		_ = s.closeReader()
	}
	s.lifetime.Unlock()
	if done != nil {
		<-done
	}
	s.lifetime.Lock()
	defer s.lifetime.Unlock()
	s.raw, s.reader, s.opener, s.cleanup = nil, nil, nil, nil
	s.cancel = nil
	return s.closeErr
}

type contentSourceReader struct{ *Source }

func (s contentSourceReader) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s contentSourceReader) Close() error               { return s.closeReader() }

// materialize is the single bounded worker owned and joined by its consumers.
func (s *Source) materialize(ctx context.Context, limit int64) {
	var raw []byte
	var err error
	if err = ctx.Err(); err == nil && s.opener != nil {
		s.reader, err = s.opener(ctx)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && s.reader == nil {
		err = errors.New("content source is closed or has no reader")
	}
	if err == nil {
		raw, err = readOwnedContent(ctx, contentSourceReader{s}, limit)
	}
	_ = s.closeReader()
	if err == nil && int64(len(raw)) > limit {
		raw = nil
		err = errors.New("content exceeds byte limit")
	}
	s.lifetime.Lock()
	defer s.lifetime.Unlock()
	if ctx.Err() != nil {
		s.cancelled = true
		raw = nil
		err = ctx.Err()
	}
	s.raw, s.err = raw, err
	s.reader, s.opener, s.cleanup = nil, nil, nil
	s.ready.Store(true)
	s.cancel() // release the bounded worker context after publishing its state
	s.cancel = nil
	close(s.done)
}

// Snapshot reads a bounded immutable snapshot once. SDK adapters call it only after
// receiver selection and authorization. The returned bytes are detached from the cached snapshot.
func (s *Source) Snapshot(ctx context.Context, limit int64) ([]byte, error) {
	raw, err := Borrow(s, ctx, limit)
	return bytes.Clone(raw), err
}

// Borrow lends immutable bytes to SDK internals without another backing owner.
// Overlapping callers join one bounded materialization. Cancelling one waiter
// interrupts only that waiter; the last cancelling waiter cancels and joins the
// worker. Cancellation is terminal, like a completed read failure.
func Borrow(s *Source, ctx context.Context, limit int64) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil content source")
	}
	s.lifetime.Lock()
	if s.retired {
		s.lifetime.Unlock()
		return nil, errors.New("content source is retired")
	}
	if limit < 0 || limit == math.MaxInt64 {
		s.lifetime.Unlock()
		_ = s.Retire()
		return nil, errors.New("invalid content byte limit")
	}
	if s.cancelled {
		s.lifetime.Unlock()
		return nil, context.Canceled
	}
	if !s.ready.Load() && s.done == nil {
		// A waiter's context must not govern other consumers or a retained result.
		workCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		s.cancel = cancel
		if ctx.Err() != nil {
			cancel()
		}
		s.done = make(chan struct{})
		go s.materialize(workCtx, limit)
	}
	if !s.ready.Load() {
		s.waiters++
		done := s.done
		s.lifetime.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
		}
		s.lifetime.Lock()
		s.waiters--
		lastCancelled := ctx.Err() != nil && s.waiters == 0 && !s.ready.Load()
		if lastCancelled {
			s.cancelled = true
			s.cancel()
		}
		if ctx.Err() != nil {
			s.lifetime.Unlock()
			if lastCancelled {
				<-done
			}
			return nil, ctx.Err()
		}
	}
	defer s.lifetime.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.retired {
		return nil, errors.New("content source is retired")
	}
	if s.cancelled {
		return nil, context.Canceled
	}
	if s.err != nil {
		return nil, s.err
	}
	if int64(len(s.raw)) > limit {
		return nil, errors.New("content exceeds byte limit")
	}
	return s.raw, nil
}

// Available observes an immutable completed snapshot without starting a read.
func (s *Source) Available() ([]byte, bool) {
	raw, ok := Available(s)
	return bytes.Clone(raw), ok
}

// Available lends an already materialized immutable snapshot to SDK internals.
func Available(s *Source) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	s.lifetime.RLock()
	defer s.lifetime.RUnlock()
	if s.retired || !s.ready.Load() || s.err != nil {
		return nil, false
	}
	return s.raw, true
}

// Claim transfers this source to one SDK occurrence. Adapters must reject reuse.
func (s *Source) Claim() bool {
	if s == nil {
		return false
	}
	s.lifetime.RLock()
	defer s.lifetime.RUnlock()
	return !s.retired && !s.closed.Load() && (s.done != nil || s.reader != nil || s.opener != nil || s.ready.Load()) && s.claimed.CompareAndSwap(false, true)
}

// readOwnedContent closes the SDK-owned reader exactly once on every exit.
// Cancellation closes it concurrently with Read, so resolvers must return readers
// whose Close unblocks Read. sync.Once also joins a cancellation-triggered Close
// before its error is inspected; Close completes before this function returns.
// Callers validate limit and reserve room for the one-byte overflow probe.
func readOwnedContent(ctx context.Context, reader io.ReadCloser, limit int64) ([]byte, error) {
	var once sync.Once
	var closeErr error
	closeReader := func() { once.Do(func() { closeErr = reader.Close() }) }
	stop := context.AfterFunc(ctx, closeReader)
	raw, err := io.ReadAll(io.LimitReader(reader, limit+1))
	stop()
	closeReader()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return raw, nil
}
