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
	openCancel context.CancelFunc
	openDone   chan struct{}
	readerMu   sync.Mutex
	opener     func(context.Context) (io.ReadCloser, error)
	cleanup    func() error
	lifetime   sync.RWMutex
	retired    bool
	reader     io.ReadCloser
	once       sync.Once
	closeOnce  sync.Once
	claimed    atomic.Bool
	closed     atomic.Bool
	ready      atomic.Bool
	raw        []byte
	err        error
	closeErr   error
}

// NewSource wraps a reader without consuming bytes or uploading anything.
// Call Close if the source is never passed to a boundary.
func NewSource(reader io.ReadCloser) *Source { return &Source{reader: reader} }

// closeReader releases I/O but leaves the immutable snapshot available to fan-out.
func (s *Source) closeReader() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.readerMu.Lock()
		reader := s.reader
		cancel := s.openCancel
		openDone := s.openDone
		s.readerMu.Unlock()
		if cancel != nil {
			cancel()
		}
		if openDone != nil {
			<-openDone
		}
		if reader != nil {
			s.closeErr = reader.Close()
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

// Retire is the adapter-compatible spelling of Close. It interrupts and joins
// active materialization before releasing backing storage.
func (s *Source) Retire() error {
	if s == nil {
		return nil
	}
	err := s.closeReader()
	s.lifetime.Lock()
	defer s.lifetime.Unlock()
	s.retired = true
	s.raw = nil
	s.reader = nil
	s.openCancel = nil
	s.openDone = nil
	s.opener = nil
	s.cleanup = nil
	s.err = nil
	return err
}

type contentSourceReader struct{ *Source }

func (s contentSourceReader) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s contentSourceReader) Close() error               { return s.closeReader() }

// Snapshot reads a bounded immutable snapshot once. SDK adapters call it only after
// receiver selection and authorization. The returned bytes are detached from the cached snapshot.
func (s *Source) Snapshot(ctx context.Context, limit int64) ([]byte, error) {
	raw, err := Borrow(s, ctx, limit)
	return bytes.Clone(raw), err
}

// Borrow lends immutable bytes to SDK internals without another backing owner.
func Borrow(s *Source, ctx context.Context, limit int64) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil content source")
	}
	s.lifetime.RLock()
	defer s.lifetime.RUnlock()
	if s.retired {
		return nil, errors.New("content source is retired")
	}
	if limit < 0 || limit == math.MaxInt64 {
		_ = s.closeReader()
		return nil, errors.New("invalid content byte limit")
	}
	s.once.Do(func() {
		defer s.ready.Store(true)
		if err := ctx.Err(); err != nil {
			s.err = err
			_ = s.closeReader()
			return
		}
		if s.opener != nil && !s.closed.Load() {
			openCtx, cancel := context.WithCancel(ctx)
			s.readerMu.Lock()
			if s.closed.Load() {
				s.readerMu.Unlock()
				cancel()
				s.err = errors.New("content source is closed")
				return
			}
			s.openCancel = cancel
			s.openDone = make(chan struct{})
			s.readerMu.Unlock()
			reader, err := s.opener(openCtx)
			s.readerMu.Lock()
			closed := s.closed.Load()
			if !closed {
				s.reader = reader
			}
			s.readerMu.Unlock()
			if closed && reader != nil {
				_ = reader.Close()
			}
			close(s.openDone)
			if err != nil {
				s.err = err
				_ = s.closeReader()
				return
			}
		}
		if s.reader == nil || s.closed.Load() {
			s.err = errors.New("content source is closed or has no reader")
			_ = s.closeReader()
			return
		}
		if err := ctx.Err(); err != nil {
			s.err = err
			_ = s.closeReader()
			return
		}
		s.raw, s.err = readOwnedContent(ctx, contentSourceReader{s}, limit)
		s.readerMu.Lock()
		s.reader = nil
		s.opener = nil
		s.cleanup = nil
		s.openCancel = nil
		s.openDone = nil
		s.readerMu.Unlock()
		if s.err == nil && int64(len(s.raw)) > limit {
			s.raw = nil
			s.err = errors.New("content exceeds byte limit")
		}
	})
	if err := ctx.Err(); err != nil {
		return nil, err
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
	s.readerMu.Lock()
	defer s.readerMu.Unlock()
	return !s.retired && !s.closed.Load() && (s.reader != nil || s.opener != nil || s.ready.Load()) && s.claimed.CompareAndSwap(false, true)
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
