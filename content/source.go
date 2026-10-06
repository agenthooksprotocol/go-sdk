package content

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
	reader    io.ReadCloser
	once      sync.Once
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

// Close releases the owned reader exactly once, including unused sources.
func (s *Source) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		if s.reader != nil {
			s.closeErr = s.reader.Close()
		}
	})
	return s.closeErr
}

type contentSourceReader struct{ *Source }

func (s contentSourceReader) Read(p []byte) (int, error) { return s.reader.Read(p) }

// Snapshot reads a bounded immutable snapshot once. SDK adapters call it only after
// receiver selection and authorization. The returned bytes are detached from the cached snapshot.
func (s *Source) Snapshot(ctx context.Context, limit int64) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil content source")
	}
	if limit < 0 || limit == math.MaxInt64 {
		_ = s.Close()
		return nil, errors.New("invalid content byte limit")
	}
	s.once.Do(func() {
		defer s.ready.Store(true)
		if s.reader == nil || s.closed.Load() {
			s.err = errors.New("content source is closed or has no reader")
			return
		}
		if err := ctx.Err(); err != nil {
			s.err = err
			_ = s.Close()
			return
		}
		s.raw, s.err = readOwnedContent(ctx, contentSourceReader{s}, limit)
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
	return bytes.Clone(s.raw), nil
}

// Available observes an immutable completed snapshot without starting a read.
func (s *Source) Available() ([]byte, bool) {
	if s == nil || !s.ready.Load() || s.err != nil {
		return nil, false
	}
	return bytes.Clone(s.raw), true
}

// Claim transfers this source to one SDK occurrence. Adapters must reject reuse.
func (s *Source) Claim() bool {
	return s != nil && s.reader != nil && s.claimed.CompareAndSwap(false, true)
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
