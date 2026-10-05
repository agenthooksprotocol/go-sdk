package client

import (
	"context"
	"io"
	"sync"
)

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
