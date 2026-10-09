package ownedcontent

import (
	"bytes"
	"context"
	"io"
)

// Attachment is an owned, single-invocation body. It fits the generated Source
// fields; metadata remains on the associated content item. Successful boundaries
// transfer attachments to their Result, which must be closed by the caller.
// An attachment may occupy several slots in one invocation, but cannot be reused
// in another invocation. Call Close when abandoning an unsubmitted attachment.
type Attachment = Source

// NewAttachment copies data before returning. No store or reference is required.
func NewAttachment(data []byte) *Attachment { return NewOwned(bytes.Clone(data)) }

// NewOwned consumes a newly allocated SDK buffer. The caller must not mutate it.
func NewOwned(data []byte) *Source {
	s := &Source{raw: data}
	s.once.Do(func() {})
	s.ready.Store(true)
	return s
}

// NewLazyAttachment opens only on body demand, at most once. open must honor its
// context; the returned reader's Close must unblock Read. cleanup, if non-nil,
// releases captured resources even when open was never called. Do not capture
// resources owned by Hooks: results can outlive Hooks.Close.
func NewLazyAttachment(open func(context.Context) (io.ReadCloser, error), cleanup func() error) *Attachment {
	return &Source{opener: open, cleanup: cleanup}
}

// Claimed reports whether an adapter has already admitted this source.
func (s *Source) Claimed() bool { return s != nil && s.claimed.Load() }
