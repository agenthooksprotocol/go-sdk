package content

import (
	"context"
	"github.com/agenthooksprotocol/go-sdk/internal/ownedcontent"
	"io"
)

// Source owns a single-invocation body. Binding transfers ownership to the SDK;
// successful results retain the same owner and must be closed. Snapshot and
// Available return defensive copies. A source cannot be reused across invocations.
type Source = ownedcontent.Source

// Attachment is the owned body used with existing generated source fields.
// Content item metadata remains on the item, not on the attachment.
type Attachment = Source

// NewSource takes ownership of reader without reading. Close must unblock Read.
func NewSource(reader io.ReadCloser) *Source { return ownedcontent.NewSource(reader) }

// NewAttachment copies data defensively into its immutable backing buffer.
func NewAttachment(data []byte) *Attachment { return ownedcontent.NewAttachment(data) }

// NewLazyAttachment opens at most once on actual demand. open must honor its
// context and return a reader whose Close unblocks Read. cleanup, when non-nil,
// runs exactly once even if open is never called, and after active opening ends.
// Factories must not capture resources owned by Hooks: results can outlive it.
func NewLazyAttachment(open func(context.Context) (io.ReadCloser, error), cleanup func() error) *Attachment {
	return ownedcontent.NewLazyAttachment(open, cleanup)
}
