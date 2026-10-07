package client

import (
	"context"
	"io"
)

// ContentResolver opens host-owned content. A ref is an opaque handle, not a URL
// that the SDK fetches. Each call must return a fresh reader for the same bytes.
// The SDK owns and closes the returned reader. Opening must honor ctx; Close
// must unblock a pending Read, because cancellation can close it concurrently.
type ContentResolver func(context.Context, string) (io.ReadCloser, error)

// ContentAuthorization identifies the local receiving backend and subscription.
// Item is a copy of the descriptor, not an authorization claim from the payload.
type ContentAuthorization struct {
	BackendID      string
	SubscriptionID string
	Subscription   map[string]any
	Item           map[string]any
}

// ContentOptions controls content disclosure independently from selection and
// event authentication. The zero value permits no body or opaque disclosure.
type ContentOptions struct {
	Resolver         ContentResolver
	AuthorizeContent func(context.Context, ContentAuthorization) (bool, error)
	// ProjectOpaque explicitly projects duplicate bytes in native/input/output and
	// other host-defined opaque fields. Native is considered only when includeNative
	// is true. A nil callback withholds opaque fields. It must return a safe view;
	// the SDK cannot discover embedded secrets in arbitrary application JSON.
	ProjectOpaque func(ctx context.Context, scope ContentAuthorization, path string, value any) (any, error)
	// AllowLoopbackHTTP permits HTTP only to literal loopback IPs or localhost.
	// Production upload endpoints require HTTPS and normal certificate validation.
	AllowLoopbackHTTP bool
}
