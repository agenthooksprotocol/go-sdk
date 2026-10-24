package ahp

import "context"

// ConfigurationSource supplies backend subscription defaults for a discovery
// request. Implementations may run concurrently and must honor cancellation.
// Authentication belongs to the application's HTTP middleware; its context is
// passed unchanged to ResolveConfiguration. Sources must not mutate a returned
// configuration while the server validates and snapshots it.
type ConfigurationSource interface {
	ResolveConfiguration(context.Context) (*Configuration, error)
}

// ResolveConfiguration makes a static configuration a ConfigurationSource.
// Servers snapshot static configurations at setup rather than on each request.
func (c *Configuration) ResolveConfiguration(context.Context) (*Configuration, error) {
	return c, nil
}

// ConfigurationFunc adapts a request-scoped function to ConfigurationSource.
type ConfigurationFunc func(context.Context) (*Configuration, error)

// ResolveConfiguration invokes f with the current request context.
func (f ConfigurationFunc) ResolveConfiguration(ctx context.Context) (*Configuration, error) {
	return f(ctx)
}
