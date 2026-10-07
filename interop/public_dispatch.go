package interop

import (
	"context"
	hooks "github.com/agenthooksprotocol/go-sdk/client"
)

// Canonical fixtures use the SDK's explicit dynamic dispatch surface. Named
// generated host inputs are deliberately not wire parsers; do not duplicate the
// generator's flattened-field mapping here. Consumer tests cover those inputs.
func dispatchPublicBoundary(ctx context.Context, c *hooks.Client, name string, ev Object, opts []hooks.InterceptOption) (*hooks.Result, error) {
	input := make(Object, len(ev))
	for key, value := range ev {
		switch key {
		case "source", "type", "manifest":
			continue
		}
		input[key] = value
	}
	return c.Dispatch(ctx, name, input, opts...)
}
