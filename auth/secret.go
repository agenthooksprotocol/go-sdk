package auth

import (
	"context"
	"os"
)

// SecretResolver resolves an opaque reference under the caller's existing scope.
// Implementations must honor cancellation and must not log secret values.
type SecretResolver func(context.Context, string) (string, error)

// ResolveSecret shares environment/reference lookup for credentials and headers.
// It resolves exactly one source, rejects empty results, and redacts provider errors.
func ResolveSecret(ctx context.Context, env, ref string, resolver SecretResolver) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", redactError(ErrCredential, err)
	}
	if (env == "") == (ref == "") {
		return "", ErrCredential
	}
	value := ""
	if env != "" {
		value = os.Getenv(env)
	} else {
		if resolver == nil {
			return "", ErrCredential
		}
		var err error
		value, err = resolver(ctx, ref)
		if err != nil {
			return "", redactError(ErrCredential, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return "", redactError(ErrCredential, err)
	}
	if value == "" {
		return "", ErrCredential
	}
	return value, nil
}
