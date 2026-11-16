package auth

import (
	"encoding/json"
	"errors"
)

// Code is a stable, secret-free operational classification, not a wire value.
type Code string

const (
	CodeInvalidConfiguration  Code = "invalid_configuration"
	CodeUnsupportedBinding    Code = "unsupported_binding"
	CodeCredentialUnavailable Code = "credential_unavailable"
	CodeInteractionRequired   Code = "interaction_required"
	CodeAccessDenied          Code = "access_denied"
	CodeRefreshRejected       Code = "refresh_rejected"
	CodeDiscoveryFailed       Code = "discovery_failed"
	CodeUntrustedDestination  Code = "untrusted_destination"
	CodeProviderFailed        Code = "provider_failed"
)

// Recovery describes the host action appropriate for an auth failure.
type Recovery string

const (
	RecoveryConfigure Recovery = "configure"
	RecoveryLogin     Recovery = "login"
	RecoveryRetry     Recovery = "retry"
	RecoveryNone      Recovery = "none"
)

// Recovery returns a secret-free, stable recovery action for the error code.
func (e *Error) Recovery() Recovery {
	switch safeCode(e.Code) {
	case CodeInvalidConfiguration, CodeUnsupportedBinding, CodeCredentialUnavailable, CodeUntrustedDestination:
		return RecoveryConfigure
	case CodeInteractionRequired, CodeRefreshRejected:
		return RecoveryLogin
	case CodeAccessDenied:
		return RecoveryNone
	default:
		return RecoveryRetry
	}
}

// SDK-returned Error carries only an allowlisted code. Formatting, recovery and
// JSON also allowlist Code for directly host-constructed values. It has no raw cause,
// endpoint, response body, callback URL or credential fields. Use errors.As to
// inspect Code and errors.Is for the existing auth sentinels. Cancellation is
// joined separately, without retaining the provider's error chain.
type Error struct{ Code Code }

// MarshalJSON preserves the Code field name while redacting unknown codes.
// A value receiver protects both Error values and pointers supplied by hosts.
func (e Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct{ Code Code }{Code: safeCode(e.Code)})
}

func safeCode(code Code) Code {
	switch code {
	case CodeInvalidConfiguration, CodeUnsupportedBinding, CodeCredentialUnavailable,
		CodeInteractionRequired, CodeAccessDenied, CodeRefreshRejected, CodeDiscoveryFailed,
		CodeUntrustedDestination, CodeProviderFailed:
		return code
	default:
		return CodeProviderFailed
	}
}
func (e *Error) Error() string { return "auth: " + string(safeCode(e.Code)) }
func (e *Error) Is(target error) bool {
	switch safeCode(e.Code) {
	case CodeInvalidConfiguration:
		return target == ErrConfig || target == ErrCredential
	case CodeUntrustedDestination:
		return target == ErrScope || target == ErrCredential
	default:
		return target == ErrCredential
	}
}

// redactProviderError is used only by registration-aware providers; legacy
// low-level token transports retain their sentinel-only error contract.
func redactProviderError(err error) error {
	return redactError(errors.Join(ErrCredential, classifiedError(err)), err)
}

// classifiedError copies only known codes from an untrusted provider error.
func classifiedError(err error) error {
	var classified *Error
	if errors.As(err, &classified) && classified != nil {
		return &Error{Code: safeCode(classified.Code)}
	}
	for _, known := range []struct {
		sentinel error
		code     Code
	}{
		{ErrConfig, CodeInvalidConfiguration},
		{ErrScope, CodeUntrustedDestination},
		{ErrCredential, CodeCredentialUnavailable},
	} {
		if errors.Is(err, known.sentinel) {
			return &Error{Code: known.code}
		}
	}
	return &Error{Code: CodeProviderFailed}
}
