package auth

import (
	"encoding/json"
	"errors"

	"github.com/agenthooksprotocol/go-sdk/internal/authutil"
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

// SDK-returned Error carries only an allowlisted code and validated required
// scopes: on interaction_required for a host to pass back to an explicit
// prepare, on access_denied for diagnostics only. Scopes are deduplicated and
// sorted in ascending byte order. LoginEnded is set only on errors from a
// login completion (oauth.Provider.Complete): true when the pending login
// named by the callback's state no longer exists after the call (consumed,
// expired or unknown), false when it is still pending, for example after a
// stray or invalid callback rejected before the login was claimed.
// Formatting, recovery and JSON also allowlist host-constructed values. It has no raw cause, endpoint, response
// body, callback URL or credential fields. Use errors.As to inspect it and
// errors.Is for the existing auth sentinels. Cancellation is joined separately,
// without retaining the provider's error chain.
type Error struct {
	Code       Code
	Scopes     []string
	LoginEnded bool
}

// MarshalJSON redacts unknown codes and scopes. A value receiver protects both
// Error values and pointers supplied by hosts.
func (e Error) MarshalJSON() ([]byte, error) {
	safe := Classify(&e)
	return json.Marshal(struct {
		Code       Code
		Scopes     []string `json:",omitempty"`
		LoginEnded bool     `json:",omitempty"`
	}{safe.Code, safe.Scopes, safe.LoginEnded})
}

// Classify copies the first *Error in err's chain without the chain itself,
// keeping only an allowlisted code and, where that code permits, grammatically
// valid scopes, and the LoginEnded flag. It returns nil when err contains no
// *Error.
func Classify(err error) *Error {
	var classified *Error
	if !errors.As(err, &classified) || classified == nil {
		return nil
	}
	result := &Error{Code: safeCode(classified.Code), LoginEnded: classified.LoginEnded}
	if result.Code == CodeInteractionRequired || result.Code == CodeAccessDenied {
		for _, scope := range classified.Scopes {
			if authutil.ValidScope(scope) {
				result.Scopes = append(result.Scopes, scope)
			}
		}
	}
	return result
}

func safeCode(code Code) Code {
	if authutil.KnownCode(string(code)) {
		return code
	}
	return CodeProviderFailed
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

// classifiedError copies only an allowlisted SDK error from an untrusted
// provider error. Any other provider error is an operational failure.
func classifiedError(err error) error {
	if classified := Classify(err); classified != nil {
		return classified
	}
	return &Error{Code: CodeProviderFailed}
}
