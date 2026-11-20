package auth

import (
	"encoding/json"
	"errors"
	"slices"

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

// SDK-returned Error carries only an allowlisted code and, on
// interaction_required and access_denied from the SDK's own scope decision,
// the operation's required scopes: deduplicated, sorted in ascending byte
// order. A host passes the scopes of interaction_required back to an explicit
// prepare; access_denied names the required scopes that were refused.
// LoginEnded is set only on errors from a login completion
// (oauth.Provider.Complete): true when the pending login named by the
// callback's state no longer exists after the call (consumed, expired or
// unknown), false when it is still pending, for example after a stray or
// invalid callback rejected before the login was claimed. It is nil on every
// other error. Formatting, recovery and JSON also allowlist host-constructed
// values. It has no raw cause, endpoint, response body, callback URL or
// credential fields. Use errors.As to inspect it and errors.Is for the
// existing auth sentinels. Cancellation is joined separately, without
// retaining the provider's error chain.
type Error struct {
	Code       Code
	Scopes     []string
	LoginEnded *bool
}

// MarshalJSON redacts unknown codes and scopes. LoginEnded is emitted, true
// or false, only when set (a Complete error). A value receiver protects both
// Error values and pointers supplied by hosts.
func (e Error) MarshalJSON() ([]byte, error) {
	safe := Classify(&e)
	return json.Marshal(struct {
		Code       Code
		Scopes     []string `json:",omitempty"`
		LoginEnded *bool    `json:",omitempty"`
	}{safe.Code, safe.Scopes, e.LoginEnded})
}

// Classify copies the first *Error in err's chain without the chain itself,
// keeping only an allowlisted code and, where that code permits, its scopes
// deduplicated and byte-sorted; a set with any invalid scope token is dropped
// whole. It never copies LoginEnded. It returns nil when err contains no
// *Error.
func Classify(err error) *Error {
	var classified *Error
	if !errors.As(err, &classified) || classified == nil {
		return nil
	}
	result := &Error{Code: safeCode(classified.Code)}
	if result.Code == CodeInteractionRequired || result.Code == CodeAccessDenied {
		for _, scope := range classified.Scopes {
			if !authutil.ValidScope(scope) {
				return result
			}
		}
		if len(classified.Scopes) > 0 {
			result.Scopes = append([]string(nil), classified.Scopes...)
			slices.Sort(result.Scopes)
			result.Scopes = slices.Compact(result.Scopes)
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
