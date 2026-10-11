package client

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/agenthooksprotocol/go-sdk/diagnostic"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

// AdmissionError describes a failure before a boundary was admitted. No backend
// call was made for a rejected boundary. Configuration failures use Kind config.
// Protocol delivery failures after admission live in Result.Diagnostics instead.
type AdmissionError struct {
	Kind string
	Err  error
}

func (e *AdmissionError) Error() string { return "client " + e.Kind + ": " + e.Err.Error() }
func (e *AdmissionError) Unwrap() error { return e.Err }

var errRemoteRPC = errors.New("backend JSON-RPC error")

// Never retain the untrusted RPC message, data, or numeric application code.
// Only a canonical, correlated error envelope is a remote RPC failure.
func interceptResponseFailure(raw []byte, requestID any) error {
	if canonical.Validate("errorResponse", raw) == nil {
		var envelope map[string]any
		if json.Unmarshal(raw, &envelope) == nil && compositionEqual(envelope["id"], requestID) {
			return errRemoteRPC
		}
	}
	return errors.New("invalid intercept response")
}

func deliveryCode(stage string, err error) diagnostic.Code {
	switch {
	case errors.Is(err, context.Canceled):
		return diagnostic.Cancelled
	case errors.Is(err, context.DeadlineExceeded):
		return diagnostic.DeadlineExceeded
	case errors.Is(err, errRemoteRPC):
		return diagnostic.RemoteRpc
	case stage == "acceptance" || stage == "request":
		return diagnostic.ProtocolRejection
	case stage == "prepare":
		return diagnostic.Preparation
	case stage == "admission":
		return diagnostic.Capacity
	default:
		return diagnostic.Transport
	}
}
