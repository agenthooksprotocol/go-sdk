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
// Protocol delivery failures after admission live in Result.Errors instead.
type AdmissionError struct {
	Kind string
	Err  error
}

func (e *AdmissionError) Error() string { return "client " + e.Kind + ": " + e.Err.Error() }
func (e *AdmissionError) Unwrap() error { return e.Err }

// DeliveryCode is a stable, payload-free classification of a delivery failure.
// Stage identifies where it happened; Code identifies the failure category.
type DeliveryCode = diagnostic.Code

const (
	DeliveryProtocolRejection DeliveryCode = diagnostic.ProtocolRejection
	DeliveryRemoteRPC         DeliveryCode = diagnostic.RemoteRpc
	DeliveryTransport         DeliveryCode = diagnostic.Transport
	DeliveryCancelled         DeliveryCode = diagnostic.Cancelled
	DeliveryDeadlineExceeded  DeliveryCode = diagnostic.DeadlineExceeded
	DeliveryPreparation       DeliveryCode = diagnostic.Preparation
	DeliveryCapacity          DeliveryCode = diagnostic.Capacity
)

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

func deliveryCode(stage string, err error) DeliveryCode {
	switch {
	case errors.Is(err, context.Canceled):
		return DeliveryCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return DeliveryDeadlineExceeded
	case errors.Is(err, errRemoteRPC):
		return DeliveryRemoteRPC
	case stage == "acceptance" || stage == "request":
		return DeliveryProtocolRejection
	case stage == "prepare":
		return DeliveryPreparation
	case stage == "admission":
		return DeliveryCapacity
	default:
		return DeliveryTransport
	}
}
