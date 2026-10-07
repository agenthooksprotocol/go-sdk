package client

import (
	"context"
	"encoding/json"
	"errors"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"strings"
	"testing"
)

type diagnosticTransport struct {
	response func(map[string]any) []byte
	err      error
}

func (d diagnosticTransport) Exchange(_ context.Context, raw []byte, note bool) ([]byte, error) {
	if note {
		return nil, nil
	}
	if d.err != nil {
		return nil, d.err
	}
	var request map[string]any
	_ = json.Unmarshal(raw, &request)
	return d.response(request), nil
}
func (diagnosticTransport) Close() error { return nil }

func TestMalformedRPCErrorRemainsProtocolRejection(t *testing.T) {
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":"request","error":{"code":"unsafe","message":"secret"}}`,
		`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"secret"}}`,
		`{"jsonrpc":"2.0","id":"request","result":{},"error":{"code":-32000,"message":"secret"}}`,
	} {
		err := interceptResponseFailure([]byte(raw), "request")
		if deliveryCode("acceptance", err) != DeliveryProtocolRejection || strings.Contains(err.Error(), "secret") {
			t.Fatalf("malformed RPC classification: %v", err)
		}
	}
}

func TestDeliveryDiagnosticCodesRetainAtomicPrefix(t *testing.T) {
	const secret = "unsafe-backend-message-token"
	rpc := func(id any) []byte {
		return sdkJSON(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32000, "message": secret, "data": map[string]any{"token": secret}}})
	}
	cases := []struct {
		name      string
		code      DeliveryCode
		transport diagnosticTransport
	}{
		{"schema", DeliveryProtocolRejection, diagnosticTransport{response: func(r map[string]any) []byte { return []byte(`{"result":"` + secret + `"}`) }}},
		{"unsupported-effect", DeliveryProtocolRejection, diagnosticTransport{response: func(r map[string]any) []byte {
			return sdkJSON(map[string]any{"jsonrpc": "2.0", "id": r["id"], "result": map[string]any{"protocolVersion": "draft", "effects": []any{map[string]any{"type": "modify", "operation": "replace", "target": "input", "value": map[string]any{"count": 99}}, map[string]any{"type": "unknown-" + secret}}}})
		}}},
		{"ungranted-effect", DeliveryProtocolRejection, diagnosticTransport{response: func(r map[string]any) []byte {
			return sdkJSON(map[string]any{"jsonrpc": "2.0", "id": r["id"], "result": map[string]any{"protocolVersion": "draft", "effects": []any{map[string]any{"type": "modify", "operation": "replace", "target": "input", "value": map[string]any{"count": 99}}, map[string]any{"type": "allow"}}}})
		}}},
		{"remote-rpc", DeliveryRemoteRPC, diagnosticTransport{response: func(r map[string]any) []byte { return rpc(r["id"]) }}},
		{"uncorrelated-rpc", DeliveryProtocolRejection, diagnosticTransport{response: func(map[string]any) []byte { return rpc("wrong") }}},
		{"transport", DeliveryTransport, diagnosticTransport{err: errors.New("safe transport failure")}},
		{"cancelled", DeliveryCancelled, diagnosticTransport{err: context.Canceled}},
		{"deadline", DeliveryDeadlineExceeded, diagnosticTransport{err: context.DeadlineExceeded}},
	}
	for _, policy := range []string{"fail-open", "fail-closed"} {
		for _, tc := range cases {
			t.Run(policy+"/"+tc.name, func(t *testing.T) {
				hooks, transports := testClient(t, "fail-open", policy)
				transports[0].reply = func(map[string]any) []any {
					return []any{map[string]any{"type": "modify", "operation": "replace", "target": "input", "value": map[string]any{"count": 2}}}
				}
				hooks.backends[1].transport = tc.transport
				// Narrow authority so a schema-valid allow effect is still ungranted.
				caps := testCaps()
				caps["effects"] = []any{"modify"}
				var narrowed ahp.Capabilities
				if err := json.Unmarshal(sdkJSON(caps), &narrowed); err != nil {
					t.Fatal(err)
				}
				result, err := hooks.intercept(context.Background(), "tool.before", testInput(), WithCapabilities(narrowed))
				if err != nil {
					t.Fatal(err)
				}
				waitObservations(t, result)
				if len(result.Errors) != 1 {
					t.Fatalf("failure multiplicity: %+v", result.Errors)
				}
				failure := result.Errors[0]
				if failure.Code != tc.code || failure.FailClosed != (policy == "fail-closed") {
					t.Fatalf("diagnostic: %+v", failure)
				}
				if strings.Contains(failure.Error(), secret) || strings.Contains(failure.Err.Error(), secret) {
					t.Fatal("unsafe backend error exposed")
				}
				if len(result.Response.Effects) != 1 || !strings.Contains(string(sdkJSON(result.EffectiveInput)), `"count":2`) {
					t.Fatalf("accepted prefix changed: %s", sdkJSON(result.Response))
				}
				if (result.State.Permission == "deny") != (policy == "fail-closed") {
					t.Fatalf("failure policy changed: %+v", result.State)
				}
				if tc.transport.err == context.Canceled && !errors.Is(failure, context.Canceled) {
					t.Fatal("lost cancellation identity")
				}
				if tc.transport.err == context.DeadlineExceeded && !errors.Is(failure, context.DeadlineExceeded) {
					t.Fatal("lost deadline identity")
				}
			})
		}
	}
}
