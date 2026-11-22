package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
	"github.com/agenthooksprotocol/go-sdk/diagnostic"
	"reflect"
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
		if deliveryCode("acceptance", err) != diagnostic.ProtocolRejection || strings.Contains(err.Error(), "secret") {
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
		code      diagnostic.Code
		transport diagnosticTransport
	}{
		{"schema", diagnostic.ProtocolRejection, diagnosticTransport{response: func(r map[string]any) []byte { return []byte(`{"result":"` + secret + `"}`) }}},
		{"unsupported-effect", diagnostic.ProtocolRejection, diagnosticTransport{response: func(r map[string]any) []byte {
			return sdkJSON(map[string]any{"jsonrpc": "2.0", "id": r["id"], "result": map[string]any{"protocolVersion": "draft", "effects": []any{map[string]any{"type": "modify", "operation": "replace", "target": "input", "value": map[string]any{"count": 99}}, map[string]any{"type": "unknown-" + secret}}}})
		}}},
		{"ungranted-effect", diagnostic.ProtocolRejection, diagnosticTransport{response: func(r map[string]any) []byte {
			return sdkJSON(map[string]any{"jsonrpc": "2.0", "id": r["id"], "result": map[string]any{"protocolVersion": "draft", "effects": []any{map[string]any{"type": "modify", "operation": "replace", "target": "input", "value": map[string]any{"count": 99}}, map[string]any{"type": "allow"}}}})
		}}},
		{"remote-rpc", diagnostic.RemoteRpc, diagnosticTransport{response: func(r map[string]any) []byte { return rpc(r["id"]) }}},
		{"uncorrelated-rpc", diagnostic.ProtocolRejection, diagnosticTransport{response: func(map[string]any) []byte { return rpc("wrong") }}},
		{"transport", diagnostic.Transport, diagnosticTransport{err: errors.New("safe transport failure")}},
		{"cancelled", diagnostic.Cancelled, diagnosticTransport{err: context.Canceled}},
		{"deadline", diagnostic.DeadlineExceeded, diagnosticTransport{err: context.DeadlineExceeded}},
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
				if len(result.Diagnostics) != 1 {
					t.Fatalf("failure multiplicity: %+v", result.Diagnostics)
				}
				failure := result.Diagnostics[0]
				if failure.Code != tc.code || failure.FailClosed != (policy == "fail-closed") {
					t.Fatalf("diagnostic: %+v", failure)
				}
				if strings.Contains(failure.Error(), secret) || strings.Contains(failure.Err.Error(), secret) {
					t.Fatal("unsafe backend error exposed")
				}
				if len(result.response.Effects.Value) != 1 || !strings.Contains(string(sdkJSON(result.Event.ToolBeforeEvent.Value.Tool.Input)), `"count":2`) {
					t.Fatalf("accepted prefix changed: %s", sdkJSON(result.response))
				}
				if (result.state.Permission == "deny") != (policy == "fail-closed") {
					t.Fatalf("failure policy changed: %+v", result.state)
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

// A typed auth failure from the real authenticated HTTP transport reaches the
// delivery diagnostic redacted, so a host can prompt login for that backend.
func TestDeliveryDiagnosticCarriesTypedAuthError(t *testing.T) {
	const secret = "secret-provider-detail"
	for _, tc := range []struct {
		name string
		err  error
		want *auth.Error
	}{
		// A scope set with any invalid token is dropped whole, never filtered.
		{"interaction-required", errors.Join(errors.New(secret), &auth.Error{Code: auth.CodeInteractionRequired, Scopes: []string{"events", "bad scope"}}), &auth.Error{Code: auth.CodeInteractionRequired}},
		{"interaction-required-sorted", errors.Join(errors.New(secret), &auth.Error{Code: auth.CodeInteractionRequired, Scopes: []string{"write", "events", "write"}}), &auth.Error{Code: auth.CodeInteractionRequired, Scopes: []string{"events", "write"}}},
		{"unclassified", errors.New(secret), &auth.Error{Code: auth.CodeProviderFailed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := clientAuthProvider{credential: func(context.Context, auth.Request) (auth.Credential, error) { return auth.Credential{}, tc.err }}
			transport, err := newAuthenticatedBackendTransport(registrationAuthTestBackend(t, "https://not-dispatched.example/hooks"), nil, provider)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.Close()
			hooks, _ := testClient(t, "fail-open", "fail-open")
			hooks.backends[1].transport = transport
			result, err := hooks.intercept(context.Background(), "tool.before", testInput())
			if err != nil {
				t.Fatal(err)
			}
			waitObservations(t, result)
			if len(result.Diagnostics) != 1 {
				t.Fatalf("diagnostics: %+v", result.Diagnostics)
			}
			failure := result.Diagnostics[0]
			if failure.Auth == nil || !reflect.DeepEqual(*failure.Auth, *tc.want) || failure.BackendID != hooks.backends[1].id {
				t.Fatalf("auth diagnostic = %+v", failure.Auth)
			}
			if classified := auth.Classify(failure); classified == nil || classified.Code != tc.want.Code {
				t.Fatalf("error chain lost the auth code: %v", failure)
			}
			if strings.Contains(fmt.Sprintf("%v %+v", failure, failure.Auth), secret) {
				t.Fatal("provider error leaked")
			}
		})
	}
}
