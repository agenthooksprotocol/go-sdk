package client

import (
	"encoding/json"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
	"net/http"
)

// newAuthenticatedBackendTransport preserves the legacy resolver as an explicit
// compatibility adapter. A registration-aware provider takes precedence.
func newAuthenticatedBackendTransport(backend *ahp.Backend, client *http.Client, resolver EventTransportResolver, provider auth.Provider) (backendTransport, error) {
	transport, err := newBackendTransport(backend, client, resolver)
	if err != nil {
		return nil, err
	}
	if t, ok := transport.(*httpBackend); ok {
		backendMap, _ := sdkMap(backend)
		backendID, _ := backendMap["id"].(string)
		request := auth.Request{BackendID: backendID, Destination: t.url, Purpose: auth.Event}
		if backend.Authentication.Present {
			request.Binding, err = json.Marshal(backend.Authentication.Value)
			if err != nil {
				transport.Close()
				return nil, auth.ErrConfig
			}
		}
		// Deployment-specific mechanisms remain owned by the explicit transport
		// resolver, not by a bearer provider. Unknown bindings without one fail closed.
		var kind struct{ Type string }
		_ = json.Unmarshal(request.Binding, &kind)
		if kind.Type != "" && kind.Type != "bearer" && kind.Type != "oauth" && resolver != nil {
			provider = nil
		}
		t.provider = provider
		t.authRequest = &request
	}
	return transport, nil
}
