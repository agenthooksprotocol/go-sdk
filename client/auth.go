package client

import (
	"encoding/json"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
	"net/http"
)

// newAuthenticatedBackendTransport applies registration-aware authentication.
func newAuthenticatedBackendTransport(backend *ahp.Backend, client *http.Client, provider auth.Provider) (backendTransport, error) {
	transport, err := newBackendTransport(backend, client)
	if err != nil {
		return nil, err
	}
	if t, ok := transport.(*httpBackend); ok {
		var backendID string
		if backend.ID != nil {
			backendID = string(*backend.ID)
		}
		request := auth.Request{BackendID: backendID, Destination: t.url, Purpose: auth.Event}
		if backend.Authentication.Present {
			request.Binding, err = json.Marshal(backend.Authentication.Value)
			if err != nil {
				transport.Close()
				return nil, auth.ErrConfig
			}
		}
		t.provider = provider
		t.authRequest = &request
	}
	return transport, nil
}
