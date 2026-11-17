package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

// Challenged replay: once, same body and JSON-RPC id, only for intercept,
// configuration and capabilities; never for notifications or uploads.
func TestManagedChallengedReplayOnce(t *testing.T) {
	for _, test := range []struct {
		name, body, mode string
		purpose          auth.Operation
		status           int
		deliveries       int32
	}{
		{"intercept", `{"jsonrpc":"2.0","id":7,"method":"hooks/intercept","params":{}}`, "ok", auth.Event, 200, 2},
		{"configuration", `{"jsonrpc":"2.0","id":"c","method":"hooks/configuration","params":{}}`, "ok", auth.Event, 200, 2},
		{"capabilities", `{"jsonrpc":"2.0","id":1,"method":"hooks/capabilities","params":{}}`, "ok", auth.Event, 200, 2},
		{"observe-notification", `{"jsonrpc":"2.0","method":"hooks/observe","params":{}}`, "ok", auth.Event, 401, 1},
		{"upload", `{"jsonrpc":"2.0","id":7,"method":"hooks/intercept","params":{}}`, "ok", auth.Upload, 401, 1},
		{"second-rejection", `{"jsonrpc":"2.0","id":7,"method":"hooks/intercept","params":{}}`, "reject-events", auth.Event, 401, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			f.mode.Store(test.mode)
			r.Binding, r.Purpose = nil, test.purpose
			request, err := http.NewRequestWithContext(budget(t), http.MethodPost, r.Destination, strings.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			response, err := auth.Do(f.server.Client(), request, r, auth.Route(auth.Routes{OAuth: p}))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			io.Copy(io.Discard, response.Body)
			if response.StatusCode != test.status || f.eventCalls.Load() != test.deliveries {
				t.Fatalf("status %d after %d deliveries", response.StatusCode, f.eventCalls.Load())
			}
			for _, body := range f.bodies {
				if body != test.body {
					t.Fatal("replay changed the body or request id")
				}
			}
		})
	}
}
func TestManagedConfiguredAuthorizationBypassesAllOAuth(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	options := p.options
	options.CheckDestination = func(context.Context, string, Purpose) error { return errors.New("OAuth policy must not be called") }
	managed, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(budget(t), http.MethodPost, r.Destination, strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := auth.DoWithHeaders(f.server.Client(), request, r, managed, http.Header{"Authorization": {"Custom host-token"}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || f.tokenCalls.Load() != 0 || f.eventCalls.Load() != 1 {
		t.Fatal("explicit Authorization did not bypass OAuth")
	}
}
