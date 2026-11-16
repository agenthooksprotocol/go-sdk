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

func TestManagedDeliveryOwnsBoundedSafeReplay(t *testing.T) {
	for _, safe := range []bool{true, false} {
		t.Run(map[bool]string{true: "safe", false: "effectful"}[safe], func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			r.Binding = nil
			request, err := http.NewRequestWithContext(budget(t), http.MethodPost, r.Destination, strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			response, err := auth.Do(f.server.Client(), request, r, auth.Route(auth.Routes{OAuth: p}), safe)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			io.Copy(io.Discard, response.Body)
			expectedStatus, expectedDeliveries := http.StatusUnauthorized, int32(1)
			if safe {
				expectedStatus = http.StatusOK
				expectedDeliveries = 2
			}
			if response.StatusCode != expectedStatus || f.eventCalls.Load() != expectedDeliveries {
				t.Fatal("managed provider changed transport replay policy")
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
	response, err := auth.DoWithHeaders(f.server.Client(), request, r, managed, true, http.Header{"Authorization": {"Custom host-token"}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || f.tokenCalls.Load() != 0 || f.eventCalls.Load() != 1 {
		t.Fatal("explicit Authorization did not bypass OAuth")
	}
}
