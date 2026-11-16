package oauth

import (
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

// An unavailable metadata service is a real host HTTP boundary. A cached grant
// must be usable without touching it, including after reconstructing Provider.
type unavailableMetadata struct{ calls atomic.Int32 }

func (u *unavailableMetadata) RoundTrip(*http.Request) (*http.Response, error) {
	u.calls.Add(1)
	return nil, errors.New("metadata temporarily unavailable")
}

func TestCachedUnboundUnsafeDeliveryAfterProviderRecreation(t *testing.T) {
	for _, purpose := range []auth.Operation{auth.Event, auth.Upload} {
		t.Run(string(purpose), func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			r.Binding = nil
			r.Purpose = purpose
			credential, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer resource_metadata="` + f.server.URL + `/custom-resource"`}}})
			if err != nil || credential == nil {
				t.Fatalf("authorize target: %v", err)
			}
			outage := &unavailableMetadata{}
			client := *f.server.Client()
			client.Transport = outage
			options := p.options
			options.HTTPClient = &client
			recreated, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequestWithContext(budget(t), http.MethodPost, r.Destination, strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			response, err := auth.Do(f.server.Client(), request, r, auth.Route(auth.Routes{OAuth: recreated}), false)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusOK || f.eventCalls.Load() != 1 {
				t.Fatalf("unsafe delivery did not send cached bearer on first attempt: %d", response.StatusCode)
			}
			if outage.calls.Load() != 0 || f.tokenCalls.Load() != 1 {
				t.Fatal("cached grant performed metadata/token HTTP")
			}
		})
	}
}
