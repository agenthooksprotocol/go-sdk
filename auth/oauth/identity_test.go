package oauth

import (
	"net/http"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

func TestManagedChallengeMetadataCannotBroadenResourceIdentifier(t *testing.T) {
	f, p, r := setup(t, "client_credentials")
	r.Binding = nil
	r.Destination += "/child"
	_, err := p.Challenge(budget(t), r, auth.Challenge{StatusCode: 401, Header: http.Header{"Www-Authenticate": {`Bearer resource_metadata="` + f.server.URL + `/custom-resource"`}}})
	assertCode(t, err, auth.CodeDiscoveryFailed)
	if f.tokenCalls.Load() != 0 {
		t.Fatal("covering but wrong source identifier reached token exchange")
	}
}
func TestDiscoveryLocationsPreserveSourceQuery(t *testing.T) {
	got := discoveryLocations("https://resource.example/events?view=1", "oauth-protected-resource", false)
	if len(got) != 2 || got[0] != "https://resource.example/.well-known/oauth-protected-resource/events?view=1" {
		t.Fatalf("source identifier query lost: %v", got)
	}
	if !resourceCovers("https://resource.example/events?view=1", "https://resource.example/events?view=1") || resourceCovers("https://resource.example/events?view=1", "https://resource.example/events?view=2") {
		t.Fatal("query resource identity conflated")
	}
}
