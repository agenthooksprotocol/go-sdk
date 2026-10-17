package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

// Exercise the standard typed decoder and New's configuration snapshot, not the
// raw AdditionalProperties escape hatch: both must retain JSON member precedence.
func TestRegistrationHeadersTypedOrderLastWins(t *testing.T) {
	t.Setenv("AHP_OVERRIDDEN_HEADER", "")
	for _, first := range []string{`"first"`, `{"valueEnv":"AHP_OVERRIDDEN_HEADER"}`, `{"valueRef":"must-not-resolve"}`} {
		for _, names := range [][2]string{{"x-key", "X-Key"}, {"X-Key", "x-key"}} {
			t.Run(first+"/"+names[0], func(t *testing.T) {
				calls, resolutions := 0, 0
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					values := r.Header.Values("X-Key")
					if len(values) != 1 || values[0] != "last" {
						t.Errorf("wire headers=%v; want one last value", values)
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				defer srv.Close()
				raw := []byte(fmt.Sprintf(`{"protocolVersion":"draft","hooks":[{"id":"com.example.headers","transport":{"type":"http","url":%q,"headers":{%q:%s,%q:"last"}},"subscriptions":[{"events":["tool.before"],"mode":"intercept","timeoutMs":1000,"failurePolicy":"fail-closed","content":{"default":"metadata"}}]}]}`, srv.URL, names[0], first, names[1]))
				parsed := ahp.ParseRegistration(raw)
				if !parsed.OK {
					t.Fatal(parsed.Diagnostics)
				}
				// Include a normal generated encode/decode round trip before New snapshots
				// the registration again; a stale losing source must not reappear.
				encoded, err := json.Marshal(parsed.Value)
				if err != nil {
					t.Fatal(err)
				}
				var reg ahp.Registration
				if err := json.Unmarshal(encoded, &reg); err != nil {
					t.Fatal(err)
				}
				c, err := New(reg, Options{Harness: ahp.Harness{Name: "test", Version: "1"}, Source: "urn:test:headers", Events: testHost(), Metadata: testManifestMetadata(), EventClient: srv.Client(), HeaderResolver: func(context.Context, HeaderRequest) (string, error) {
					resolutions++
					t.Error("overridden reference was resolved")
					return "wrong", nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if _, err := c.backends[0].transport.Exchange(context.Background(), []byte(`{}`), true); err != nil {
					t.Fatal(err)
				}
				if calls != 1 || resolutions != 0 {
					t.Fatalf("requests=%d resolutions=%d", calls, resolutions)
				}
			})
		}
	}
}
