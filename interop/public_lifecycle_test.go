package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLifecyclePublicAcceptance(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		req := request("lifecycle-public")
		seen := 0
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var sent Object
			if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
				t.Error(err)
				return
			}
			seen++
			effect := Object{"type": "allow"}
			if invalid {
				effect = Object{"type": "invented-effect"}
			}
			_ = json.NewEncoder(w).Encode(response(str(sent["id"]), effect))
		}))
		accepted, err := lifecyclePublicCall(context.Background(), req, nil, peer.Client(), "", peer.URL)
		peer.Close()
		if seen != 1 {
			t.Fatalf("public runtime delivered %d times", seen)
		}
		if invalid && (err == nil || accepted != nil) {
			t.Fatalf("invalid response escaped public acceptance: %#v %v", accepted, err)
		}
		if !invalid && (err != nil || accepted["id"] != req["id"]) {
			t.Fatalf("ordinary response: %#v %v", accepted, err)
		}
	}
}

func TestLifecyclePublicObservation(t *testing.T) {
	req := request("lifecycle-observe")
	note := Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": obj(req["params"])["event"]}}
	seen := 0
	_, _, err := PublicBoundary(context.Background(), note, func(_ context.Context, method string, data []byte) ([]byte, error) {
		seen++
		var sent Object
		if err := json.Unmarshal(data, &sent); err != nil {
			return nil, err
		}
		if method != "hooks/observe" || sent["id"] != nil {
			t.Errorf("not a notification: %#v", sent)
		}
		return nil, nil
	})
	if err != nil || seen != 1 {
		t.Fatalf("observation calls=%d error=%v", seen, err)
	}
}

func TestConfirmedUploadCacheCannotMintOrCrossScopes(t *testing.T) {

	for _, tc := range []struct {
		name   string
		bodies map[string]string
		body   string
		valid  bool
	}{
		{"confirmed", map[string]string{"ready": "bytes"}, "bytes", true},
		{"unknown-scope", map[string]string{}, "bytes", false},
		{"changed-body", map[string]string{"ready": "bytes"}, "changed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &confirmedUploadTransport{endpoint: "http://127.0.0.1/upload", bodies: tc.bodies, resolved: map[string]string{confirmedBodyKey([]byte(tc.body)): "ready"}}
			request, _ := http.NewRequest("POST", transport.endpoint, bytes.NewBufferString(tc.body))
			response, err := transport.RoundTrip(request)
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				raw, _ := io.ReadAll(response.Body)
				var descriptor Object
				_ = json.Unmarshal(raw, &descriptor)
				if descriptor["ref"] != "ready" {
					t.Fatal(descriptor)
				}
			} else if err == nil {
				response.Body.Close()
				t.Fatal("unconfirmed body received a reference")
			}
		})
	}
}

// Reads may all settle before their uploads, and transfers may arrive in either order.
func TestConfirmedUploadCacheIndependentResolvedBodies(t *testing.T) {
	transport := &confirmedUploadTransport{
		endpoint: "http://127.0.0.1/upload",
		bodies:   map[string]string{"first-ref": "first", "second-ref": "second"},
		resolved: map[string]string{confirmedBodyKey([]byte("first")): "first-ref", confirmedBodyKey([]byte("second")): "second-ref"},
	}
	for _, body := range []string{"second", "first", "second"} {
		request, _ := http.NewRequest("POST", transport.endpoint, bytes.NewBufferString(body))
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		var descriptor Object
		err = json.NewDecoder(response.Body).Decode(&descriptor)
		response.Body.Close()
		if err != nil || descriptor["ref"] != body+"-ref" {
			t.Fatalf("body %q: descriptor=%v error=%v", body, descriptor, err)
		}
	}
}
