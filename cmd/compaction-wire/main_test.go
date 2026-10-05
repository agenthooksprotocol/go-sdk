package main

import (
	"bytes"
	"encoding/json"
	ahp "github.com/agenthooksprotocol/go-sdk/interop"
	"mime"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUploadFailureSuppressesEvent(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		media      string
		descriptor O
	}{
		{"204", 204, "application/json", nil},
		{"202", 202, "application/json", nil},
		{"empty-ref", 201, "application/json", O{"ref": "", "size": 12, "sha256": digest([]byte("conversation"))}},
		{"size", 201, "application/json", O{"ref": "opaque", "size": 13, "sha256": digest([]byte("conversation"))}},
		{"hash", 201, "application/json", O{"ref": "opaque", "size": 12, "sha256": "bad"}},
		{"extra-field", 201, "application/json", O{"ref": "opaque", "size": 12, "sha256": digest([]byte("conversation")), "extra": true}},
		{"media", 201, "text/plain", O{"ref": "opaque", "size": 12, "sha256": digest([]byte("conversation"))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/upload" {
					t.Error("dependent event sent")
				}
				if r.Header.Get("Authorization") != "Bearer upload-secret" {
					t.Error("wrong upload credential")
				}
				for _, h := range []string{"AHP-Content-Ref", "AHP-Subscription"} {
					if r.Header.Get(h) != "" {
						t.Errorf("sent %s", h)
					}
				}
				w.Header().Set("Content-Type", tc.media)
				w.WriteHeader(tc.status)
				if tc.descriptor != nil {
					json.NewEncoder(w).Encode(tc.descriptor)
				}
			}))
			defer server.Close()
			trace := []any{}
			_, err := exchange(O{"endpoint": server.URL, "transport": "http", "credentials": O{"scope": O{"token": "event-secret", "uploadToken": "upload-secret"}}}, "scope", "case", O{"boundary": "before", "instructions": "base", "capabilities": compactionTestCaps()}, nil, &trace)
			if err == nil || calls != 1 || len(trace) != 0 {
				t.Fatalf("err=%v calls=%d trace=%v", err, calls, trace)
			}
		})
	}
}

func TestStorageScopeIsIndependentOfReference(t *testing.T) {
	if location("store", "principal-a", "ref") == location("store", "principal-b", "ref") {
		t.Fatal("cross-principal storage collision")
	}
}

func TestCompactionHTTPRepliesUseJSON(t *testing.T) {
	validator, err := ahp.NewValidator("../../../agent-hooks-protocol/schema/draft")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AHP_COMPACTION_TOKENS", `{"event-token":"scope"}`)
	handler := compactionHTTPHandler(O{"scope": O{"effects": []any{}}}, t.TempDir(), validator)
	peer := httptest.NewServer(handler)
	defer peer.Close()
	for _, invalid := range []bool{false, true} {
		name := "success"
		if invalid {
			name = "rpc-error"
		}
		t.Run(name, func(t *testing.T) {
			eventID := "compact"
			if invalid {
				eventID = "mismatched-event"
			}
			request := O{"jsonrpc": "2.0", "id": "compact", "method": "hooks/intercept", "params": O{"protocolVersion": "draft", "event": O{"id": eventID, "source": "urn:test:host", "time": "2026-09-15T12:00:00Z", "type": "context.compact.before", "trigger": "manual", "items": []any{}}, "capabilities": O{"effects": []any{}}}}
			raw, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodPost, peer.URL+"/hooks/intercept", bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer event-token")
			req.Header.Set("Content-Type", "application/json")
			reply, err := peer.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer reply.Body.Close()
			media, _, err := mime.ParseMediaType(reply.Header.Get("Content-Type"))
			if err != nil || media != "application/json" {
				t.Fatalf("JSON-RPC reply media type=%q error=%v", reply.Header.Get("Content-Type"), err)
			}
			var envelope O
			if err := json.NewDecoder(reply.Body).Decode(&envelope); err != nil {
				t.Fatal(err)
			}
			if reply.StatusCode != http.StatusOK || envelope["jsonrpc"] != "2.0" || envelope["id"] != "compact" {
				t.Fatalf("invalid response status=%d envelope=%v", reply.StatusCode, envelope)
			}
			if (envelope["error"] != nil) != invalid {
				t.Fatalf("invalid=%v envelope=%v", invalid, envelope)
			}
		})
	}
}

func compactionTestCaps() O { caps, _ := ahp.CompactionCapabilities("before", false); return caps }
