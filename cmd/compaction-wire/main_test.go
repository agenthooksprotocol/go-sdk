package main

import (
	"encoding/json"
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
			_, err := exchange(O{"endpoint": server.URL, "transport": "http", "credentials": O{"scope": O{"token": "event-secret", "uploadToken": "upload-secret"}}}, "scope", "case", O{"boundary": "before"}, nil, &trace)
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
