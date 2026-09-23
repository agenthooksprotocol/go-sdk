package main

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestUploadAllocatesImmutableReferences(t *testing.T) {
	store := map[string][]byte{}
	refs := []string{}
	for _, raw := range [][]byte{[]byte("one"), []byte("two"), {}} {
		request := httptest.NewRequest("POST", "/upload", bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("AHP-Content-SHA256", hash(raw))
		status, value := receiveUpload(request, raw, store)
		descriptor := obj(value)
		if status != 201 || len(descriptor) != 3 || descriptor["size"] != len(raw) || descriptor["sha256"] != hash(raw) || str(descriptor["ref"]) == "" {
			t.Fatalf("invalid confirmation %d %v", status, value)
		}
		refs = append(refs, str(descriptor["ref"]))
	}
	if len(store) != 3 || refs[0] == refs[1] || string(store[refs[0]]) != "one" {
		t.Fatal("reference was reused or changed")
	}
}

func TestUploadRejectsInvalidFramingWithoutStorage(t *testing.T) {
	for _, kind := range []string{"hash", "length", "media", "encoding", "chunked", "method"} {
		t.Run(kind, func(t *testing.T) {
			raw := []byte("bytes")
			request := httptest.NewRequest("POST", "/upload", bytes.NewReader(raw))
			request.Header.Set("Content-Type", "application/octet-stream")
			request.Header.Set("AHP-Content-SHA256", hash(raw))
			switch kind {
			case "hash":
				request.Header.Set("AHP-Content-SHA256", "bad")
			case "length":
				request.ContentLength++
			case "media":
				request.Header.Set("Content-Type", "application/json")
			case "encoding":
				request.Header.Set("Content-Encoding", "gzip")
			case "chunked":
				request.TransferEncoding = []string{"chunked"}
			case "method":
				request.Method = "PUT"
			}
			store := map[string][]byte{}
			status, _ := receiveUpload(request, raw, store)
			if status != 400 || len(store) != 0 {
				t.Fatalf("status=%d stored=%d", status, len(store))
			}
		})
	}
}

func TestRequestEventCorrelation(t *testing.T) {
	for _, tc := range []struct {
		name               string
		requestID, eventID any
		want               bool
	}{
		{"matching", "event-1", "event-1", true},
		{"different", "rpc-1", "event-1", false},
		{"missing", nil, "event-1", false},
		{"empty", "", "", false},
		{"numeric", float64(1), "1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := correlatedEvent(O{"id": tc.requestID}, O{"id": tc.eventID}); got != tc.want {
				t.Fatalf("correlation=%v, want %v", got, tc.want)
			}
		})
	}
}
