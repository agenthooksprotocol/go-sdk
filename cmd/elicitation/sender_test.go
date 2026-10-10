package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	hooks "github.com/agenthooksprotocol/go-sdk/client"
	sdk "github.com/agenthooksprotocol/go-sdk/interop"
)

func senderFixture(stage string, raw []byte) O {
	meta := O{"server": "requesting-server", "mode": "form", stage: O{"id": stage + "-body", "kind": "text", "mediaType": "text/plain", "selection": "body", "text": string(raw)}}
	event := O{"id": stage, "source": "urn:real:requester", "type": "user.elicitation." + stage, "time": "2026-09-01T00:00:00Z", "session": O{"id": "real-session"}, "elicitation": meta}
	if stage == "result" {
		event["parentEventId"] = "request"
		meta["action"] = "accept"
	}
	return O{"jsonrpc": "2.0", "id": stage, "method": "hooks/intercept", "params": O{"protocolVersion": "draft", "event": event, "capabilities": O{"effects": []any{}}}}
}
func senderFixtureStep(message O) senderStep {
	raw, _ := json.Marshal(message)
	return senderStep{Path: "/hooks/intercept", Bytes: base64.StdEncoding.EncodeToString(raw)}
}
func senderFixtureSource(stage string, raw []byte) senderSource {
	return senderSource{Descriptor: O{"ref": "urn:" + stage, "size": len(raw), "sha256": hash(raw)}, Bytes: base64.StdEncoding.EncodeToString(raw)}
}

func TestOrdinaryResultUsesPersistedActualRequest(t *testing.T) {
	reqBody := []byte(`{"message":"Choose","requestedSchema":{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"]}}`)
	resultBody := []byte(`{"action":"accept","content":{"answer":"yes"}}`)
	requests := []O{}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upload" {
			t.Error("inline MCP JSON must not upload")
			raw, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(O{"ref": "urn:uploaded:" + hash(raw), "size": len(raw), "sha256": hash(raw)})
			return
		}
		var request O
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		response, err := sdk.ReceiveBoundary(r.Context(), request, func(admitted O) (O, error) {
			requests = append(requests, admitted)
			meta := obj(obj(obj(admitted["params"])["event"])["elicitation"])
			for _, stage := range []string{"request", "result"} {
				if item := obj(meta[stage]); item != nil {
					if item["body"] != nil || item["kind"] != "text" || !json.Valid([]byte(str(item["text"]))) {
						t.Errorf("MCP payload is not inline JSON text: %#v", item)
					}
				}
			}
			return O{"jsonrpc": "2.0", "id": admitted["id"], "result": O{"protocolVersion": "draft", "effects": []any{}}}, nil
		})
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer peer.Close()
	base := senderPlan{Endpoint: peer.URL, Token: "principal", UploadToken: "upload-principal", StateFile: filepath.Join(t.TempDir(), "private", "state.json")}
	before := base
	before.Steps = []senderStep{senderFixtureStep(senderFixture("request", reqBody))}
	first, err := runSender(context.Background(), before, peer.Client())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || len(obj(first[0])["contentUploads"].([]any)) != 0 {
		t.Fatalf("inline MCP JSON unexpectedly uploaded: %#v", first)
	}
	// The second invocation has only inline result JSON. It must recover the actual
	// previously accepted original request, not derive an identity from the result.
	after := base
	after.Steps = []senderStep{senderFixtureStep(senderFixture("result", resultBody))}
	bad := senderFixture("result", resultBody)
	obj(obj(bad["params"])["event"])["session"] = O{"id": "other"}
	wrong := after
	wrong.Steps = []senderStep{senderFixtureStep(bad)}
	if _, err := runSender(context.Background(), wrong, peer.Client()); err == nil {
		t.Fatal("mismatched session accepted")
	}
	if len(requests) != 1 {
		t.Fatal("invalid result reached receiver")
	}
	if _, err := runSender(context.Background(), after, peer.Client()); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 {
		t.Fatalf("request count %d", len(requests))
	}
	if _, err := runSender(context.Background(), after, peer.Client()); err == nil {
		t.Fatal("consumed request snapshot reused")
	}
	// A host that retains state elsewhere can supply the real original explicitly.
	explicit := after
	explicit.OriginalRequest = senderFixture("request", reqBody)
	if _, err := runSender(context.Background(), explicit, peer.Client()); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 3 {
		t.Fatal("explicit original did not cross public result dispatch")
	}

}

func TestOrdinaryResultNeverFallsBackToRaw(t *testing.T) {
	raw := []byte(`{"action":"accept","content":{}}`)
	p := senderPlan{Endpoint: "http://127.0.0.1:1", Token: "principal", StateFile: filepath.Join(t.TempDir(), "private", "state.json"), ContentSources: []senderSource{senderFixtureSource("result", raw)}, Steps: []senderStep{senderFixtureStep(senderFixture("result", raw))}}
	if _, err := runSender(context.Background(), p, &http.Client{}); err == nil {
		t.Fatal("missing original request accepted")
	} else {
		t.Log(fmt.Sprintf("explicit missing-state rejection: %v", err))
	}
}

func TestSenderLocalSourceReceiptEvidence(t *testing.T) {
	raw := []byte{0, 255, 128, '\r', '\n'}
	for _, mode := range []string{"valid", "ref-only", "size", "hash", "null-size", "extra"} {
		t.Run(mode, func(t *testing.T) {
			source := senderFixtureSource("request", raw)
			switch mode {
			case "ref-only":
				delete(source.Descriptor, "size")
				delete(source.Descriptor, "sha256")
			case "size":
				source.Descriptor["size"] = len(raw) + 1
			case "hash":
				source.Descriptor["sha256"] = hash([]byte("wrong"))
			case "null-size":
				source.Descriptor["size"] = nil
			case "extra":
				source.Descriptor["extension"] = true
			}
			// Exercise the same JSON-decoded plan shape as the matrix process.
			wire, err := json.Marshal(senderPlan{ContentSources: []senderSource{source}})
			if err != nil {
				t.Fatal(err)
			}
			var plan senderPlan
			if err = json.Unmarshal(wire, &plan); err != nil {
				t.Fatal(err)
			}
			got, err := senderSources(plan)
			if mode == "valid" {
				if err != nil || string(got["urn:request"]) != string(raw) {
					t.Fatalf("receipt source rejected: %v", err)
				}
			} else if err == nil {
				t.Fatal("invalid receipt evidence admitted")
			}
		})
	}
}

func TestSenderDoesNotPublishUnverifiedReceiptEvidence(t *testing.T) {
	raw := []byte{0, 255, 128, 13, 10}
	for _, mode := range []string{"size", "hash"} {
		t.Run(mode, func(t *testing.T) {
			uploads := 0
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/upload" {
					t.Error("invalid receipt reached event exchange")
					w.WriteHeader(500)
					return
				}
				uploads++
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != string(raw) {
					t.Errorf("binary body changed: %v", err)
				}
				receipt := O{"ref": "receiver-only", "size": len(body), "sha256": hash(body)}
				if mode == "size" {
					receipt["size"] = len(body) + 1
				} else {
					receipt["sha256"] = hash([]byte("wrong"))
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(receipt)
			}))
			defer peer.Close()
			// Receipt verification applies to immutable binary attachments, not inline MCP text.
			request := O{"jsonrpc": "2.0", "id": "binary", "method": "hooks/intercept", "params": O{"protocolVersion": "draft", "capabilities": O{"effects": []any{}}, "event": O{
				"id": "binary", "source": "urn:test", "time": "2026-09-01T00:00:00Z", "type": "model.request.before",
				"attempt": O{"id": "attempt", "number": 1}, "model": O{"id": "model", "provider": "test"}, "params": O{},
				"items": []any{O{"id": "message", "role": "user", "parts": []any{O{"id": "binary-part", "kind": "attachment", "mediaType": "application/octet-stream", "selection": "body", "body": O{"ref": "urn:binary"}}}}},
			}}}
			receipts := &elicitationReceiptTransport{base: peer.Client().Transport, receipts: map[string]O{}}
			delivered := false
			_, _, err := sdk.PublicBoundary(context.Background(), request, func(context.Context, string, []byte) ([]byte, error) {
				delivered = true
				t.Error("unverified receipt reached event exchange")
				return nil, nil
			}, sdk.PublicBoundaryOptions{
				Content: hooks.ContentOptions{AllowLoopbackHTTP: true, Resolver: resolver(map[string][]byte{"urn:binary": raw})},
				Upload:  O{"endpoint": peer.URL + "/upload", "timeoutMs": 10000, "maxBytes": 4096}, UploadClient: &http.Client{Transport: receipts},
			})
			if err == nil || delivered || uploads != 1 {
				t.Fatalf("unverified receipt escaped: %v uploads=%d", err, uploads)
			}
		})
	}
}
