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

	sdk "github.com/agenthooksprotocol/go-sdk/interop"
)

func senderFixture(stage string, raw []byte) O {
	meta := O{"server": "requesting-server", "mode": "form", stage: O{"id": stage + "-body", "kind": "elicitation." + stage, "mediaType": "application/json", "selection": "body", "body": O{"ref": "urn:" + stage, "size": len(raw), "sha256": hash(raw)}}}
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
	return senderSource{Descriptor: O{"ref": "urn:" + stage, "size": float64(len(raw)), "sha256": hash(raw)}, Bytes: base64.StdEncoding.EncodeToString(raw)}
}

func TestOrdinaryResultUsesPersistedActualRequest(t *testing.T) {
	reqBody := []byte(`{"message":"Choose","requestedSchema":{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"]}}`)
	resultBody := []byte(`{"action":"accept","content":{"answer":"yes"}}`)
	requests := []O{}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upload" {
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
	before.ContentSources = []senderSource{senderFixtureSource("request", reqBody)}
	before.Steps = []senderStep{senderFixtureStep(senderFixture("request", reqBody))}
	if _, err := runSender(context.Background(), before, peer.Client()); err != nil {
		t.Fatal(err)
	}
	// The second invocation has only result bytes. It must recover the actual
	// previously accepted original request, not derive an identity from the result.
	after := base
	after.ContentSources = []senderSource{senderFixtureSource("result", resultBody)}
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
	explicit.ContentSources = append(explicit.ContentSources, senderFixtureSource("request", reqBody))
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
