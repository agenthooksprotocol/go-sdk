package ahp_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/capability"
	"github.com/agenthooksprotocol/go-sdk/client"
	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/effect"
	"github.com/agenthooksprotocol/go-sdk/event"
	"github.com/agenthooksprotocol/go-sdk/registration"
	"github.com/agenthooksprotocol/go-sdk/server"
	"github.com/agenthooksprotocol/go-sdk/subscription"
	"github.com/agenthooksprotocol/go-sdk/transport"
)

// This exercises public APIs and actual receiver-allocated uploads, rather than
// deriving a passing result from the fixture's own composition implementation.
func TestPublicResolvedInstructionsAcrossReceivers(t *testing.T) {
	original := []byte("original instructions\n")
	const hostRef = "urn:test:host:instructions"
	var instruction ahp.ContentItem
	if err := json.Unmarshal(completionJSON(map[string]any{"id": "instructions-1", "kind": "text", "mediaType": "text/plain", "selection": "body", "body": map[string]any{"ref": hostRef, "size": len(original), "sha256": fmt.Sprintf("%x", sha256.Sum256(original))}}), &instruction); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	stored := map[string][]byte{}
	seen := []string{}
	uploaded := []string{}
	mux := http.NewServeMux()
	for _, receiver := range []string{"a", "b"} {
		mux.HandleFunc("/upload/"+receiver, func(w http.ResponseWriter, r *http.Request) {
			upload, err := server.ParseUpload(r, 4096)
			if err != nil {
				http.Error(w, "invalid upload", 400)
				return
			}
			defer upload.Close()
			raw, err := io.ReadAll(upload)
			if err != nil {
				http.Error(w, "invalid bytes", 400)
				return
			}
			mu.Lock()
			refName := fmt.Sprintf("urn:test:receiver:%s:%d", receiver, len(stored))
			stored[refName] = append([]byte(nil), raw...)
			uploaded = append(uploaded, refName)
			mu.Unlock()
			ref, err := upload.Reference(refName)
			if err != nil {
				t.Error(err)
				http.Error(w, "unverified", 500)
				return
			}
			if err := server.WriteUploadResponse(w, ref); err != nil {
				t.Error(err)
			}
		})
		handler, err := server.NewHandler(server.Handlers{Intercept: func(_ context.Context, req ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
			var wire map[string]any
			_ = json.Unmarshal(completionJSON(req), &wire)
			ev := wire["params"].(map[string]any)["event"].(map[string]any)
			descriptor := ev["instructions"].(map[string]any)
			ref := descriptor["body"].(map[string]any)["ref"].(string)
			if !strings.HasPrefix(ref, "urn:test:receiver:"+receiver+":") {
				return ahp.InterceptResponseResult{}, fmt.Errorf("wrong receiver ref")
			}
			mu.Lock()
			raw, ok := stored[ref]
			seen = append(seen, string(raw))
			mu.Unlock()
			if !ok || descriptor["id"] != "instructions-1" {
				return ahp.InterceptResponseResult{}, fmt.Errorf("unknown bytes or changed logical identity")
			}
			version := ahp.ProtocolVersion("draft")
			effects := []*ahp.Effect{}
			if receiver == "a" {
				modification, err := effect.ModifyInstructionsReplace("accepted instructions\n")
				if err != nil {
					return ahp.InterceptResponseResult{}, err
				}
				effects = append(effects, modification)
			}
			return ahp.InterceptResponseResult{ProtocolVersion: &version, Effects: effects}, nil
		}}, server.Options{})
		if err != nil {
			t.Fatal(err)
		}
		mux.Handle("/hooks/"+receiver, handler)
	}
	endpoint := httptest.NewServer(mux)
	defer endpoint.Close()
	backends := []*ahp.Backend{}
	for _, receiver := range []string{"a", "b"} {
		upload := content.NewUpload(endpoint.URL+"/upload/"+receiver, json.Number("4096"), time.Second)
		sub := subscription.NewIntercept([]string{"context.compact.before"}, time.Second, "fail-closed", content.NewSelection("body"), subscription.WithInterceptUpload(upload))
		backends = append(backends, registration.NewBackend("com.example."+receiver, transport.NewHttp(endpoint.URL+"/hooks/"+receiver), sub))
	}
	compactCapabilities, err := capability.Intercept(capability.ModifyInstructions(capability.Replace))
	if err != nil {
		t.Fatal(err)
	}
	var manifest ahp.StaticCapabilityManifest
	if err := json.Unmarshal(completionJSON(map[string]any{"events": []any{map[string]any{"event": "context.compact.before", "modes": []string{"intercept"}, "capabilities": compactCapabilities.Capabilities}}, "gaps": []any{}, "transports": []string{"http"}, "authentication": []any{}, "toolPaths": []any{}, "contentCategories": []string{"text"}, "limits": map[string]any{"maxUploadBytes": 4096}, "managedPolicy": map[string]any{"scopes": []string{"user"}, "disableable": true}, "correlationIdentityFields": []string{"event.id"}}), &manifest); err != nil {
		t.Fatal(err)
	}
	hooks, err := client.New(registration.New(backends...), client.Options{Source: "urn:test:completion", Manifest: manifest, EventClient: endpoint.Client(), UploadClient: endpoint.Client(), Content: client.ContentOptions{AllowLoopbackHTTP: true, AuthorizeContent: func(context.Context, client.ContentAuthorization) (bool, error) { return true, nil }, Resolver: func(_ context.Context, ref string) (io.ReadCloser, error) {
		if ref != hostRef {
			return nil, fmt.Errorf("SDK leaked a staged reference to host resolver")
		}
		return io.NopCloser(bytes.NewReader(original)), nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer hooks.Close()
	result, err := hooks.ContextCompactBefore(context.Background(), event.ContextCompactBeforeInput{ID: ahp.Some("compact-public"), Trigger: "manual", Items: []*ahp.ModelVisibleItem{}, Instructions: ahp.Some(&instruction)})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || len(result.Errors) != 0 {
		t.Fatalf("not accepted: %+v", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != string(original) || seen[1] != "accepted instructions\n" {
		t.Fatalf("effective receiver bodies: %q", seen)
	}
	if len(uploaded) != 2 || uploaded[0] == uploaded[1] {
		t.Fatalf("receiver upload isolation: %v", uploaded)
	}
}
func completionJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}
