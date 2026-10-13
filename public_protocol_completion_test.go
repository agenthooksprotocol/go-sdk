package ahp_test

import (
	"bytes"
	"context"
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

// This exercises inline instruction composition and actual receiver-allocated
// attachment uploads through public APIs, preserving receiver isolation coverage.
func TestPublicResolvedInstructionsAcrossReceivers(t *testing.T) {
	original := []byte("original instructions\n")
	const hostRef = "urn:test:host:report"
	var instructions ahp.TextParts
	var attachment ahp.ContentItem
	if err := json.Unmarshal(completionJSON(map[string]any{"id": "report-1", "kind": "attachment", "mediaType": "application/pdf", "selection": "body", "body": map[string]any{"ref": hostRef}}), &attachment); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(completionJSON([]any{map[string]any{"id": "instructions-1", "kind": "text", "mediaType": "text/plain", "selection": "body", "text": string(original)}}), &instructions); err != nil {
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
			ref, err := upload.Receipt(refName)
			if err != nil {
				t.Error(err)
				http.Error(w, "unverified", 500)
				return
			}
			if err := server.WriteUploadResponse(w, ref); err != nil {
				t.Error(err)
			}
		})
		handler, err := server.NewHandler(server.Handlers{Intercept: server.InterceptHandlers{ContextCompactBefore: func(_ context.Context, req server.InterceptContext[ahp.ContextCompactBeforeEvent, ahp.ContextCompactBeforeCapabilities]) (server.ContextCompactBeforeReply, error) {
			var ev map[string]any
			if err := json.Unmarshal(completionJSON(req.Event), &ev); err != nil {
				return server.ContextCompactBeforeReply{}, err
			}
			instruction := ev["instructions"].([]any)[0].(map[string]any)
			descriptor := ev["items"].([]any)[0].(map[string]any)["parts"].([]any)[0].(map[string]any)
			ref := descriptor["body"].(map[string]any)["ref"].(string)
			if !strings.HasPrefix(ref, "urn:test:receiver:"+receiver+":") {
				return server.ContextCompactBeforeReply{}, fmt.Errorf("wrong receiver ref")
			}
			mu.Lock()
			raw, ok := stored[ref]
			seen = append(seen, instruction["text"].(string))
			mu.Unlock()
			if !ok || !bytes.Equal(raw, original) || descriptor["id"] != "report-1" || instruction["id"] != "instructions-1" {
				return server.ContextCompactBeforeReply{}, fmt.Errorf("unknown bytes or changed logical identity")
			}
			effects := []*ahp.ContextCompactBeforeEffect{}
			if receiver == "a" {
				modification, err := effect.ModifyInstructionsReplace(&ahp.TextParts{&ahp.TextPart{TextBodyPart: ahp.Some(&ahp.TextBodyPart{ID: "instructions-1", Kind: ahp.TextBodyPartKindText, MediaType: ahp.TextBodyPartMediaTypeTextPlain, Selection: ahp.TextBodyPartSelectionBody, Text: "accepted instructions\n"})}})
				if err != nil {
					return server.ContextCompactBeforeReply{}, err
				}
				var typed ahp.ContextCompactBeforeEffect
				if err := json.Unmarshal(completionJSON(modification), &typed); err != nil {
					return server.ContextCompactBeforeReply{}, err
				}
				effects = append(effects, &typed)
			}
			return server.ContextCompactBeforeReply{Effects: effects}, nil
		}}}, server.Options{})
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
	hooks, err := client.New(registration.New(backends...), client.Options{Harness: ahp.Harness{Name: "test", Version: "1"}, Source: "urn:test:completion",
		Events: capability.Host{ContextCompactBefore: capability.ContextCompactBefore{ModifyInstructions: capability.Replace()}},
		// Advertise the inline text category and the bounded attachment upload size.
		Metadata: &client.ManifestMetadata{
			ContentCategories: ahp.Some([]string{"text"}),
			Limits:            ahp.Some(ahp.StaticCapabilityManifestLimits{MaxUploadBytes: ahp.Some(json.Number("4096"))}),
		},
		EventClient: endpoint.Client(), UploadClient: endpoint.Client(), Content: client.ContentOptions{AllowLoopbackHTTP: true, AuthorizeContent: func(context.Context, client.ContentAuthorization) (bool, error) { return true, nil }, Resolver: func(_ context.Context, ref string) (io.ReadCloser, error) {
			if ref != hostRef {
				return nil, fmt.Errorf("SDK leaked a staged reference to host resolver")
			}
			return io.NopCloser(bytes.NewReader(original)), nil
		}}})
	if err != nil {
		t.Fatal(err)
	}
	defer hooks.Close()
	result, err := hooks.ContextCompactBefore(context.Background(), event.ContextCompactBeforeInput{ID: ahp.Some("compact-public"), Trigger: "manual", Items: []*ahp.ModelVisibleItem{{ID: "report-message", Role: ahp.ModelVisibleItemRoleUser, Parts: []*ahp.ContentItem{&attachment}}}, Instructions: ahp.Some(&instructions)})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || len(result.Diagnostics) != 0 {
		t.Fatalf("not accepted: %+v", result)
	}
	defer result.Close()
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
