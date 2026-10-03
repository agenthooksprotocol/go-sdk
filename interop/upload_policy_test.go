package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestCredentialOnlyUploadReceiverPolicy(t *testing.T) {
	t.Setenv("AHP_POLICY_UPLOAD", "upload-secret")
	for _, explicitDeny := range []bool{false, true} {
		t.Run(map[bool]string{false: "credential-scope", true: "empty-grants"}[explicitDeny], func(t *testing.T) {
			dir := t.TempDir()
			fixture := filepath.Join(dir, "scenarios.json")
			if err := writeAtomic(fixture, Object{"scenarios": []any{}}); err != nil {
				t.Fatal(err)
			}
			c := LifecycleConfig{Config: Config{Transport: "http", SchemaDir: schemaPath(t), ScenarioFile: fixture, ReadinessFile: filepath.Join(dir, "ready.json"), Auth: Auth{Mode: "bearer", Token: "event-secret"}}}
			c.UploadAuth.Token = "upload-secret"
			if explicitDeny {
				c.UploadAuth.Subscriptions = []string{}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			done := make(chan error, 1)
			go func() { done <- LifecycleServer(ctx, c) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			ready := waitReady(t, c.ReadinessFile)
			binding := UploadBinding{Endpoint: str(ready["uploadEndpoint"]), Auth: &UploadAuth{Type: "bearer", TokenEnv: "AHP_POLICY_UPLOAD"}}
			descriptor, status, err := UploadContent(ctx, binding, "untrusted-alias", "untrusted-ref", []byte{0, 255, 128})
			if explicitDeny {
				if err == nil || status != http.StatusForbidden {
					t.Fatalf("explicit empty grants: status=%d err=%v", status, err)
				}
				return
			}
			if err != nil || status != http.StatusCreated {
				t.Fatalf("credential-scoped upload: status=%d err=%v", status, err)
			}
			event := obj(obj(request("unrelated-event"))["params"])["event"]
			obj(event)["items"] = []any{Object{"id": "item", "kind": "text", "mediaType": "application/octet-stream", "selection": "body", "body": descriptor}}
			note := Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": event}}
			body, _ := json.Marshal(note)
			req, err := http.NewRequestWithContext(ctx, "POST", str(ready["endpoint"])+"/observe", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer event-secret")
			res, err := lifecycleHTTP.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("independently authenticated event failed: %d", res.StatusCode)
			}
		})
	}
}
