package interop

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestLifecycleAuthParity(t *testing.T) {
	t.Setenv("AHP_GO_LIFE_UPLOAD", "independent-upload-test-token")
	t.Setenv("AHP_INTEROP_UNAUTHORIZED_UPLOAD_TOKEN", "unauthorized-upload-test-token")
	var all Object
	if e := Load("../../agent-hooks-protocol/interop/lifecycle-scenarios.json", &all); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"none", "bearer", "oauth", "workload", "mtls", "stdio"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			fixture := filepath.Join(dir, "scenarios.json")
			scenarios := []any{}
			for _, raw := range array(all["scenarios"]) {
				s := obj(raw)
				if mode != "stdio" && s["transports"] != nil && !has(s["transports"], "http") {
					continue
				}
				scenarios = append(scenarios, s)
			}
			if e := writeAtomic(fixture, Object{"version": 1, "scenarios": scenarios}); e != nil {
				t.Fatal(e)
			}
			transport := "http"
			authMode := mode
			if mode == "stdio" {
				transport = "stdio"
				authMode = "none"
			}
			auth := Auth{Mode: authMode, Token: "event-only-token", Issuer: "urn:test:issuer", Audience: "urn:test:receiver", Purpose: authMode, SigningKey: "TEST-only-key", Clock: 1893456000}
			if mode == "mtls" {
				auth.CAFile = fixturePath(t, "ca.pem")
				auth.CertFile = fixturePath(t, "server.pem")
				auth.KeyFile = fixturePath(t, "server-key.pem")
			}
			server := LifecycleConfig{Config: Config{Transport: transport, Auth: auth, ScenarioFile: fixture, SchemaDir: schemaPath(t), ReadinessFile: filepath.Join(dir, "ready.json")}}
			server.UploadAuth.Token = "independent-upload-test-token"
			server.UploadAuth.Subscriptions = []string{"body"}
			client := server
			client.ReportFile = filepath.Join(dir, "report.json")
			client.Upload = UploadBinding{TimeoutMs: 5000, Auth: &UploadAuth{Type: "bearer", TokenEnv: "AHP_GO_LIFE_UPLOAD"}}
			if mode == "mtls" {
				client.Auth.CertFile = fixturePath(t, "client.pem")
				client.Auth.KeyFile = fixturePath(t, "client-key.pem")
			}
			if mode == "workload" {
				client.Auth.Assertion = signed(auth, nil)
			}
			if mode == "oauth" {
				issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.ParseForm() != nil || r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "secret" {
						w.WriteHeader(401)
						return
					}
					json.NewEncoder(w).Encode(Object{"access_token": signed(auth, nil), "token_type": "Bearer"})
				}))
				defer issuer.Close()
				client.Auth.TokenEndpoint = issuer.URL
				client.Auth.ClientID = "client"
				client.Auth.ClientSecret = "secret"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if mode == "stdio" {
				binary := filepath.Join(dir, "lifecycle-server")
				if b, e := exec.Command("go", "build", "-o", binary, "../cmd/lifecycle-server").CombinedOutput(); e != nil {
					t.Fatalf("build: %v %.1000s", e, b)
				}
				client.ServerCommand = []string{binary}
				client.ServerConfig = filepath.Join(dir, "server.json")
				if e := writeAtomic(client.ServerConfig, server); e != nil {
					t.Fatal(e)
				}
			} else {
				done := make(chan error, 1)
				go func() { done <- LifecycleServer(ctx, server) }()
				defer func() {
					cancel()
					select {
					case e := <-done:
						if e != nil {
							t.Error(e)
						}
					case <-time.After(time.Second):
						t.Error("server shutdown timeout")
					}
				}()
				ready := waitReady(t, server.ReadinessFile)
				client.Endpoint = str(ready["endpoint"])
				client.ControlEndpoint = str(ready["controlEndpoint"])
				client.Upload.Endpoint = str(ready["uploadEndpoint"])
				if mode != "none" && mode != "mtls" {
					_, status, e := lifecycleCall(ctx, client.Endpoint+"/intercept", obj(scenarios[0])["requests"])
					if e != nil || status != 401 {
						t.Fatalf("missing event credentials: %d %v", status, e)
					}
				}
				// Event credentials never authorize the independently configured upload.
				t.Setenv("AHP_GO_EVENT_TOKEN", auth.Token)
				bad := client.Upload
				bad.Auth = &UploadAuth{Type: "bearer", TokenEnv: "AHP_GO_EVENT_TOKEN"}
				if _, status, _ := UploadContent(ctx, bad, "body", "event-token-must-fail", []byte("x")); status != 401 {
					t.Fatal("event credential accepted by upload", status)
				}
			}
			// Exclude the explicit credential rejection probes above from fixture receipts.
			receiptOffset := 0
			if transport == "http" {
				prior, err := lifecycleControl(ctx, client.ControlEndpoint, "/receipts", nil)
				if err != nil {
					t.Fatal(err)
				}
				receiptOffset = len(array(obj(prior)["entries"]))
			}
			if e := LifecycleClient(ctx, client); e != nil {
				t.Fatal(e)
			}
			var report Object
			if e := Load(client.ReportFile, &report); e != nil {
				t.Fatal(e)
			}
			results := array(report["results"])
			if len(results) != len(scenarios) {
				t.Fatal("missing scenarios")
			}
			requests := map[string]Object{}
			chainRequests := map[string][]Object{}
			chainReceived := map[string]int{}
			for i, raw := range scenarios {
				sc := obj(raw)
				actual := obj(obj(results[i])["actual"])
				for key, want := range obj(sc["expected"]) {
					if !reflect.DeepEqual(actual[key], want) {
						t.Fatalf("%s %s: got %v want %v", sc["id"], key, actual[key], want)
					}
				}
				for _, raw := range array(obj(sc["chainProof"])["requests"]) {
					req := obj(raw)
					id := lifecycleID(req)
					chainRequests[id] = append(chainRequests[id], req)
				}
				for _, req := range obj(sc["requests"]) {
					m := obj(req)
					requests[lifecycleID(m)] = m
				}
			}
			received, observed := 0, 0
			validator, e := newLifecycleValidator(schemaPath(t))
			if e != nil {
				t.Fatal(e)
			}
			uploadSteps := []Object{}
			for _, raw := range scenarios {
				for _, rawStep := range array(obj(raw)["steps"]) {
					if step := obj(rawStep); step["op"] == "upload" {
						uploadSteps = append(uploadSteps, step)
					}
				}
			}
			uploadIndex := 0
			aliases := map[string]string{}
			for _, raw := range array(obj(report["receipts"])["entries"])[receiptOffset:] {
				r := obj(raw)
				m := obj(r["message"])
				switch r["kind"] {
				case "upload":
					if uploadIndex >= len(uploadSteps) {
						t.Fatal("unexpected upload receipt")
					}
					step := uploadSteps[uploadIndex]
					uploadIndex++
					if r["size"] != step["size"] || r["sha256"] != step["sha256"] {
						t.Fatal("upload integrity receipt mismatch", r)
					}
					key := contentKey(str(step["subscription"]), str(step["ref"]))
					delete(aliases, key)
					if r["status"] == float64(201) {
						if str(r["ref"]) == "" || r["ref"] == step["ref"] {
							t.Fatal("missing receiver-allocated reference", r)
						}
						aliases[key] = str(r["ref"])
					}
				case "view":
					t.Fatal("semantic oracle receipt")
				case "received":
					received++
					want := requests[lifecycleID(m)]
					if chain, ok := chainRequests[lifecycleID(m)]; ok {
						n := chainReceived[lifecycleID(m)]
						if n >= len(chain) {
							t.Fatal("extra chain interception", m)
						}
						want = chain[n]
						chainReceived[lifecycleID(m)] = n + 1
					}
					// Only fixture aliases change on the wire, using earlier upload receipts.
					want = obj(clone(want))
					resolveUploadAliases(want, "body", aliases)
					if m == nil || !reflect.DeepEqual(m, want) {
						t.Fatal("not exact received message", r)
					}
				case "observed":
					observed++
					if e := validator.validate("observe", m); e != nil {
						t.Fatal(e)
					}
				}
			}
			if uploadIndex != len(uploadSteps) {
				t.Fatal("missing upload receipts")
			}
			if received == 0 || observed == 0 {
				t.Fatal("missing actual message receipts")
			}
			t.Log(fmt.Sprintf("%d lifecycle scenarios, %d received and %d observed messages", len(scenarios), received, observed))
		})
	}
}
