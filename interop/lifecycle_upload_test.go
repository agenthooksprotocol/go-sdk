package interop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestLifecycleUploadPolicyAndScopedReadiness(t *testing.T) {
	t.Setenv("AHP_TEST_UPLOAD", "valid-upload")
	t.Setenv("AHP_TEST_BAD_UPLOAD", "invalid-upload")
	for _, name := range []string{"default", "configured", "cross-scope", "ambiguous", "unauthorized", "anonymous-override", "explicit-endpoint"} {
		t.Run(name, func(t *testing.T) {
			var events atomic.Int32
			body := []byte{0xff, 0, 'x'}
			hash := fmt.Sprintf("%x", sha256.Sum256(body))
			headers := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/upload", "/override":
					headers <- r.Header.Get("Authorization")
					if name == "unauthorized" {
						w.WriteHeader(401)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(201)
					json.NewEncoder(w).Encode(Object{"ref": "allocated", "size": len(body), "sha256": hash})
				case "/intercept":
					events.Add(1)
					var got Object
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
						t.Error(err)
					}
					descriptor := obj(obj(array(obj(obj(got["params"])["event"])["items"])[0])["body"])
					if descriptor["ref"] != "allocated" {
						t.Error("fixture alias escaped onto wire", descriptor)
					}
					json.NewEncoder(w).Encode(response("scoped-upload", Object{"type": "allow"}))
				default:
					json.NewEncoder(w).Encode(Object{})
				}
			}))
			defer server.Close()
			dir := t.TempDir()
			cfg := LifecycleConfig{Config: Config{Transport: "http", Endpoint: server.URL, SchemaDir: schemaPath(t), ScenarioFile: filepath.Join(dir, "fixture.json"), ReportFile: filepath.Join(dir, "report.json")}, ControlEndpoint: server.URL, Upload: UploadBinding{Endpoint: server.URL + "/upload", Auth: &UploadAuth{Type: "bearer", TokenEnv: "AHP_TEST_UPLOAD"}}}
			upload := Object{"op": "upload", "subscription": "body", "ref": "local", "bodyBase64": base64.StdEncoding.EncodeToString(body)}
			send := Object{"op": "send", "key": "a", "slot": "a"}
			wantHeader := "Bearer valid-upload"
			switch name {
			case "configured":
				cfg.Uploads = map[string]UploadBinding{"body": cfg.Upload}
				cfg.Upload = UploadBinding{}
			case "cross-scope":
				send["subscription"] = "metadata"
			case "ambiguous":
				cfg.Uploads = map[string]UploadBinding{"body": cfg.Upload, "other": cfg.Upload}
			case "unauthorized":
				upload["upload"] = Object{"auth": Object{"type": "bearer", "tokenEnv": "AHP_TEST_BAD_UPLOAD"}}
				wantHeader = "Bearer invalid-upload"
			case "anonymous-override":
				upload["upload"] = Object{}
				wantHeader = ""
			case "explicit-endpoint":
				upload["upload"] = Object{"endpoint": server.URL + "/override"}
				cfg.Upload.Endpoint = "http://127.0.0.1:1/unreachable"
				wantHeader = ""
			}
			req := request("scoped-upload")
			obj(obj(req["params"])["event"])["items"] = []any{Object{"id": "item", "kind": "text", "mediaType": "application/octet-stream", "selection": "body", "body": Object{"ref": "local", "size": len(body), "sha256": hash}}}
			steps := []Object{upload, send, {"op": "receive", "slot": "a"}}
			if name == "unauthorized" {
				steps = []Object{upload}
			}
			if err := writeAtomic(cfg.ScenarioFile, Object{"scenarios": []lifecycleScenario{{ID: name, Requests: map[string]Object{"a": req}, Steps: steps}}}); err != nil {
				t.Fatal(err)
			}
			err := LifecycleClient(context.Background(), cfg)
			rejected := name == "cross-scope" || name == "ambiguous"
			if rejected {
				if err == nil || !strings.Contains(err.Error(), "unavailable scoped content reference") {
					t.Fatalf("cross-scope reference not rejected: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if got := <-headers; got != wantHeader {
				t.Fatalf("upload Authorization = %q, want %q", got, wantHeader)
			}
			wantEvents := int32(1)
			if rejected || name == "unauthorized" {
				wantEvents = 0
			}
			if events.Load() != wantEvents {
				t.Fatalf("events = %d, want %d", events.Load(), wantEvents)
			}
			if name == "unauthorized" {
				var report Object
				if err := Load(cfg.ReportFile, &report); err != nil {
					t.Fatal(err)
				}
				statuses := obj(obj(array(report["results"])[0])["actual"])["uploadStatuses"]
				if !reflect.DeepEqual(statuses, []any{float64(401)}) {
					t.Fatal("override was not rejected", statuses)
				}
			}
		})
	}
}
