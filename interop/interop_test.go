package interop

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func schemaPath(t *testing.T) string {
	t.Helper()
	p, e := filepath.Abs("../../agent-hooks-protocol/schema/draft")
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	p, e := filepath.Abs("../../agent-hooks-protocol/interop/fixtures/" + name)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func wire(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func request(id string) Object {
	return Object{"jsonrpc": "2.0", "id": id, "method": "hooks/intercept", "params": Object{"protocolVersion": "draft", "event": Object{"id": id, "source": "urn:ahp:interop", "type": "tool.before", "time": "2026-01-01T00:00:00Z", "session": Object{"id": "test"}, "call": Object{"id": "call-1"}, "path": "execute", "tool": Object{"name": "task", "kind": "task", "origin": "native", "input": Object{"task": float64(1)}}}, "capabilities": ToolCapabilities(), "state": Object{"permission": "none", "candidate": nil}}}
}
func response(id string, effects ...any) Object {
	return Object{"jsonrpc": "2.0", "id": id, "result": Object{"protocolVersion": "draft", "effects": effects}}
}
func testScenarios() []Scenario {
	flowRequest := request("flow")
	flowEvent := obj(obj(flowRequest["params"])["event"])
	flowEvent["type"] = "turn.finish.before"
	flowEvent["outcome"] = "completed"
	flowEvent["continuationCount"] = float64(0)
	flowEvent["items"] = []any{}
	flowEvent["turn"] = Object{"id": "turn-1"}
	delete(flowEvent, "tool")
	delete(flowEvent, "call")
	delete(flowEvent, "path")
	obj(flowRequest["params"])["capabilities"] = Object{"effects": []any{"flow", "message"}, "flow": obj(Capabilities()["flow"])}
	return []Scenario{
		{ID: "atomic", Request: wire(request("atomic")), Response: wire(response("atomic", Object{"type": "return", "value": false}, Object{"type": "modify", "target": "input", "operation": "merge", "value": Object{"task": 2}}, Object{"type": "message", "text": "accepted"})), Expected: Object{"decision": "allow", "executed": false, "input": Object{"task": float64(2)}, "messages": []any{"accepted"}, "result": false}},
		{ID: "flow", Request: wire(flowRequest), Response: wire(response("flow", Object{"type": "flow", "operation": "stop", "reason": "stop"}, Object{"type": "flow", "operation": "continue", "instruction": "next"})), Expected: Object{"decision": "allow", "executed": false, "flow": "stop"}},
		{ID: "invalid", Request: wire(request("invalid")), Response: wire(response("invalid", Object{"type": "message", "text": "must not commit"}, Object{"type": "modify", "target": "input", "operation": "merge", "value": Object{"task": 0}})), ExpectError: true},
	}
}
func TestValidationAndAtomic(t *testing.T) {
	v, e := NewValidator(schemaPath(t))
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range testScenarios() {
		t.Run(s.ID, func(t *testing.T) {
			req, e := v.Validate("intercept-request", s.Request)
			if e != nil {
				t.Fatal(e)
			}
			before := clone(req)
			res, e := v.Validate("intercept-response", s.Response)
			if e != nil {
				t.Fatal(e)
			}
			actual, e := Apply(req, res)
			if s.ExpectError {
				if e == nil {
					t.Fatal("accepted invalid effect")
				}
				if actual != nil {
					t.Fatal("partially committed")
				}
			} else {
				if e != nil {
					t.Fatal(e)
				}
				for k, x := range s.Expected {
					if !reflect.DeepEqual(actual[k], x) {
						t.Fatalf("%s: %v != %v", k, actual[k], x)
					}
				}
			}
			if !reflect.DeepEqual(before, req) {
				t.Fatal("mutated input")
			}
		})
	}
	for _, bad := range []Object{response("x", Object{"type": "unknown"}), response("x", Object{"type": "deny"}), response("x", Object{"type": "message", "text": 12})} {
		if _, e := v.Validate("intercept-response", wire(bad)); e == nil {
			t.Fatal("canonical invalid response accepted")
		}
	}
}
func TestSharedScenarios(t *testing.T) {
	path := "../../agent-hooks-protocol/interop/scenarios.json"
	if _, e := os.Stat(path); e != nil {
		t.Skip("central scenarios not published yet")
	}
	ss, e := scenarios(path)
	if e != nil {
		t.Fatal(e)
	}
	v, e := NewValidator(schemaPath(t))
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range ss {
		t.Run(s.ID, func(t *testing.T) {
			req, e := v.Validate("intercept-request", s.Request)
			if e != nil {
				t.Fatal(e)
			}
			res, e := v.Validate("intercept-response", s.Response)
			var actual Object
			if e == nil {
				actual, e = Apply(req, res)
			}
			if s.ExpectError {
				if e == nil {
					t.Fatal("expected rejection")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			for k, x := range s.Expected {
				if !reflect.DeepEqual(actual[k], x) {
					t.Fatalf("%s mismatch: got %#v expected %#v", k, actual[k], x)
				}
			}
		})
	}
}
func signed(a Auth, overrides Object) string {
	claims := Object{"iss": a.Issuer, "aud": a.Audience, "purpose": a.Purpose, "iat": a.Clock, "exp": a.Clock + 3600}
	for k, x := range overrides {
		claims[k] = x
	}
	enc := base64.RawURLEncoding.EncodeToString
	prefix := enc(wire(Object{"alg": "HS256", "typ": "JWT"})) + "." + enc(wire(claims))
	mac := hmac.New(sha256.New, []byte(a.SigningKey))
	mac.Write([]byte(prefix))
	return prefix + "." + enc(mac.Sum(nil))
}
func TestJWTRejection(t *testing.T) {
	a := Auth{SigningKey: "TEST-ONLY-key", Issuer: "issuer", Audience: "audience", Purpose: "workload", Clock: 1893456000}
	if !a.verifyJWT(signed(a, nil)) {
		t.Fatal("valid JWT rejected")
	}
	for _, bad := range []Object{{"exp": a.Clock}, {"iat": a.Clock + 1}, {"iss": "other"}, {"aud": "other"}, {"purpose": "oauth"}} {
		if a.verifyJWT(signed(a, bad)) {
			t.Fatal("invalid JWT accepted")
		}
	}
	if a.verifyJWT(signed(a, nil) + "bad") {
		t.Fatal("bad signature accepted")
	}
}
func waitReady(t *testing.T, path string) Object {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var ready Object
		if Load(path, &ready) == nil {
			return ready
		}
		select {
		case <-deadline.C:
			t.Fatal("readiness watchdog expired")
		case <-tick.C:
		}
	}
}
func transportScenarios(t *testing.T) []Scenario {
	t.Helper()
	all := testScenarios()
	path := "../../agent-hooks-protocol/interop/scenarios.json"
	if _, err := os.Stat(path); err == nil {
		central, err := scenarios(path)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, central...)
	}
	return all
}
func TestHTTPAuthModes(t *testing.T) {
	for _, mode := range []string{"none", "bearer", "oauth", "workload", "mtls"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			scenariosFile := filepath.Join(dir, "scenarios.json")
			if e := writePrettyScenarios(scenariosFile, transportScenarios(t)); e != nil {
				t.Fatal(e)
			}
			auth := Auth{Mode: mode, Token: "TEST-ONLY-bearer", Issuer: "urn:ahp:interop:local-issuer", Audience: "urn:ahp:interop:local-server", Purpose: mode, SigningKey: "TEST-ONLY-key", Clock: 1893456000}
			if mode == "mtls" {
				auth.CAFile = fixturePath(t, "ca.pem")
				auth.CertFile = fixturePath(t, "server.pem")
				auth.KeyFile = fixturePath(t, "server-key.pem")
			}
			c := Config{Transport: "http", ReadinessFile: filepath.Join(dir, "ready.json"), ScenarioFile: scenariosFile, SchemaDir: schemaPath(t), Auth: auth}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- Server(ctx, c) }()
			ready := waitReady(t, c.ReadinessFile)
			defer func() {
				cancel()
				select {
				case e := <-done:
					if e != nil {
						t.Error(e)
					}
				case <-time.After(time.Second):
					t.Error("server failed shutdown")
				}
			}()
			ca := auth
			if mode == "mtls" {
				ca.CertFile = fixturePath(t, "client.pem")
				ca.KeyFile = fixturePath(t, "client-key.pem")
			}
			if mode == "workload" {
				ca.Assertion = signed(auth, nil)
			}
			if mode == "oauth" {
				issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.ParseForm() != nil || r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "secret" || r.Form.Get("grant_type") != "client_credentials" {
						http.Error(w, "bad token request", 401)
						return
					}
					json.NewEncoder(w).Encode(Object{"access_token": signed(auth, nil), "token_type": "Bearer"})
				}))
				defer issuer.Close()
				ca.TokenEndpoint = issuer.URL
				ca.ClientID = "client"
				ca.ClientSecret = "secret"
			}
			cc := Config{Transport: "http", Endpoint: str(ready["endpoint"]), ScenarioFile: scenariosFile, ReportFile: filepath.Join(dir, "report.json"), SchemaDir: schemaPath(t), Auth: ca}
			if e := Client(ctx, cc); e != nil {
				b, _ := os.ReadFile(cc.ReportFile)
				t.Fatalf("%v: %s", e, b)
			}
			// Unauthorized requests must never be recorded (including discovery).
			if mode != "none" {
				bad := ca
				if mode == "mtls" {
					bad.CertFile = fixturePath(t, "untrusted-client.pem")
					bad.KeyFile = fixturePath(t, "untrusted-client-key.pem")
				} else {
					bad.Mode = "bearer"
					bad.Token = "invalid"
				}
				hc, token, e := bad.client(ctx)
				if e != nil {
					t.Fatal(e)
				}
				defer hc.CloseIdleConnections()
				r, _ := http.NewRequest("POST", cc.Endpoint+"/intercept", strings.NewReader(string(testScenarios()[0].Request)))
				if token != "" {
					r.Header.Set("Authorization", "Bearer "+token)
				}
				res, e := hc.Do(r)
				if e == nil {
					res.Body.Close()
					if res.StatusCode != 401 {
						t.Fatalf("unauthorized status %d", res.StatusCode)
					}
				}
			}
			res, e := http.Get(str(ready["controlEndpoint"]) + "/receipts")
			if e != nil {
				t.Fatal(e)
			}
			defer res.Body.Close()
			var receipt Object
			json.NewDecoder(res.Body).Decode(&receipt)
			if len(array(receipt["requests"])) != len(transportScenarios(t)) {
				t.Fatalf("unexpected receipts: %v", receipt)
			}
			validator, err := NewValidator(schemaPath(t))
			if err != nil {
				t.Fatal(err)
			}
			expected := map[string]Object{}
			for _, scenario := range transportScenarios(t) {
				var req Object
				if err := json.Unmarshal(scenario.Request, &req); err != nil {
					t.Fatal(err)
				}
				expected[str(req["id"])] = req
			}
			for _, raw := range array(receipt["requests"]) {
				entry := obj(raw)
				message := obj(entry["message"])
				if !reflect.DeepEqual(message, expected[str(entry["id"])]) {
					t.Fatal("receipt is not exact incoming canonical request")
				}
				if _, err := validator.Validate("intercept-request", wire(message)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
func TestStdio(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "adapter")
	build := exec.Command("go", "build", "-o", binary, "../cmd/interop")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("%v: %s", e, b)
	}
	sc := filepath.Join(dir, "scenarios.json")
	writePrettyScenarios(sc, transportScenarios(t))
	server := Config{Transport: "stdio", ScenarioFile: sc, SchemaDir: schemaPath(t), ReadinessFile: filepath.Join(dir, "ready.json")}
	config := filepath.Join(dir, "server.json")
	writeAtomic(config, server)
	for _, command := range [][]string{{binary, "server"}, {"go", "run", "../cmd/interop", "server"}} {
		client := Config{Transport: "stdio", ScenarioFile: sc, SchemaDir: schemaPath(t), ReportFile: filepath.Join(dir, "report.json"), ServerCommand: command, ServerConfig: config}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if e := Client(ctx, client); e != nil {
			b, _ := os.ReadFile(client.ReportFile)
			t.Fatalf("%v: %s", e, b)
		}
		var ready Object
		if e := Load(server.ReadinessFile, &ready); e != nil {
			t.Fatal(e)
		}
		hc := http.Client{Timeout: time.Second}
		res, e := hc.Get(str(ready["controlEndpoint"]) + "/health")
		if e == nil {
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			t.Fatal("stdio server leaked")
		}
	}
}

func writePrettyScenarios(path string, scenarios []Scenario) error {
	b, err := json.MarshalIndent(Object{"version": 1, "scenarios": scenarios}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}
func TestNDJSON(t *testing.T) {
	raw := []byte("{\n  \"jsonrpc\": \"2.0\",\n  \"text\": \"escaped\\nnewline\"\n}")
	framed, err := ndjson(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(framed, []byte("\n")) != 1 || framed[len(framed)-1] != '\n' {
		t.Fatalf("not one NDJSON line: %q", framed)
	}
	var before, after any
	json.Unmarshal(raw, &before)
	json.Unmarshal(framed, &after)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("framing changed JSON value")
	}
	if _, err := ndjson([]byte("{}\n{}")); err == nil {
		t.Fatal("accepted multiple frames")
	}
}
