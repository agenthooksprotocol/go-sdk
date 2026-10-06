package interop

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func adversarialLifecycleScenarios(t *testing.T) []lifecycleScenario {
	t.Helper()
	all, err := lifecycleFixtures(interopFixturePath("lifecycle-scenarios.json"))
	if err != nil {
		t.Fatal(err)
	}
	var selected []lifecycleScenario
	for _, sc := range all {
		if sc.ID == "cancel-before-reply" || sc.ID == "cancel-after-reply-before-acceptance" || sc.ID == "cancelled-boundary-observed" || sc.ID == "settled-observer-effects-ignored" {
			selected = append(selected, sc)
		}
	}
	if len(selected) != 4 {
		t.Fatal("missing adversarial fixtures")
	}
	return selected
}

func TestLifecycleAdversarialLateReplyTransports(t *testing.T) {
	for _, sc := range adversarialLifecycleScenarios(t) {
		if sc.ID == "settled-observer-effects-ignored" {
			continue
		}
		for _, mode := range []string{"http", "stdio"} {
			t.Run(sc.ID+"/"+mode, func(t *testing.T) {
				s := publicLifecycleReceiver()
				m := sc.Requests["a"]
				key := lifecycleID(m)
				s.responses[key] = sc.Responses["a"]
				h, err := s.publicHandler()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				replies := make(chan Object, 1)
				if mode == "http" {
					go func() {
						w := httptest.NewRecorder()
						r := httptest.NewRequest("POST", "/intercept", bytes.NewReader(jsonBytes(m)))
						r.Header.Set("Content-Type", "application/json")
						h.ServeHTTP(w, r.WithContext(ctx))
						var reply Object
						_ = json.Unmarshal(w.Body.Bytes(), &reply)
						replies <- reply
					}()
				} else {
					in, send := io.Pipe()
					receive, out := io.Pipe()
					defer send.Close()
					defer receive.Close()
					var mu sync.Mutex
					done := make(chan error, 1)
					go func() { done <- serveLifecycleStdio(ctx, in, out, &mu, h) }()
					defer func() { cancel(); <-done }()
					go func() {
						scanner := bufio.NewScanner(receive)
						if scanner.Scan() {
							var reply Object
							_ = json.Unmarshal(scanner.Bytes(), &reply)
							replies <- reply
						}
					}()
					if err := json.NewEncoder(send).Encode(m); err != nil {
						t.Fatal(err)
					}
				}
				if err := s.wait(ctx, func() bool { return len(s.entries) == 1 }); err != nil {
					t.Fatal(err)
				}
				select {
				case reply := <-replies:
					t.Fatalf("reply escaped release barrier: %#v", reply)
				default:
				}
				// Cancellation is a host settlement step; releasing the receiver must still
				// deliver the exact malicious late envelope, not a public validation error.
				s.mu.Lock()
				s.record(Object{"kind": "cancelled", "id": m["id"]})
				s.released[key] = true
				s.record(Object{"kind": "release"})
				s.mu.Unlock()
				select {
				case reply := <-replies:
					if !reflect.DeepEqual(reply, sc.Responses["a"]) {
						t.Fatalf("late reply rewritten: %#v", reply)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				ordinary := obj(clone(m))
				ordinary["id"] = "ordinary-late"
				obj(obj(ordinary["params"])["event"])["id"] = "ordinary-late"
				ordinaryReply := obj(clone(sc.Responses["a"]))
				ordinaryReply["id"] = "ordinary-late"
				s.mu.Lock()
				s.responses[lifecycleID(ordinary)] = ordinaryReply
				s.released[lifecycleID(ordinary)] = true
				s.mu.Unlock()
				w := publicLifecycleCall(t, h, ordinary)
				if !bytes.Contains(w.Body.Bytes(), []byte(`"error"`)) {
					t.Fatalf("ordinary ungranted continue accepted: %s", w.Body.String())
				}
				invalid := obj(clone(m))
				delete(obj(obj(invalid["params"])["event"]), "source")
				w = publicLifecycleCall(t, h, invalid)
				if !bytes.Contains(w.Body.Bytes(), []byte(`"error"`)) {
					t.Fatalf("adversarial path skipped request validation: %s", w.Body.String())
				}

				// The exact ID must not bypass arbitrary response failures:
				// only the configured ungranted continue control is raw.
				other := obj(clone(m))
				obj(other["params"])["capabilities"] = Object{"effects": []any{"flow"}, "flow": Object{"operations": []any{"stop"}}}
				s.mu.Lock()
				s.responses[key] = response(str(m["id"]), Object{"type": "message", "text": "ungranted"})
				s.mu.Unlock()
				if s.adversarialCancellationReply(other) {
					t.Fatal("exact ID enabled a non-continue raw response")
				}
				w = publicLifecycleCall(t, h, other)
				if !bytes.Contains(w.Body.Bytes(), []byte(`"error"`)) {
					t.Fatalf("non-control response escaped rejection: %s", w.Body.String())
				}
			})
		}
	}
}

func TestLifecycleAdversarialSettledReport(t *testing.T) {
	scenarios := adversarialLifecycleScenarios(t)
	dir := t.TempDir()
	cfg := LifecycleConfig{Config: Config{Transport: "http", ScenarioFile: filepath.Join(dir, "fixture.json"), SchemaDir: schemaPath(t), ReadinessFile: filepath.Join(dir, "ready.json"), ReportFile: filepath.Join(dir, "report.json")}}
	if err := writeAtomic(cfg.ScenarioFile, Object{"version": 1, "scenarios": scenarios}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- LifecycleServer(ctx, cfg) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	var ready Object
	for Load(cfg.ReadinessFile, &ready) != nil {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	endpoint := str(ready["endpoint"])
	cfg.ControlEndpoint = str(ready["controlEndpoint"])
	malicious := response("unsolicited-observer", Object{"type": "deny", "reason": "observer must not decide"})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstream, err := http.Post(endpoint+r.URL.Path, "application/json", bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer upstream.Body.Close()
		var notification Object
		_ = json.Unmarshal(body, &notification)
		eventID := obj(obj(notification["params"])["event"])["id"]
		if r.URL.Path == "/observe" && upstream.StatusCode == 204 && eventID == "settled-observer-effects-ignored:a" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(malicious)
			return
		}
		w.WriteHeader(upstream.StatusCode)
		_, _ = io.Copy(w, upstream.Body)
	}))
	defer proxy.Close()
	cfg.Endpoint = proxy.URL
	if err := LifecycleClient(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	var report Object
	if err := Load(cfg.ReportFile, &report); err != nil {
		t.Fatal(err)
	}
	results := array(report["results"])
	if len(results) != len(scenarios) {
		t.Fatalf("missing lifecycle results: %#v", report)
	}
	for i, raw := range results {
		result := obj(raw)
		// Compare all canonical outcome fields, not only decision/permission.
		var fixture Object
		if err := Load(interopFixturePath("lifecycle-scenarios.json"), &fixture); err != nil {
			t.Fatal(err)
		}
		var expected any
		for _, raw := range array(fixture["scenarios"]) {
			sc := obj(raw)
			if sc["id"] == scenarios[i].ID {
				expected = sc["expected"]
			}
		}
		if expected == nil {
			t.Fatal("missing canonical expectation")
		}
		if !reflect.DeepEqual(result["actual"], expected) {
			t.Fatalf("settled outcome changed: got %#v want %#v", result["actual"], expected)
		}
		if result["id"] == "settled-observer-effects-ignored" {
			diagnostics := array(result["observationDiagnostics"])
			if len(diagnostics) != 2 {
				t.Fatalf("lost delivery diagnostics: %#v", result)
			}
			for _, raw := range diagnostics {
				d := obj(raw)
				if d["kind"] != "invalid-observation-acknowledgement" || d["eventId"] != "settled-observer-effects-ignored:a" || d["status"] != float64(200) || !reflect.DeepEqual(d["response"], malicious) {
					t.Fatalf("malicious response not retained: %#v", d)
				}
			}
		}
	}
	// Direct callers still receive a rejection, never malformed HTTP success.
	_, err := lifecyclePublicCall(ctx, publicLifecycleObservation("settled-observer-effects-ignored:a"), nil, http.DefaultClient, "", proxy.URL)
	var acknowledgement *lifecycleObservationAcknowledgementError
	if !errors.As(err, &acknowledgement) {
		t.Fatalf("malformed acknowledgement not rejected: %v", err)
	}
}

func TestLifecycleAdversarialFailurePolicySequence(t *testing.T) {
	all, err := lifecycleFixtures(interopFixturePath("lifecycle-scenarios.json"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, sc := range all {
		if sc.ID != "observation-chain-fail-open" && sc.ID != "observation-chain-fail-closed" {
			continue
		}
		count++
		for _, mode := range []string{"http", "stdio"} {
			t.Run(sc.ID+"/"+mode, func(t *testing.T) {
				s := publicLifecycleReceiver()
				message := sc.Requests["a"]
				key := lifecycleID(message)
				s.responses[key] = sc.Responses["a"]
				s.sequences[key] = sc.ResponseSequences["a"]
				s.released[key] = true
				h, err := s.publicHandler()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var send *io.PipeWriter
				replies := make(chan Object, 2)
				if mode == "stdio" {
					in, writer := io.Pipe()
					receive, out := io.Pipe()
					send = writer
					defer writer.Close()
					defer receive.Close()
					var mu sync.Mutex
					done := make(chan error, 1)
					go func() { done <- serveLifecycleStdio(ctx, in, out, &mu, h) }()
					defer func() { cancel(); <-done }()
					go func() {
						scanner := bufio.NewScanner(receive)
						for scanner.Scan() {
							var reply Object
							_ = json.Unmarshal(scanner.Bytes(), &reply)
							replies <- reply
						}
					}()
				}
				for i, expected := range sc.ResponseSequences["a"] {
					if s.adversarialFailurePolicyReply(message) != (i == 0) {
						t.Fatalf("wrong raw sequence occurrence %d", i)
					}
					var reply Object
					if mode == "http" {
						w := publicLifecycleCall(t, h, message)
						_ = json.Unmarshal(w.Body.Bytes(), &reply)
					} else {
						if err := json.NewEncoder(send).Encode(message); err != nil {
							t.Fatal(err)
						}
						select {
						case reply = <-replies:
						case <-ctx.Done():
							t.Fatalf("next intercept stalled after failure-policy response: %v", ctx.Err())
						}
					}
					if !reflect.DeepEqual(reply, expected) {
						t.Fatalf("occurrence %d rewritten: got %#v want %#v", i, reply, expected)
					}
				}
				// Same ungranted return on an ordinary ID must remain publicly rejected.
				ordinary := obj(clone(message))
				ordinary["id"] = "ordinary-failure-policy"
				obj(obj(ordinary["params"])["event"])["id"] = "ordinary-failure-policy"
				bad := obj(clone(sc.ResponseSequences["a"][0]))
				bad["id"] = "ordinary-failure-policy"
				s.mu.Lock()
				s.responses[lifecycleID(ordinary)] = bad
				s.released[lifecycleID(ordinary)] = true
				s.mu.Unlock()
				w := publicLifecycleCall(t, h, ordinary)
				if !bytes.Contains(w.Body.Bytes(), []byte(`"error"`)) {
					t.Fatalf("ordinary ungranted return escaped rejection: %s", w.Body.String())
				}
			})
		}
	}
	if count != 2 {
		t.Fatal("missing failure-policy controls")
	}
}
