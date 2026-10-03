package interop

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

func Capabilities() Object {
	return Object{"effects": []any{"deny", "allow", "ask", "modify", "message", "return", "flow", "inject"}, "modify": Object{"input": Object{"replace": true, "merge": true}}, "flow": Object{"operations": []any{"stop", "continue"}, "remainingContinuations": 4, "continuationCount": 0, "maxContinuations": 4}, "inject": Object{"context": Object{"append": true, "deliverAt": []any{"now", "next_turn"}}}}
}

func ToolCapabilities() Object {
	caps := Capabilities()
	caps["flow"] = Object{"operations": []any{"stop"}}
	return caps
}

type serverState struct {
	mu        sync.Mutex
	requests  []any
	barriers  map[string]chan struct{}
	scenarios []Scenario
	validator *Validator
	lineage   TaskLineage
}

func (s *serverState) intercept(ctx context.Context, b []byte) ([]byte, error) {
	req, e := s.validator.Validate("intercept-request", b)
	if e != nil {
		return nil, e
	}
	event := obj(obj(req["params"])["event"])
	if e := checkContent(event, "", nil); e != nil {
		return nil, e
	}
	if e := s.lineage.Accept(event); e != nil {
		return nil, e
	}
	id := str(event["id"])
	var scenario *Scenario
	for i := range s.scenarios {
		if s.scenarios[i].ID == id {
			scenario = &s.scenarios[i]
			break
		}
	}
	if scenario == nil {
		return nil, fmt.Errorf("unknown scenario")
	}
	s.mu.Lock()
	s.requests = append(s.requests, Object{"id": id, "method": "hooks/intercept", "accepted": true, "message": clone(req)})
	barrier := s.barriers[scenario.Barrier]
	s.mu.Unlock()
	if barrier != nil {
		select {
		case <-barrier:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// Fixtures deliberately contain invalid responses for negative tests. Validate
	// normal replies; send negative fixtures unchanged so the remote client proves rejection.
	if !scenario.ExpectError {
		response, err := s.validator.Validate("intercept-response", scenario.Response)
		if err != nil {
			return nil, err
		}
		response["id"] = req["id"]
		return json.Marshal(response)
	}
	return scenario.Response, nil
}
func rpcError(id any) Object {
	return Object{"jsonrpc": "2.0", "id": id, "error": Object{"code": -32602, "message": "request rejected"}}
}
func Server(ctx context.Context, c Config) error {
	if !c.Auth.validMode() {
		return fmt.Errorf("unsupported auth mode")
	}
	if c.Transport != "http" && c.Transport != "stdio" {
		return fmt.Errorf("unsupported transport")
	}
	if c.Transport == "stdio" && c.Auth.mode() != "none" {
		return fmt.Errorf("HTTP auth is inapplicable to stdio")
	}
	v, e := NewValidator(c.SchemaDir)
	if e != nil {
		return e
	}
	ss, e := scenarios(c.ScenarioFile)
	if e != nil {
		return e
	}
	state := &serverState{validator: v, scenarios: ss, requests: []any{}, barriers: map[string]chan struct{}{}}
	for _, s := range ss {
		if s.Barrier != "" {
			state.barriers[s.Barrier] = make(chan struct{})
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	control, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	defer control.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(Object{"ready": true}) })
	mux.HandleFunc("GET /receipts", func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		json.NewEncoder(w).Encode(Object{"requests": state.requests})
	})
	mux.HandleFunc("POST /release", func(w http.ResponseWriter, r *http.Request) {
		var b Object
		if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&b) != nil {
			http.Error(w, "invalid control", 400)
			return
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		ch, ok := state.barriers[str(b["barrier"])]
		if ok {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
		json.NewEncoder(w).Encode(Object{"released": ok})
	})
	mux.HandleFunc("POST /shutdown", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Object{"shutdown": true})
		cancel()
	})
	controlServer := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	defer controlServer.Close()
	go controlServer.Serve(control)
	endpoint := "stdio"
	var ahpServer *http.Server
	if c.Transport == "http" {
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return e
		}
		defer listener.Close()
		scheme := "http"
		if c.Auth.mode() == "mtls" {
			tc, e := c.Auth.tlsConfig(true)
			if e != nil {
				return e
			}
			listener = tls.NewListener(listener, tc)
			scheme = "https"
		}
		endpoint = scheme + "://" + listener.Addr().String()
		m := http.NewServeMux()
		m.HandleFunc("GET /capabilities", func(w http.ResponseWriter, r *http.Request) {
			if !c.Auth.authorize(r) {
				http.Error(w, "unauthorized", 401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(Capabilities())
		})
		m.HandleFunc("POST /intercept", func(w http.ResponseWriter, r *http.Request) {
			if !c.Auth.authorize(r) {
				http.Error(w, "unauthorized", 401)
				return
			}
			b, e := io.ReadAll(io.LimitReader(r.Body, (4<<20)+1))
			if e != nil || len(b) > 4<<20 {
				http.Error(w, "invalid body", 400)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			out, e := state.intercept(ctx, b)
			if e != nil {
				http.Error(w, "request rejected", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(out)
		})
		ahpServer = &http.Server{Handler: m, ReadHeaderTimeout: 5 * time.Second}
		defer ahpServer.Close()
		go ahpServer.Serve(listener)
	}
	if e = writeAtomic(c.ReadinessFile, Object{"endpoint": endpoint, "controlEndpoint": "http://" + control.Addr().String(), "pid": os.Getpid()}); e != nil {
		return e
	}
	if c.Transport == "stdio" {
		done := make(chan error, 1)
		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Buffer(make([]byte, 4096), 4<<20)
			for scanner.Scan() {
				b := append([]byte(nil), scanner.Bytes()...)
				var req Object
				if json.Unmarshal(b, &req) != nil {
					json.NewEncoder(os.Stdout).Encode(rpcError(nil))
					continue
				}
				if req["method"] == "hooks/capabilities" {
					if _, err := v.Validate("capabilities-request", b); err != nil {
						json.NewEncoder(os.Stdout).Encode(rpcError(req["id"]))
						continue
					}
					response := Object{"jsonrpc": "2.0", "id": req["id"], "result": Object{"protocolVersion": "draft", "manifest": Object{
						"events":     []any{Object{"event": "tool.before", "modes": []any{"intercept"}, "capabilities": ToolCapabilities()}, Object{"event": "turn.finish.before", "modes": []any{"intercept"}, "capabilities": Object{"effects": []any{"flow", "message"}, "flow": obj(Capabilities()["flow"])}}},
						"gaps":       []any{Object{"path": "events.other", "reason": "Synthetic tool.before and turn.finish.before application only"}},
						"transports": []any{"http", "stdio"}, "authentication": []any{"bearer", "oauth", "workload", "mtls"},
						"toolPaths": []any{"native"}, "contentCategories": []any{}, "limits": Object{"maxContinuations": 4},
						"managedPolicy": Object{"scopes": []any{"user"}, "disableable": true}, "correlationIdentityFields": []any{"event.id", "call.id"},
					}}}
					encoded, err := json.Marshal(response)
					if err == nil {
						_, err = v.Validate("capabilities-response", encoded)
					}
					if err != nil {
						json.NewEncoder(os.Stdout).Encode(rpcError(req["id"]))
						continue
					}
					frame, err := ndjson(encoded)
					if err != nil {
						done <- err
						return
					}
					if _, err = os.Stdout.Write(frame); err != nil {
						done <- err
						return
					}
					continue
				}
				call, cancel := context.WithTimeout(ctx, 20*time.Second)
				out, e := state.intercept(call, b)
				cancel()
				if e != nil {
					json.NewEncoder(os.Stdout).Encode(rpcError(req["id"]))
				} else {
					frame, err := ndjson(out)
					if err != nil {
						json.NewEncoder(os.Stdout).Encode(rpcError(req["id"]))
						continue
					}
					if _, err = os.Stdout.Write(frame); err != nil {
						done <- err
						return
					}
				}
			}
			done <- scanner.Err()
		}()
		select {
		case e := <-done:
			return e
		case <-ctx.Done():
			return nil
		}
	}
	<-ctx.Done()
	return nil
}
