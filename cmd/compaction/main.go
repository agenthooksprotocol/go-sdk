// Offline host fixture. Runtime semantics are implemented in the public SDK.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	ahp "github.com/agenthooksprotocol/go-sdk/interop"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"
)

type O = map[string]any

func receive(request O) O {
	failure := O{"jsonrpc": "2.0", "id": request["id"], "error": O{"code": -32602, "message": "invalid request"}}
	if request["jsonrpc"] != "2.0" || request["method"] != "compaction/run" {
		return failure
	}
	p, ok := request["params"].(map[string]any)
	if !ok {
		return failure
	}
	input, ok := p["instructions"].(string)
	if !ok {
		return failure
	}
	hooks := func(boundary string) ([]ahp.CompactionHook, error) {
		result := []ahp.CompactionHook{}
		raw, exists := p[boundary]
		if !exists {
			return result, nil
		}
		rows, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("hooks")
		}
		for _, raw := range rows {
			row, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("hook")
			}
			supplier, ok := row["supplier"].(string)
			if !ok {
				return nil, fmt.Errorf("supplier")
			}
			policy := "fail-closed"
			if v, exists := row["failurePolicy"]; exists {
				policy, ok = v.(string)
				if !ok {
					return nil, fmt.Errorf("policy")
				}
			}
			result = append(result, ahp.CompactionHook{Supplier: supplier, FailurePolicy: policy, Run: func(_ ahp.Object) ([]ahp.Object, error) {
				if row["throw"] == true {
					return nil, fmt.Errorf("hook failed")
				}
				effects, ok := row["effects"].([]any)
				if !ok {
					return nil, fmt.Errorf("effects")
				}
				out := []ahp.Object{}
				for _, e := range effects {
					v, ok := e.(map[string]any)
					if !ok {
						return nil, fmt.Errorf("effect")
					}
					out = append(out, ahp.Object(v))
				}
				return out, nil
			}})
		}
		return result, nil
	}
	before, err := hooks("before")
	if err != nil {
		return failure
	}
	after, err := hooks("after")
	if err != nil {
		return failure
	}
	id := "summary-1"
	if v, exists := p["itemId"]; exists {
		id, ok = v.(string)
		if !ok {
			return failure
		}
	}
	result, err := ahp.RunCompaction(input, id, before, after, nil, p["observeOnly"] == true)
	if err != nil {
		return failure
	}
	return O{"jsonrpc": "2.0", "id": request["id"], "result": result}
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	switch os.Args[1] {
	case "stdio":
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 4096), 4*1024*1024)
		enc := json.NewEncoder(os.Stdout)
		for scanner.Scan() {
			var r O
			if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
				return err
			}
			if err := enc.Encode(receive(r)); err != nil {
				return err
			}
		}
		return scanner.Err()
	case "server":
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		fmt.Printf("{\"endpoint\":\"http://%s\"}\n", listener.Addr())
		server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+os.Getenv("AHP_COMPACTION_TOKEN") {
				w.WriteHeader(401)
				return
			}
			var request O
			if err := json.NewDecoder(io.LimitReader(r.Body, 4*1024*1024)).Decode(&request); err != nil {
				w.WriteHeader(400)
				return
			}
			json.NewEncoder(w).Encode(receive(request))
		})}
		return server.Serve(listener)
	case "client":
		var plan struct {
			Transport string
			Command   []string
			Endpoint  string
			Token     string
			Requests  []O
		}
		if err := json.NewDecoder(os.Stdin).Decode(&plan); err != nil {
			return err
		}
		replies := []O{}
		if plan.Transport == "stdio" {
			var input bytes.Buffer
			enc := json.NewEncoder(&input)
			for _, r := range plan.Requests {
				enc.Encode(r)
			}
			args := append(append([]string{}, plan.Command[1:]...), "stdio")
			cmd := exec.Command(plan.Command[0], args...)
			cmd.Stdin = &input
			cmd.Stderr = os.Stderr
			output, err := cmd.Output()
			if err != nil {
				return err
			}
			dec := json.NewDecoder(bytes.NewReader(output))
			for {
				var r O
				err := dec.Decode(&r)
				if err == io.EOF {
					break
				}
				if err != nil {
					return err
				}
				replies = append(replies, r)
			}
		} else {
			client := &http.Client{Timeout: 20 * time.Second}
			for _, r := range plan.Requests {
				body, _ := json.Marshal(r)
				req, err := http.NewRequest("POST", plan.Endpoint, bytes.NewReader(body))
				if err != nil {
					return err
				}
				req.Header.Set("Authorization", "Bearer "+plan.Token)
				response, err := client.Do(req)
				if err != nil {
					return err
				}
				var reply O
				err = json.NewDecoder(response.Body).Decode(&reply)
				response.Body.Close()
				if err != nil {
					return err
				}
				if response.StatusCode != 200 {
					return fmt.Errorf("HTTP %d", response.StatusCode)
				}
				replies = append(replies, reply)
			}
		}
		return json.NewEncoder(os.Stdout).Encode(replies)
	}
	return fmt.Errorf("unknown mode")
}
