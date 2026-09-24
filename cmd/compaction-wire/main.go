// Canonical AHP traffic. Local host scheduling is never transmitted as a method.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	ahp "github.com/agenthooksprotocol/go-sdk/interop"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

type O = map[string]any

func obj(v any) O              { m, _ := v.(map[string]any); return m }
func arr(v any) []any          { a, _ := v.([]any); return a }
func str(v any) string         { s, _ := v.(string); return s }
func digest(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }
func location(store, sub, ref string) string {
	return filepath.Join(store, digest([]byte(sub+"\x00"+ref)))
}
func validate(v *ahp.Validator, kind string, value any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	_, e = v.Validate(kind, b)
	return e
}
func receive(request O, sub string, config O, store string, v *ahp.Validator) O {
	failure := O{"jsonrpc": "2.0", "id": request["id"], "error": O{"code": -32602, "message": "Invalid compaction request"}}
	if validate(v, "intercept-request", request) != nil {
		return failure
	}
	event := obj(obj(request["params"])["event"])
	bodies := O{}
	items := append([]any{}, arr(event["items"])...)
	for _, key := range []string{"instructions", "summary"} {
		if i, ok := event[key]; ok {
			items = append(items, i)
		}
	}
	for _, raw := range items {
		item := obj(raw)
		ref := obj(item["body"])
		body, e := os.ReadFile(location(store, sub, str(ref["ref"])))
		if e != nil || float64(len(body)) != ref["size"] || digest(body) != ref["sha256"] || !utf8.Valid(body) {
			return failure
		}
		bodies[str(item["id"])] = string(body)
	}
	action := obj(config[sub])
	if action == nil {
		return failure
	}
	effects := action["effects"]
	if action["kind"] == "append" {
		target := str(action["target"])
		item := obj(event[target])
		body, ok := bodies[str(item["id"])].(string)
		if !ok {
			return failure
		}
		effects = []any{O{"type": "modify", "target": target, "operation": "replace", "value": body + str(action["suffix"])}}
	}
	response := O{"jsonrpc": "2.0", "id": request["id"], "result": O{"protocolVersion": "draft", "effects": effects}}
	if validate(v, "intercept-response", response) != nil {
		return failure
	}
	f, e := os.OpenFile(filepath.Join(store, "receipts.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return failure
	}
	defer f.Close()
	if json.NewEncoder(f).Encode(O{"subscription": sub, "request": request, "response": response, "bodies": bodies}) != nil {
		return failure
	}
	return response
}

var client = &http.Client{Timeout: 20 * time.Second}

func post(endpoint, token string, body []byte, headers map[string]string) ([]byte, int, error) {
	request, e := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if e != nil {
		return nil, 0, e
	}
	request.Header.Set("Authorization", "Bearer "+token)
	for k, v := range headers {
		request.Header.Set(k, v)
	}
	response, e := client.Do(request)
	if e != nil {
		return nil, 0, e
	}
	defer response.Body.Close()
	if response.StatusCode == 201 && strings.Split(response.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return nil, response.StatusCode, fmt.Errorf("upload confirmation media type")
	}
	raw, e := io.ReadAll(response.Body)
	return raw, response.StatusCode, e
}
func exchange(plan O, sub, name string, snapshot O, v *ahp.Validator, trace *[]any) ([]ahp.Object, error) {
	credential := obj(obj(plan["credentials"])[sub])
	boundary := str(snapshot["boundary"])
	event := O{"id": name + ":" + boundary, "source": "urn:ahp:compaction-host", "time": "2026-09-15T12:00:00Z", "session": O{"id": name}, "type": "context.compact." + boundary}
	item := func(id, kind, text, role string) (O, error) {
		raw := []byte(text)
		hash := digest(raw)
		reply, status, e := post(str(plan["endpoint"])+"/upload", str(credential["uploadToken"]), raw, map[string]string{"Content-Type": "application/octet-stream", "AHP-Content-SHA256": hash})
		if e != nil {
			return nil, e
		}
		var ref O
		if status != 201 || json.Unmarshal(reply, &ref) != nil || len(ref) != 3 || str(ref["ref"]) == "" || ref["size"] != float64(len(raw)) || ref["sha256"] != hash {
			return nil, fmt.Errorf("invalid upload confirmation %d", status)
		}
		return O{"id": id, "kind": kind, "mediaType": "text/plain", "role": role, "selection": "body", "body": ref}, nil
	}
	if boundary == "before" {
		context, e := item(name+":context", "user", "conversation", "user")
		if e != nil {
			return nil, e
		}
		instructions, e := item(name+":instructions", "instructions", str(snapshot["instructions"]), "system")
		if e != nil {
			return nil, e
		}
		event["trigger"] = "manual"
		event["items"] = []any{context}
		event["instructions"] = instructions
	} else {
		handle := obj(snapshot["summary"])
		summary, e := item(str(handle["id"]), "summary", str(obj(snapshot["bodies"])[str(handle["ref"])]), "assistant")
		if e != nil {
			return nil, e
		}
		event["summary"] = summary
		event["parentEventId"] = name + ":before"
		event["removed"] = []any{O{"id": name + ":context"}}
		candidate := obj(snapshot["candidate"])
		if candidate == nil {
			event["execution"] = O{"status": "executed"}
		} else {
			event["execution"] = O{"status": "skipped", "reason": "supplied_result"}
		}
	}
	request := O{"jsonrpc": "2.0", "id": event["id"], "method": "hooks/intercept", "params": O{"protocolVersion": "draft", "event": event, "capabilities": snapshot["capabilities"]}}
	if e := validate(v, "intercept-request", request); e != nil {
		return nil, e
	}
	raw, _ := json.Marshal(request)
	var reply []byte
	if plan["transport"] == "http" {
		out, status, e := post(str(plan["endpoint"])+"/hooks/intercept", str(credential["token"]), raw, map[string]string{"Content-Type": "application/json"})
		if e != nil {
			return nil, e
		}
		if status != 200 {
			return nil, fmt.Errorf("HTTP %d", status)
		}
		reply = out
	} else {
		command := arr(plan["receiverCommand"])
		args := []string{}
		for _, a := range command[1:] {
			args = append(args, str(a))
		}
		args = append(args, "stdio", sub)
		cmd := exec.Command(str(command[0]), args...)
		cmd.Stdin = bytes.NewReader(append(raw, '\n'))
		cmd.Stderr = os.Stderr
		out, e := cmd.Output()
		if e != nil {
			return nil, e
		}
		reply = out
	}
	var response O
	if e := json.Unmarshal(reply, &response); e != nil {
		return nil, e
	}
	*trace = append(*trace, O{"subscription": sub, "request": request, "response": response})
	if e := validate(v, "intercept-response", response); e != nil {
		return nil, e
	}
	if response["id"] != request["id"] {
		return nil, fmt.Errorf("correlation")
	}
	effects, ok := obj(response["result"])["effects"].([]any)
	if !ok {
		return nil, fmt.Errorf("effects")
	}
	out := []ahp.Object{}
	for _, e := range effects {
		out = append(out, obj(e))
	}
	return out, nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	args := os.Args[1:]
	if args[0] != "host" && args[0] != "server" && args[0] != "stdio" {
		mode := args[3]
		reordered := []string{mode, args[0], args[1], args[2]}
		args = append(reordered, args[4:]...)
	}
	if args[0] == "host" {
		var plan O
		if e := json.NewDecoder(os.Stdin).Decode(&plan); e != nil {
			return e
		}
		v, e := ahp.NewValidator(str(plan["schema"]))
		if e != nil {
			return e
		}
		out := []any{}
		for _, raw := range arr(plan["cases"]) {
			row := obj(raw)
			name := str(row["name"])
			trace := []any{}
			hooks := func(boundary string) []ahp.CompactionHook {
				result := []ahp.CompactionHook{}
				for _, raw := range arr(row[boundary]) {
					h := obj(raw)
					result = append(result, ahp.CompactionHook{Supplier: str(h["supplier"]), FailurePolicy: str(h["failurePolicy"]), Run: func(snapshot ahp.Object) ([]ahp.Object, error) {
						return exchange(plan, str(h["supplier"]), name, snapshot, v, &trace)
					}})
				}
				return result
			}
			result, e := ahp.RunCompaction("base", name+":summary", hooks("before"), hooks("after"), nil, false)
			if e != nil {
				return e
			}
			downstream := []any{}
			if result["applied"] == true {
				downstream = append(downstream, obj(result["bodies"])[str(obj(result["summary"])["ref"])])
			}
			out = append(out, O{"name": name, "result": result, "trace": trace, "downstream": downstream})
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	schema, store, configPath := args[1], args[2], args[3]
	v, e := ahp.NewValidator(schema)
	if e != nil {
		return e
	}
	raw, e := os.ReadFile(configPath)
	if e != nil {
		return e
	}
	var config O
	if e = json.Unmarshal(raw, &config); e != nil {
		return e
	}
	if args[0] == "stdio" {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 4096), 4*1024*1024)
		for scanner.Scan() {
			var request O
			if e := json.Unmarshal(scanner.Bytes(), &request); e != nil {
				return e
			}
			json.NewEncoder(os.Stdout).Encode(receive(request, args[4], config, store, v))
		}
		return scanner.Err()
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	fmt.Printf("{\"endpoint\":\"http://%s\"}\n", listener.Addr())
	return http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upload := r.URL.Path == "/upload"
		name := "AHP_COMPACTION_TOKENS"
		if upload {
			name = "AHP_COMPACTION_UPLOAD_TOKENS"
		}
		var tokens map[string]string
		_ = json.Unmarshal([]byte(os.Getenv(name)), &tokens)
		sub := tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || sub == "" || config[sub] == nil {
			w.WriteHeader(401)
			return
		}
		if r.Method != "POST" || (!upload && r.URL.Path != "/hooks/intercept") {
			w.WriteHeader(404)
			return
		}
		raw, e := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024+1))
		if e != nil || len(raw) > 4*1024*1024 {
			w.WriteHeader(400)
			return
		}
		if upload {
			if r.ContentLength != int64(len(raw)) || len(r.TransferEncoding) != 0 || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Content-Type") != "application/octet-stream" || digest(raw) != r.Header.Get("AHP-Content-SHA256") {
				w.WriteHeader(400)
				return
			}
			var id [32]byte
			if _, e := rand.Read(id[:]); e != nil {
				w.WriteHeader(500)
				return
			}
			ref := fmt.Sprintf("urn:ahp:content:%x", id)
			f, e := os.OpenFile(location(store, sub, ref), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				w.WriteHeader(500)
				return
			}
			_, e = f.Write(raw)
			closeErr := f.Close()
			if e != nil || closeErr != nil {
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(O{"ref": ref, "size": len(raw), "sha256": digest(raw)})
			return
		}
		var request O
		if json.Unmarshal(raw, &request) != nil {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(receive(request, sub, config, store, v))
	}))
}
