// Offline HTTP sender/receiver. No expected outcomes enter the adapters.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	sdk "github.com/agenthooksprotocol/go-sdk/interop"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type O = map[string]any

func obj(v any) O          { m, _ := v.(map[string]any); return m }
func str(v any) string     { s, _ := v.(string); return s }
func hash(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// receiveUpload runs only after credential authentication has selected this store.
func receiveUpload(r *http.Request, raw []byte, store map[string][]byte) (int, any) {
	if r.Method != "POST" || r.ContentLength != int64(len(raw)) || len(r.TransferEncoding) != 0 || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Content-Type") != "application/octet-stream" || hash(raw) != r.Header.Get("AHP-Content-SHA256") {
		return 400, nil
	}
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return 500, nil
	}
	ref := fmt.Sprintf("urn:ahp:content:%x", id)
	store[ref] = raw
	return 201, O{"ref": ref, "size": len(raw), "sha256": hash(raw)}
}

// Correlation is required by base/events; it is not an authorization claim.
func correlatedEvent(message, event O) bool {
	id, ok := message["id"].(string)
	return ok && id != "" && id == event["id"]
}

func main() {
	if os.Args[1] == "client" {
		var plan senderPlan
		if err := json.NewDecoder(io.LimitReader(os.Stdin, 24<<20)).Decode(&plan); err != nil {
			panic(err)
		}
		results, err := runSender(context.Background(), plan, &http.Client{Timeout: 10 * time.Second})
		if err != nil {
			panic(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(results); err != nil {
			panic(err)
		}
		return
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true
	files, e := filepath.Glob(filepath.Join(os.Args[2], "*.schema.json"))
	if e != nil {
		panic(e)
	}
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			panic(e)
		}
		var s O
		json.Unmarshal(b, &s)
		if e = compiler.AddResource(str(s["$id"]), bytes.NewReader(b)); e != nil {
			panic(e)
		}
	}
	compiled := map[string]*jsonschema.Schema{}
	validate := func(name string, value any) error {
		if name == "form-answer" {
			input := obj(value)
			raw, err := json.Marshal(input["schema"])
			if err != nil {
				return err
			}
			c := jsonschema.NewCompiler()
			c.AssertFormat = true
			if err = c.AddResource("https://local.test/form", bytes.NewReader(raw)); err != nil {
				return err
			}
			schema, err := c.Compile("https://local.test/form")
			if err != nil {
				return err
			}
			return schema.Validate(input["value"])
		}
		s := compiled[name]
		if s == nil {
			parts := strings.Split(name, "#")
			url := "https://agenthooksprotocol.org/schemas/draft/" + parts[0] + ".schema.json"
			if len(parts) > 1 {
				url += "#/$defs/" + parts[1]
			}
			var err error
			s, err = compiler.Compile(url)
			if err != nil {
				return err
			}
			compiled[name] = s
		}
		return s.Validate(value)
	}
	token, principal := os.Getenv("AHP_ELICITATION_TOKEN"), os.Args[3]
	if token == "" || principal == "" {
		panic("Missing auth")
	}
	store := map[string][]byte{}
	type requestKey struct{ Source, ID string }
	pending := map[requestKey]O{}
	receipts := []any{}
	resolve := func(ref O) ([]byte, error) {
		if err := validate("content-reference", ref); err != nil {
			return nil, err
		}
		b, ok := store[str(ref["ref"])]
		if !ok || float64(len(b)) != ref["size"] || hash(b) != ref["sha256"] {
			return nil, fmt.Errorf("Upload integrity")
		}
		return b, nil
	}
	if os.Args[1] == "check" {
		var cases []O
		if err := json.NewDecoder(os.Stdin).Decode(&cases); err != nil {
			panic(err)
		}
		outputs := []any{}
		for _, c := range cases {
			clear(store)
			uploads, _ := c["uploads"].([]any)
			for _, u := range uploads {
				upload := obj(u)
				raw, err := base64.StdEncoding.DecodeString(str(upload["bytes"]))
				if err != nil {
					panic(err)
				}
				store[str(upload["ref"])] = raw
			}
			var summary O
			var err error
			before, _ := json.Marshal(c)
			if c["op"] == "capability" {
				origin := str(c["origin"])
				if origin == "" {
					origin = "ahp"
				}
				summary, err = sdk.ValidateElicitationMode(str(c["mode"]), obj(c["capabilities"]), origin)
			} else if c["op"] == "apply" {
				effects, _ := c["effects"].([]any)
				summary, err = sdk.ApplyElicitationEffects(obj(c["request"]), obj(c["result"]), resolve, validate, principal, effects)
			} else {
				summary, err = sdk.ValidateElicitationExchange(obj(c["request"]), obj(c["result"]), resolve, validate, principal, obj(c["effect"]))
			}
			after, _ := json.Marshal(c)
			if !bytes.Equal(before, after) {
				panic("input mutated")
			}

			if err != nil {
				outputs = append(outputs, O{"accepted": false})
			} else {
				outputs = append(outputs, O{"accepted": true, "summary": summary})
			}
			if c["op"] == "apply" {
				obj(outputs[len(outputs)-1])["inputUnchanged"] = bytes.Equal(before, after)
			}
		}
		json.NewEncoder(os.Stdout).Encode(outputs)
		return
	}
	// net/http is concurrent; a single lock serializes each isolated receiver store.
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		expected := token
		if r.URL.Path == "/upload" && os.Getenv("AHP_ELICITATION_UPLOAD_TOKEN") != "" {
			expected = os.Getenv("AHP_ELICITATION_UPLOAD_TOKEN")
		}
		if r.Header.Get("Authorization") != "Bearer "+expected {
			w.WriteHeader(401)
			return
		}
		status, response := func() (int, any) {
			raw, err := io.ReadAll(io.LimitReader(r.Body, 4194305))
			if err != nil || len(raw) > 4194304 {
				return 400, nil
			}
			if r.URL.Path == "/upload" {
				return receiveUpload(r, raw, store)
			}
			if r.URL.Path == "/receipts" {
				return 200, receipts
			}
			if r.URL.Path != "/hooks/intercept" {
				return 400, nil
			}
			var message O
			if json.Unmarshal(raw, &message) != nil || validate("intercept-request", message) != nil {
				return 400, nil
			}
			accepted, err := sdk.ReceiveBoundary(context.Background(), message, func(message sdk.Object) (sdk.Object, error) {
				event := obj(obj(message["params"])["event"])
				meta := obj(event["elicitation"])
				parent := str(event["id"])
				if event["type"] != "user.elicitation.request" {
					parent = str(event["parentEventId"])
				}
				key := requestKey{str(event["source"]), parent}
				if !correlatedEvent(message, event) || parent == "" {
					return nil, fmt.Errorf("host elicitation rejected")
				}
				var body []byte
				var summary O
				switch event["type"] {
				case "user.elicitation.request":
					if _, exists := pending[key]; exists {
						return nil, fmt.Errorf("host elicitation rejected")
					}
					if _, err = sdk.ValidateElicitationMode(str(meta["mode"]), O{"form": O{}, "url": O{}}, "ahp"); err != nil {
						return nil, fmt.Errorf("host elicitation rejected")
					}
					payload, e := sdk.ReadSelectedElicitation(meta, "request", resolve, validate)
					if e != nil {
						return nil, fmt.Errorf("host elicitation rejected")
					}
					if payload != nil {
						body, _ = resolve(obj(obj(meta["request"])["body"]))
						summary = O{"request": payload}
					} else {
						selection := str(obj(meta["request"])["selection"])
						if selection == "" {
							selection = "omit"
						}
						summary = O{"selection": selection}
					}
					pending[key] = message

				case "user.elicitation.result":
					req, ok := pending[key]
					if !ok {
						return nil, fmt.Errorf("host elicitation rejected")
					}
					summary, err = sdk.ValidateElicitationExchange(req, message, resolve, validate, principal, nil)
					if err != nil {
						return nil, fmt.Errorf("host elicitation rejected")
					}
					if item := obj(meta["result"]); obj(item["body"]) != nil {
						body, _ = resolve(obj(item["body"]))
					}
					delete(pending, key)
				default:
					return nil, fmt.Errorf("host elicitation rejected")
				}
				receipts = append(receipts, O{"message": message, "bytes": base64.StdEncoding.EncodeToString(body), "summary": summary})
				return O{"jsonrpc": "2.0", "id": message["id"], "result": O{"protocolVersion": "draft", "effects": []any{}}}, nil
			})
			if err != nil {
				return 400, nil
			}
			return 200, accepted
		}()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == 204 {
			return
		}
		if status == 400 {
			response = O{"error": "rejected"}
		}
		json.NewEncoder(w).Encode(response)
	})
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		panic(e)
	}
	json.NewEncoder(os.Stdout).Encode(O{"endpoint": "http://" + listener.Addr().String()})
	if e = http.Serve(listener, handler); e != nil {
		panic(e)
	}
}

type elicitationUploadTransport struct{ token string }

func (t elicitationUploadTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(r)
}
