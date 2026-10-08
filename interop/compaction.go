package interop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	ahp "github.com/agenthooksprotocol/go-sdk"
	hooks "github.com/agenthooksprotocol/go-sdk/client"
	"github.com/agenthooksprotocol/go-sdk/server"
	"io"
	"net/http"
)

// CompactionHook is a serial host-owned subscription. Run receives a detached
// snapshot. A failed response never commits any of its staged effects.
type CompactionHook struct {
	Supplier      string
	FailurePolicy string
	Run           func(Object) ([]Object, error)
}

// CompactionCapabilities advertises only enforceable text replacement.
func CompactionCapabilities(boundary string, observeOnly bool) (Object, error) {
	if boundary != "before" && boundary != "after" {
		return nil, fmt.Errorf("unknown boundary")
	}
	if observeOnly {
		return Object{"effects": []any{}, "modify": Object{}}, nil
	}
	target := "summary"
	effects := []any{"modify", "message"}
	if boundary == "before" {
		target = "instructions"
		effects = append(effects, "return", "deny")
	}
	return Object{"effects": effects, "modify": Object{target: Object{"replace": true, "merge": false}}}, nil
}

// RunCompaction runs the before pipeline, generation/substitution, then after
// controls. Only applied=true permits downstream use. Returned bodies are
// immutable UTF-8 content; upload them before exposing their references on ahp.
// Observe-only after callbacks run on detached goroutines after settlement; their
// results, errors and panics cannot change settlement or delay downstream use.
func RunCompaction(instructions, itemID string, before, after []CompactionHook, generate func(string) (string, error), observeOnly bool) (Object, error) {
	if itemID == "" {
		return nil, fmt.Errorf("empty item ID")
	}
	for _, hooks := range [][]CompactionHook{before, after} {
		for _, h := range hooks {
			if h.Supplier == "" || h.Run == nil || (h.FailurePolicy != "fail-open" && h.FailurePolicy != "fail-closed") {
				return nil, fmt.Errorf("invalid hook")
			}
		}
	}
	state := Object{"instructions": instructions, "candidate": nil, "summary": nil, "bodies": Object{}, "messages": []any{}, "denied": false}
	seen := []any{}
	failures := []any{}
	summary := func(staged Object, body string) Object {
		ref := "urn:ahp:compaction:utf8:" + hex.EncodeToString([]byte(body))
		obj(staged["bodies"])[ref] = body
		return Object{"id": itemID, "ref": ref}
	}
	pipeline := func(boundary string, hooks []CompactionHook) bool {
		caps, _ := CompactionCapabilities(boundary, observeOnly && boundary == "after")
		for _, h := range hooks {
			snapshot := obj(clone(state))
			snapshot["boundary"] = boundary
			snapshot["capabilities"] = caps
			seen = append(seen, clone(snapshot))
			effects, err := h.Run(obj(clone(snapshot)))
			if err == nil {
				err = acceptCompactionEffects(snapshot, effects)
			}
			staged := obj(clone(state))
			if err == nil {
				for _, e := range effects {
					if shapeErr := validateEffectShape(e); shapeErr != nil {
						err = fmt.Errorf("invalid effect")
						break
					}
					kind := str(e["type"])
					if kind != "modify" && kind != "message" && !(boundary == "before" && (kind == "return" || kind == "deny")) || (observeOnly && boundary == "after") {
						err = fmt.Errorf("unsupported effect")
						break
					}
					if kind == "modify" {
						target := "summary"
						if boundary == "before" {
							target = "instructions"
						}
						value, ok := e["value"].(string)
						if str(e["target"]) != target || str(e["operation"]) != "replace" || !ok {
							err = fmt.Errorf("invalid modification")
							break
						}
						if boundary == "before" {
							staged["instructions"] = value
						} else {
							staged["summary"] = summary(staged, value)
						}
					} else if kind == "deny" {
						if str(e["reason"]) == "" {
							err = fmt.Errorf("denial requires reason")
							break
						}
					} else if kind == "return" {
						if _, ok := e["value"].(string); !ok {
							err = fmt.Errorf("summary must be text")
							break
						}
					} else if kind == "message" {
						if _, ok := e["text"].(string); !ok {
							err = fmt.Errorf("message must be text")
							break
						}
					}
				}
			}
			if err != nil {
				failures = append(failures, Object{"boundary": boundary, "supplier": h.Supplier})
				if h.FailurePolicy == "fail-closed" && !(observeOnly && boundary == "after") {
					return false
				}
				continue
			}
			if staged["instructions"] != state["instructions"] {
				staged["candidate"] = nil
			}
			for _, e := range effects {
				switch str(e["type"]) {
				case "return":
					staged["candidate"] = Object{"body": e["value"], "supplier": h.Supplier}
				case "deny":
					staged["denied"] = true
				case "message":
					staged["messages"] = append(array(staged["messages"]), e["text"])
				}
			}
			state = staged
			if state["denied"] == true {
				return false
			}
		}
		return true
	}
	generated, applied := false, false
	var provenance any
	if pipeline("before", before) {
		body := ""
		if candidate := obj(state["candidate"]); candidate != nil {
			body = str(candidate["body"])
			provenance = Object{"kind": "supplied", "supplier": candidate["supplier"]}
		} else {
			var err error
			if generate == nil {
				body = "summary:" + str(state["instructions"])
			} else {
				body, err = generate(str(state["instructions"]))
			}
			if err != nil {
				return nil, err
			}
			generated = true
			provenance = Object{"kind": "generated"}
		}
		state["summary"] = summary(state, body)
		if observeOnly {
			applied = true
		} else {
			applied = pipeline("after", after)
		}
	}
	state["seen"] = seen
	state["failures"] = failures
	state["generated"] = generated
	state["applied"] = applied
	state["provenance"] = provenance
	if observeOnly && applied {
		// Detached notifications own their snapshots; no result/diagnostic writes.
		for _, h := range after {
			snapshot := obj(clone(state))
			delete(snapshot, "seen")
			delete(snapshot, "failures")
			snapshot["boundary"] = "after"
			snapshot["capabilities"], _ = CompactionCapabilities("after", true)
			state["seen"] = append(array(state["seen"]), clone(snapshot))
			notify := h.Run
			go func() {
				defer func() { _ = recover() }()
				_, _ = notify(snapshot) // No effect or failure-policy authority.
			}()
		}
	}
	return state, nil
}

// ReceiveBoundary runs a fixture callback behind the public server's canonical
// admission and response acceptance. Authentication and host effects stay with
// the adapter. The in-memory HTTP exchange also serves owned stdio fixtures.
func ReceiveBoundary(ctx context.Context, request Object, callback func(Object) (Object, error)) (Object, error) {
	h, err := server.NewHandler(server.Handlers{Intercept: func(_ context.Context, req ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
		var canonical Object
		raw, err := json.Marshal(req)
		if err != nil {
			return ahp.InterceptResponseResult{}, err
		}
		if err = json.Unmarshal(raw, &canonical); err != nil {
			return ahp.InterceptResponseResult{}, err
		}
		response, err := callback(canonical)
		if err != nil {
			return ahp.InterceptResponseResult{}, err
		}
		var result ahp.InterceptResponseResult
		raw, err = json.Marshal(response["result"])
		if err == nil {
			err = json.Unmarshal(raw, &result)
		}
		return result, err
	}}, server.Options{})
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	output := &boundaryOutput{}
	if err = server.ServeStdio(ctx, io.NopCloser(bytes.NewReader(append(raw, '\n'))), output, h); err != nil {
		return nil, err
	}
	var result Object
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		return nil, err
	}
	if result["error"] != nil {
		return nil, fmt.Errorf("public receiver rejected boundary: %v", result["error"])
	}
	return result, nil
}

// memoryUpload implements the public upload exchange for offline host fixtures.
// It does not bypass client hashing, size bounds, confirmation or projection.
// No resulting reference leaves this isolated boundary.
type memoryUpload struct{}

func (memoryUpload) RoundTrip(req *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(io.LimitReader(req.Body, 4<<20+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 4<<20 {
		return nil, fmt.Errorf("fixture upload limit")
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(raw))
	reply := jsonBytes(Object{"ref": "urn:fixture:" + sum, "size": len(raw), "sha256": sum})
	return &http.Response{StatusCode: 201, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(reply)), Request: req}, nil
}

func acceptCompactionEffects(snapshot Object, effects []Object) error {
	boundary := str(snapshot["boundary"])
	target, body, role := "instructions", str(snapshot["instructions"]), "system"
	if boundary == "after" {
		target = "summary"
		role = "assistant"
		body = str(obj(snapshot["bodies"])[str(obj(snapshot["summary"])["ref"])])
	}
	raw := []byte(body)
	descriptor := Object{"id": "fixture-" + target, "kind": target, "role": role, "mediaType": "text/plain", "selection": "body", "body": Object{"ref": "urn:host:body"}}
	ev := Object{"id": "fixture-" + boundary, "source": "urn:fixture:compaction", "time": "2026-09-15T12:00:00Z", "type": "context.compact." + boundary, target: descriptor}
	if boundary == "before" {
		ev["trigger"] = "manual"
		ev["items"] = []any{}
	} else {
		ev["removed"] = []any{}
		ev["execution"] = Object{"status": "executed"}
		if snapshot["candidate"] != nil {
			ev["execution"] = Object{"status": "skipped", "reason": "supplied_result"}
		}
		ev["parentEventId"] = "fixture-before"
	}
	request := Object{"jsonrpc": "2.0", "id": ev["id"], "method": "hooks/intercept", "params": Object{"protocolVersion": "draft", "event": ev, "capabilities": snapshot["capabilities"]}}
	_, _, err := PublicBoundary(context.Background(), request, func(_ context.Context, _ string, sent []byte) ([]byte, error) {
		var req Object
		if err := json.Unmarshal(sent, &req); err != nil {
			return nil, err
		}
		return jsonBytes(Object{"jsonrpc": "2.0", "id": req["id"], "result": Object{"protocolVersion": "draft", "effects": effects}}), nil
	}, PublicBoundaryOptions{Content: hooks.ContentOptions{Resolver: func(context.Context, string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }}, Upload: Object{"endpoint": "https://fixture.invalid/upload", "timeoutMs": 1000, "maxBytes": 4 << 20}, UploadClient: &http.Client{Transport: memoryUpload{}}})
	return err
}

// boundaryOutput captures the public stdio adapter's single bounded response.
type boundaryOutput struct{ bytes.Buffer }

func (*boundaryOutput) Close() error { return nil }
