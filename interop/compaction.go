package interop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	ahp "github.com/agenthooksprotocol/go-sdk"
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
// inline text parts; no upload or reference cache is needed.
// Observe-only after callbacks run on detached goroutines after settlement; their
// results, errors and panics cannot change settlement or delay downstream use.
func RunCompaction(instructions, itemID string, before, after []CompactionHook, generate func(string) (string, error), observeOnly bool) (Object, error) {
	return RunCompactionParts(textParts(instructions), itemID, before, after, generate, observeOnly)
}

// RunCompactionParts retains the ordered canonical instruction parts, including
// their identities. Generation consumes their effective text in part order.
func RunCompactionParts(instructions []any, itemID string, before, after []CompactionHook, generate func(string) (string, error), observeOnly bool) (Object, error) {
	if !validTextParts(instructions) {
		return nil, fmt.Errorf("invalid inline instructions")
	}

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
	state := Object{"instructions": clone(instructions), "candidate": nil, "summary": nil, "messages": []any{}, "denied": false}
	seen := []any{}
	failures := []any{}
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
						value := e["value"]
						ok := validTextParts(value)
						if str(e["target"]) != target || str(e["operation"]) != "replace" || !ok {
							err = fmt.Errorf("invalid modification")
							break
						}
						if boundary == "before" {
							staged["instructions"] = clone(value)
						} else {
							staged["summary"] = clone(value)
						}
					} else if kind == "deny" {
						if str(e["reason"]) == "" {
							err = fmt.Errorf("denial requires reason")
							break
						}
					} else if kind == "return" {
						if !validTextParts(e["value"]) {
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
			if partsText(staged["instructions"]) != partsText(state["instructions"]) {
				staged["candidate"] = nil
			}
			for _, e := range effects {
				switch str(e["type"]) {
				case "return":
					staged["candidate"] = Object{"body": clone(e["value"]), "supplier": h.Supplier}
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
			body = partsText(candidate["body"])
			provenance = Object{"kind": "supplied", "supplier": candidate["supplier"]}
		} else {
			var err error
			if generate == nil {
				body = "summary:" + partsText(state["instructions"])
			} else {
				body, err = generate(partsText(state["instructions"]))
			}
			if err != nil {
				return nil, err
			}
			generated = true
			provenance = Object{"kind": "generated"}
		}
		state["summary"] = textParts(body)
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
	target := "instructions"
	if boundary == "after" {
		target = "summary"
	}
	ev := Object{"id": "fixture-" + boundary, "source": "urn:fixture:compaction", "time": "2026-09-15T12:00:00Z", "type": "context.compact." + boundary, target: clone(snapshot[target])}
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
	})
	return err
}

// boundaryOutput captures the public stdio adapter's single bounded response.
type boundaryOutput struct{ bytes.Buffer }

func (*boundaryOutput) Close() error { return nil }

// textParts keeps host convenience strings at the canonical inline boundary.
func textParts(text string) []any {
	return []any{Object{"id": "text", "kind": "text", "mediaType": "text/plain", "selection": "body", "text": text}}
}
func validTextParts(value any) bool {
	parts, ok := value.([]any)
	if !ok {
		return false
	}
	for _, part := range parts {
		p := obj(part)
		if p["kind"] != "text" || p["selection"] != "body" || p["mediaType"] != "text/plain" || str(p["id"]) == "" {
			return false
		}
		for _, key := range []string{"body", "ref", "size", "sha256"} {
			if _, exists := p[key]; exists {
				return false
			}
		}
		if _, ok := p["text"].(string); !ok {
			return false
		}
	}
	return true
}
func partsText(value any) string {
	var result string
	for _, part := range array(value) {
		result += str(obj(part)["text"])
	}
	return result
}

func contextMessages(text string) []any {
	return []any{Object{"id": "context", "role": "system", "parts": textParts(text)}}
}
