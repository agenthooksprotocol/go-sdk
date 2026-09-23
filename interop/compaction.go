package interop

import (
	"encoding/hex"
	"fmt"
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
// immutable UTF-8 content; upload them before exposing their references on wire.
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
