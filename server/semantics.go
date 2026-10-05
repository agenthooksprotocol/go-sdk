package server

import (
	"bytes"
	"encoding/json"
	"math/big"
	"reflect"
)

func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func array(v any) []any           { a, _ := v.([]any); return a }
func contains(v any, want any) bool {
	for _, value := range array(v) {
		if reflect.DeepEqual(value, want) {
			return true
		}
	}
	return false
}
func document(b []byte) map[string]any {
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	_ = d.Decode(&m)
	return m
}
func natural(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	value, valid := new(big.Rat).SetString(string(n))
	if !valid || !value.IsInt() || !value.Num().IsInt64() {
		return 0, false
	}
	i := value.Num().Int64()
	return i, i >= 0
}

// These checks supplement canonical JSON Schema with cross-field constraints.
// They never apply effects or decide host execution policy.
func validInterceptContext(b []byte) bool {
	req := document(b)
	params := object(req["params"])
	event := object(params["event"])
	if !reflect.DeepEqual(req["id"], event["id"]) {
		return false
	}
	flow := object(object(params["capabilities"])["flow"])
	if contains(flow["operations"], "continue") {
		remaining, rOK := natural(flow["remainingContinuations"])
		count, cOK := natural(flow["continuationCount"])
		if !rOK || !cOK {
			return false
		}
		if max, exists := flow["maxContinuations"]; exists {
			maximum, ok := natural(max)
			if !ok || count > maximum || remaining > maximum-count {
				return false
			}
		}
	}
	return true
}
func validEffects(request, response []byte) bool {
	p := object(document(request)["params"])
	caps := object(p["capabilities"])
	event := object(p["event"])
	// A content descriptor is not its resolved application value. This stateless
	// receiver can check inline input and replacements staged within this reply;
	// only the host client has the verified body store for descriptor-backed bases.
	values := make(map[string]any)
	if input, present := object(event["tool"])["input"]; present {
		values["input"] = input
	}
	for _, raw := range array(object(document(response)["result"])["effects"]) {
		e := object(raw)
		typ := e["type"]
		if !contains(caps["effects"], typ) {
			return false
		}
		switch typ {
		case "modify":
			target, _ := e["target"].(string)
			operation, _ := e["operation"].(string)
			if object(object(caps["modify"])[target])[operation] != true {
				return false
			}
			value := e["value"]
			if operation == "merge" {
				base, known := values[target]
				current := object(base)
				patch := object(value)
				if patch == nil || (known && current == nil) {
					return false
				}
				if !known {
					// Capability admission and patch shape are checkable here; decoding and
					// validating the actual base remains atomic host-client acceptance.
					continue
				}
				merged := make(map[string]any, len(current)+len(patch))
				for k, v := range current {
					merged[k] = v
				}
				for k, v := range patch {
					merged[k] = v
				}
				value = merged
			} else if target == "input" && object(value) == nil {
				return false
			}
			values[target] = value
		case "flow":
			flow := object(caps["flow"])
			if !contains(flow["operations"], e["operation"]) {
				return false
			}
			if e["operation"] == "continue" {
				remaining, ok := natural(flow["remainingContinuations"])
				if !ok || remaining < 1 {
					return false
				}
			}
		case "inject":
			allowed := object(object(caps["inject"])["context"])
			if e["target"] != "context" || e["operation"] != "append" || allowed["append"] != true || !contains(allowed["deliverAt"], e["deliverAt"]) {
				return false
			}
		}
	}
	return true
}
