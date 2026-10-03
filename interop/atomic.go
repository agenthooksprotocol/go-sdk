package interop

import (
	"fmt"
	"math"
	"reflect"
)

// Apply stages a whole response in private memory, committing no partial state
// on structural, capability, input-contract, or flow-admission failure.
func Apply(request, response Object) (Object, error) {
	if !reflect.DeepEqual(request["id"], response["id"]) {
		return nil, fmt.Errorf("response correlation mismatch")
	}
	p := obj(request["params"])
	caps := obj(p["capabilities"])
	event := obj(p["event"])
	input := obj(clone(obj(event["tool"])["input"]))
	if input == nil {
		input = Object{}
	}
	initial := clone(input)
	state := obj(p["state"])
	permission := str(state["permission"])
	candidate := clone(state["candidate"])
	messages := []any{}
	// State is the already accepted prefix of this boundary's serial pipeline.
	// Clone queues so a rejected later response cannot mutate that prefix.
	injections := append([]any{}, array(clone(state["injections"]))...)
	priorFlow := str(state["flow"])
	if priorFlow == "none" {
		priorFlow = ""
	}
	if priorFlow != "" && priorFlow != "stop" && priorFlow != "continue" {
		return nil, fmt.Errorf("unknown prior flow")
	}
	flow := priorFlow
	continuationInstructions := append([]any{}, array(clone(state["instructions"]))...)
	effects, ok := obj(response["result"])["effects"].([]any)
	if !ok {
		return nil, fmt.Errorf("effects must be an array")
	}
	// Capability-check all effects before applying any.
	for _, raw := range effects {
		e := obj(raw)
		if err := validateEffectShape(e); err != nil {
			return nil, fmt.Errorf("invalid effect")
		}
		typ := str(e["type"])
		if !has(caps["effects"], typ) {
			return nil, fmt.Errorf("unadvertised effect %s", typ)
		}
		switch typ {
		case "allow", "ask":
		case "deny":
			if str(e["reason"]) == "" {
				return nil, fmt.Errorf("deny requires reason")
			}
		case "return":
			if event["type"] != "tool.before" {
				return nil, fmt.Errorf("synthetic host cannot return at this boundary")
			}
			if _, ok := e["value"]; !ok {
				return nil, fmt.Errorf("return requires value")
			}
		case "message":
			if _, ok := e["text"].(string); !ok {
				return nil, fmt.Errorf("message requires text")
			}
		case "modify":
			if obj(event["tool"]) == nil || obj(event["tool"])["input"] == nil {
				return nil, fmt.Errorf("synthetic host cannot modify input at this boundary")
			}
			if e["target"] != "input" || (e["operation"] != "replace" && e["operation"] != "merge") || obj(obj(caps["modify"])["input"])[str(e["operation"])] != true {
				return nil, fmt.Errorf("unsupported modify")
			}
		case "flow":
			f := obj(caps["flow"])
			op := str(e["operation"])
			if !has(f["operations"], op) || (op != "stop" && op != "continue") {
				return nil, fmt.Errorf("unsupported flow")
			}
			if op == "stop" && str(e["reason"]) == "" {
				return nil, fmt.Errorf("stop requires reason")
			}
			if op == "continue" {
				if instruction, present := e["instruction"]; present && str(instruction) == "" {
					return nil, fmt.Errorf("invalid continuation instruction")
				}
				n, ok := f["remainingContinuations"].(float64)
				if !ok || math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n || n < 0 || (n == 0 && priorFlow != "continue") {
					return nil, fmt.Errorf("continuation allowance exhausted")
				}
			}
		case "inject":
			if _, ok := e["value"]; !ok {
				return nil, fmt.Errorf("inject requires value")
			}
			if e["deliverAt"] != "now" && e["deliverAt"] != "next_turn" {
				return nil, fmt.Errorf("unsupported injection delivery")
			}
			if c := obj(obj(caps["inject"])["context"]); c == nil || c["append"] != true || e["target"] != "context" || e["operation"] != "append" || !has(c["deliverAt"], str(e["deliverAt"])) {
				return nil, fmt.Errorf("unadvertised injection delivery")
			}
		default:
			return nil, fmt.Errorf("unsupported effect %s", typ)
		}
	}
	for _, raw := range effects {
		e := obj(raw)
		if e["type"] != "modify" {
			continue
		}
		v := obj(clone(e["value"]))
		if v == nil {
			return nil, fmt.Errorf("input must be object")
		}
		if e["operation"] == "replace" {
			input = v
		} else {
			for k, x := range v {
				input[k] = x
			}
		}
		// The shared synthetic complete_task tool requires a positive integral task.
		if _, present := obj(initial)["task"]; present {
			n, ok := input["task"].(float64)
			if !ok || n <= 0 || math.Trunc(n) != n {
				return nil, fmt.Errorf("invalid effective tool input")
			}
		}
	}
	if !reflect.DeepEqual(initial, input) {
		candidate = nil
		if permission == "allow" {
			permission = "none"
		}
	}
	// "none" means use this synthetic host's native policy, not hook approval.
	// A relevant rewrite already invalidated stale prompt suppression above.
	native := str(state["nativePermission"])
	if native != "" && native != "allow" && native != "ask" && native != "deny" {
		return nil, fmt.Errorf("unknown native permission")
	}
	denied := permission == "deny" || native == "deny"
	for _, raw := range effects {
		e := obj(raw)
		switch e["type"] {
		case "deny":
			denied = true
		case "ask":
			permission = "ask"
		case "allow":
			if permission != "ask" {
				permission = "allow"
			}
		case "return":
			candidate = Object{"value": clone(e["value"])}
		case "message":
			t, ok := e["text"].(string)
			if !ok {
				return nil, fmt.Errorf("invalid message")
			}
			messages = append(messages, t)
		case "flow":
			if e["operation"] == "continue" && e["instruction"] != nil {
				continuationInstructions = append(continuationInstructions, clone(e["instruction"]))
			}
			if e["operation"] == "stop" || flow != "stop" {
				flow = str(e["operation"])
			}
		case "inject":
			injections = append(injections, clone(e))
		}
	}
	if permission == "none" || permission == "" {
		permission = native
	}
	decision := "allow"
	if permission == "ask" {
		decision = "ask"
	}
	if denied {
		decision = "deny"
		candidate = nil
	}
	result := Object{"decision": decision, "executed": decision == "allow" && candidate == nil && flow != "stop" && event["type"] == "tool.before", "input": input, "messages": messages}
	if candidate != nil && decision == "allow" && flow != "stop" {
		result["result"] = obj(candidate)["value"]
	}
	if flow != "" {
		result["flow"] = flow
	}
	if flow != "" {
		if _, budgeted := obj(caps["flow"])["remainingContinuations"]; budgeted || len(continuationInstructions) > 0 || flow == "continue" {
			result["continuationInstructions"] = continuationInstructions
		}
		if n, ok := obj(caps["flow"])["remainingContinuations"].(float64); ok {
			if flow == "continue" && priorFlow != "continue" {
				n--
			}
			result["continuationRemaining"] = n
		}
	}
	if len(continuationInstructions) > 0 || state["instructions"] != nil {
		result["continuationInstructions"] = continuationInstructions
	}
	if len(injections) > 0 || state["injections"] != nil {
		result["injections"] = injections
	}
	return result, nil
}
