package interop

import (
	"encoding/json"
	"fmt"
	"strings"
)

// validateRegistration combines canonical document validation with the real
// discovered host capabilities. Context is trusted local policy input, never a
// claimed remote principal. Credential values are never included in errors.
func validateRegistration(v *Validator, registration, manifest Object, requirements []any, context Object) error {
	encoded, e := json.Marshal(registration)
	if e != nil {
		return e
	}
	if _, e = v.Validate("registration", encoded); e != nil {
		return e
	}
	entries := map[string]Object{}
	for _, raw := range array(manifest["events"]) {
		entry := obj(raw)
		for _, mode := range array(entry["modes"]) {
			entries[str(entry["event"])+"\x00"+str(mode)] = entry
		}
	}
	subscribed := map[string]bool{}
	ids := map[string]bool{}
	policy := obj(manifest["managedPolicy"])
	for _, raw := range array(registration["hooks"]) {
		backend := obj(raw)
		id := str(backend["id"])
		if ids[id] {
			return fmt.Errorf("duplicate backend ID")
		}
		ids[id] = true
		if !has(manifest["transports"], str(obj(backend["transport"])["type"])) {
			return fmt.Errorf("unsupported backend transport")
		}
		if auth := obj(backend["authentication"]); auth != nil {
			kind := str(auth["type"])
			if !has(manifest["authentication"], kind) {
				return fmt.Errorf("unsupported authentication")
			}
			// This context resolves environment credentials only. It cannot invent a
			// credential-reference store, OAuth grant, certificate or workload proof.
			if kind != "bearer" || str(auth["tokenEnv"]) == "" || str(obj(context["environment"])[str(auth["tokenEnv"])]) == "" {
				return fmt.Errorf("unresolved authentication configuration")
			}
		}
		for _, rawSub := range array(backend["subscriptions"]) {
			sub := obj(rawSub)
			scope := str(sub["scope"])
			if scope == "" {
				scope = "user"
			}
			if !has(policy["scopes"], scope) {
				return fmt.Errorf("unsupported policy scope")
			}
			if (scope == "managed" || sub["disableable"] == false) && policy["disableable"] != false {
				return fmt.Errorf("non-disableable policy not enforceable")
			}
			for _, ev := range array(sub["events"]) {
				selector := str(ev)
				mode := str(sub["mode"])
				matched := false
				for key, entry := range entries {
					name := str(entry["event"])
					if key != name+"\x00"+mode {
						continue
					}
					if selector == name || selector == "*" || (strings.HasSuffix(selector, ".*") && strings.HasPrefix(name, strings.TrimSuffix(selector, "*"))) {
						subscribed[key] = true
						matched = true
					}
				}
				if !matched {
					return fmt.Errorf("unsupported event/mode")
				}
			}
			if timeout, ok := sub["timeoutMs"].(float64); ok {
				limits := obj(manifest["limits"])
				if n, ok := limits["minTimeoutMs"].(float64); ok && timeout < n {
					return fmt.Errorf("timeout below host limit")
				}
				if n, ok := limits["maxTimeoutMs"].(float64); ok && timeout > n {
					return fmt.Errorf("timeout above host limit")
				}
			}
		}
	}
	for _, raw := range requirements {
		requirement := obj(raw)
		key := str(requirement["event"]) + "\x00" + str(requirement["mode"])
		entry := entries[key]
		if entry == nil || !subscribed[key] {
			return fmt.Errorf("requirement lacks subscription coverage")
		}
		caps := obj(entry["capabilities"])
		for _, effect := range array(requirement["effects"]) {
			if !has(caps["effects"], str(effect)) {
				return fmt.Errorf("unsupported required effect")
			}
			if effect == "ask" && context["interactive"] != true {
				return fmt.Errorf("interactive confirmation unavailable")
			}
		}
		for target, rawOps := range obj(requirement["modify"]) {
			if !has(caps["effects"], "modify") {
				return fmt.Errorf("modification not enforceable")
			}
			for operation, required := range obj(rawOps) {
				if required == true && obj(obj(caps["modify"])[target])[operation] != true {
					return fmt.Errorf("unsupported modification target/operation")
				}
			}
		}
	}
	return nil
}
