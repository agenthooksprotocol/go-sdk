package interop

import "fmt"

// runObservationChain runs actual serial wire interception; subscriptions after
// settlement are automatically observed, never expanded into fixture decisions.
func runObservationChain(sc lifecycleScenario, send func(Object) (<-chan lifecycleResult, error), control func(string, Object) error, observe func(Object) error, validate func(string, Object) error) (Object, error) {
	original := sc.Requests["a"]
	id := original["id"]
	event := obj(clone(obj(original["params"])["event"]))
	called, failures, remaining := []any{}, []any{}, []Object{}
	halted := false
	var pending <-chan lifecycleResult
	for _, raw := range array(sc.Chain["subscriptions"]) {
		sub := obj(raw)
		if sub["mode"] == "observe" || halted {
			remaining = append(remaining, sub)
			continue
		}
		request := obj(clone(original))
		params := obj(request["params"])
		params["event"] = clone(event)
		delete(params, "subscriptionId") // legacy fixture metadata is not wire identity
		if sub["content"] == "omit" {
			obj(params["event"])["items"] = []any{}
		}
		if err := validate("intercept-request", request); err != nil {
			return nil, err
		}
		called = append(called, sub["id"])
		reply, err := send(request)
		if err != nil {
			return nil, err
		}
		if err = control("/wait", Object{"id": id, "count": len(called)}); err != nil {
			return nil, err
		}
		if sc.Chain["interrupt"] == true {
			if err = control("/mark", Object{"scenario": sc.ID, "kind": "cancelled", "id": id}); err != nil {
				return nil, err
			}
			pending = reply
			halted = true
			continue
		}
		if err = control("/release", Object{"id": id}); err != nil {
			return nil, err
		}
		result := <-reply
		var state Object
		if result.err == nil {
			state, err = Apply(request, result.response)
		} else {
			err = result.err
		}
		if err != nil {
			failures = append(failures, sub["id"])
			halted = sub["failurePolicy"] == "fail-closed"
		} else {
			obj(event["tool"])["input"] = clone(state["input"])
			halted = state["decision"] == "deny" || state["flow"] == "stop"
		}
	}
	if err := control("/mark", Object{"scenario": sc.ID, "kind": "chain-settled", "id": id}); err != nil {
		return nil, err
	}
	deliveries := make(chan error, len(remaining))
	observed := []any{}
	for _, sub := range remaining {
		projected := obj(clone(event))
		if sub["content"] == "omit" {
			projected["items"] = []any{}
		} else {
			for _, raw := range array(projected["items"]) {
				item := obj(raw)
				delete(item, "body")
				delete(item, "gap")
				item["selection"] = "metadata"
			}
		}
		note := Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": projected}}
		if err := validate("observe", note); err != nil {
			return nil, err
		}
		observed = append(observed, sub["id"])
		go func() { deliveries <- observe(note) }()
	}
	// Only the test controller drains; execution has already settled or stopped.
	if pending != nil {
		if err := control("/release", Object{"id": id}); err != nil {
			return nil, err
		}
		<-pending
	}
	if len(remaining) > 0 {
		if err := control("/wait-observed", Object{"eventId": event["id"], "count": len(remaining)}); err != nil {
			return nil, err
		}
	}
	if sc.Chain["holdObservers"] == true {
		if err := control("/release", Object{"id": str(id) + ":observers"}); err != nil {
			return nil, err
		}
	}
	for range remaining {
		if err := <-deliveries; err != nil {
			return nil, fmt.Errorf("observation test drain: %w", err)
		}
	}
	return Object{"called": called, "failures": failures, "observations": observed, "input": obj(event["tool"])["input"]}, nil
}
