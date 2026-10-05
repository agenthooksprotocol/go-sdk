package interop

import (
	"errors"
	"fmt"
	"reflect"
)

// runObservationChain runs actual serial wire interception; subscriptions after
// settlement are automatically observed, never expanded into fixture decisions.
func runObservationChain(sc lifecycleScenario, send func(Object) (<-chan lifecycleResult, error), control func(string, Object) error, observe func(Object) error, validate func(string, Object) error) (Object, []any, error) {
	original := sc.Requests["a"]
	id := original["id"]
	event := obj(clone(obj(original["params"])["event"]))
	pendingState := obj(clone(obj(original["params"])["state"]))
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
		params["state"] = clone(pendingState)
		delete(params, "subscriptionId") // legacy fixture metadata is not wire identity
		if sub["content"] == "omit" {
			obj(params["event"])["items"] = []any{}
		}
		if err := validate("intercept-request", request); err != nil {
			return nil, nil, err
		}
		called = append(called, sub["id"])
		reply, err := send(request)
		if err != nil {
			return nil, nil, err
		}
		if err = control("/wait", Object{"id": id, "count": len(called)}); err != nil {
			return nil, nil, err
		}
		if sc.Chain["interrupt"] == true {
			if err = control("/mark", Object{"scenario": sc.ID, "kind": "cancelled", "id": id}); err != nil {
				return nil, nil, err
			}
			pending = reply
			halted = true
			continue
		}
		if err = control("/release", Object{"id": id}); err != nil {
			return nil, nil, err
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
			// Carry the accepted protocol prefix, not the template state or
			// Apply's final host decision (which may reflect native policy).
			permission := str(pendingState["permission"])
			if !reflect.DeepEqual(obj(event["tool"])["input"], state["input"]) {
				pendingState["candidate"] = nil
				if permission == "allow" {
					permission = "none"
				}
			}
			for _, raw := range array(obj(result.response["result"])["effects"]) {
				effect := obj(raw)
				switch effect["type"] {
				case "deny":
					permission = "deny"
				case "ask":
					if permission != "deny" {
						permission = "ask"
					}
				case "allow":
					if permission == "none" {
						permission = "allow"
					}
				case "return":
					pendingState["candidate"] = Object{"value": clone(effect["value"])}
				}
			}
			pendingState["permission"] = permission
			obj(event["tool"])["input"] = clone(state["input"])
			halted = state["decision"] == "deny" || state["flow"] == "stop"
		}
	}
	if err := control("/mark", Object{"scenario": sc.ID, "kind": "chain-settled", "id": id}); err != nil {
		return nil, nil, err
	}
	type observationDelivery struct {
		eventID      any
		subscription any
		done         <-chan error
	}
	deliveries := make([]observationDelivery, 0, len(remaining))
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
			return nil, nil, err
		}
		observed = append(observed, sub["id"])
		done := make(chan error, 1)
		deliveries = append(deliveries, observationDelivery{eventID: projected["id"], subscription: sub["id"], done: done})
		go func() { done <- observe(note) }()
	}
	// Only the test controller drains; execution has already settled or stopped.
	if pending != nil {
		if err := control("/release", Object{"id": id}); err != nil {
			return nil, nil, err
		}
		<-pending
	}
	if len(remaining) > 0 {
		if err := control("/wait-observed", Object{"eventId": event["id"], "count": len(remaining)}); err != nil {
			return nil, nil, err
		}
	}
	if sc.Chain["holdObservers"] == true {
		if err := control("/release", Object{"id": str(id) + ":observers"}); err != nil {
			return nil, nil, err
		}
	}
	diagnostics := []any{}
	// Drain in subscription order, independent of asynchronous completion order.
	// Rejected acknowledgements are delivery evidence, never new decisions.
	for _, delivery := range deliveries {
		if err := <-delivery.done; err != nil {
			var acknowledgement *lifecycleObservationAcknowledgementError
			if !errors.As(err, &acknowledgement) {
				return nil, nil, fmt.Errorf("observation test drain: %w", err)
			}
			diagnostics = append(diagnostics, Object{"eventId": delivery.eventID, "subscription": delivery.subscription, "kind": "invalid-observation-acknowledgement", "status": acknowledgement.Status, "response": clone(acknowledgement.Response)})
		}
	}
	return Object{"called": called, "failures": failures, "observations": observed, "input": obj(event["tool"])["input"]}, diagnostics, nil
}
