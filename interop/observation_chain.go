package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
	hooks "github.com/agenthooksprotocol/go-sdk/client"
)

type chainRoundTripper func(*http.Request) (*http.Response, error)

func (f chainRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// runObservationChain runs ONE ordinary SDK operation. The adapter owns only
// receiver barriers, native transport plumbing and evidence from actual calls;
// the SDK owns serial interception, acceptance, failure policy and observations.
func runObservationChain(parent context.Context, sc lifecycleScenario, send func(context.Context, Object) (<-chan lifecycleResult, error), control func(string, Object) error, observe func(context.Context, Object) error, validate func(string, Object) error) (Object, []any, error) {
	original := sc.Requests["a"]
	params := obj(original["params"])
	event := obj(params["event"])
	id := original["id"]
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var mu sync.Mutex
	called := []any{}
	invoked := map[string]bool{}
	notified := map[string]bool{}
	observationErrors := map[string]error{}
	var adapterError error
	recordError := func(err error) {
		if err != nil {
			mu.Lock()
			adapterError = errors.Join(adapterError, err)
			mu.Unlock()
		}
	}
	subscriptions := []Object{}
	backendSubs := map[string][]Object{}
	backendOrder := []string{}
	for index, raw := range array(sc.Chain["subscriptions"]) {
		sub := obj(clone(raw))
		backend := str(sub["backend"])
		if backend == "" {
			backend = strconv.Itoa(index)
		}
		if _, exists := backendSubs[backend]; !exists {
			backendOrder = append(backendOrder, backend)
		}
		backendSubs[backend] = append(backendSubs[backend], sub)
		subscriptions = append(subscriptions, sub)
	}
	settled := make(chan struct{})
	var settleOnce sync.Once
	markSettled := func() {
		settleOnce.Do(func() {
			recordError(control("/mark", Object{"scenario": sc.ID, "kind": "chain-settled", "id": id}))
			close(settled)
		})
	}
	// Holding observer acknowledgements is test-controller work, not SDK-owned
	// delivery. The controller is scoped and joined before this adapter returns.
	controllerDone := make(chan error, 1)
	if sc.Chain["holdObservers"] == true {
		go func() {
			<-settled
			mu.Lock()
			count := len(subscriptions) - len(called)
			mu.Unlock()
			var err error
			if ctx.Err() == nil && count > 0 {
				err = control("/wait-observed", Object{"eventId": event["id"], "count": count})
			}
			releaseErr := control("/release", Object{"id": str(id) + ":observers"})
			controllerDone <- errors.Join(err, releaseErr)
		}()
	} else {
		controllerDone <- nil
	}
	// Always release the controller even if configuration fails before dispatch.
	defer func() { markSettled(); <-controllerDone }()
	backendIDs := map[string][]Object{}
	registrationBackends := []any{}
	endpointBackends := map[string][]Object{}
	for index, backend := range backendOrder {
		backendID := fmt.Sprintf("org.ahp.chain.b%d", index)
		endpoint := "http://127.0.0.1/chain/" + strconv.Itoa(index)
		backendIDs[backendID] = backendSubs[backend]
		endpointBackends[endpoint] = backendSubs[backend]
		registered := []any{}
		for _, sub := range backendSubs[backend] {
			mode := str(sub["mode"])
			selection := str(sub["content"])
			if selection == "" {
				selection = "metadata"
			}
			entry := Object{"id": sub["id"], "events": []any{event["type"]}, "mode": mode, "content": Object{"default": selection}, "includeNative": true}
			if mode == "intercept" {
				entry["timeoutMs"] = 20000
				policy := str(sub["failurePolicy"])
				if policy == "" {
					policy = "fail-open"
				}
				entry["failurePolicy"] = policy
			}
			registered = append(registered, entry)
		}
		registrationBackends = append(registrationBackends, Object{"id": backendID, "transport": Object{"type": "http", "url": endpoint}, "subscriptions": registered})
	}
	transport := chainRoundTripper(func(request *http.Request) (*http.Response, error) {
		if err := request.Context().Err(); err != nil {
			return nil, err
		}
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			recordError(err)
			return nil, err
		}
		var envelope Object
		if err = json.Unmarshal(raw, &envelope); err != nil {
			recordError(err)
			return nil, err
		}
		note := envelope["method"] == "hooks/observe"
		mu.Lock()
		var selected Object
		for _, sub := range endpointBackends[request.URL.String()] {
			key := str(sub["id"])
			if invoked[key] || notified[key] || (!note && sub["mode"] != "intercept") {
				continue
			}
			selected = sub
			break
		}
		if selected == nil {
			mu.Unlock()
			err := errors.New("SDK delivered an unselected chain subscription")
			recordError(err)
			return nil, err
		}
		key := str(selected["id"])
		if note {
			notified[key] = true
		} else {
			invoked[key] = true
			called = append(called, selected["id"])
		}
		count := len(called)
		mu.Unlock()
		// The fixture host chooses to omit the collection entirely for an omit
		// route. This only narrows the SDK's receiver view; it never alters state.
		if selected["content"] == "omit" {
			obj(obj(envelope["params"])["event"])["items"] = []any{}
		}
		kind := "intercept-request"
		if note {
			kind = "observe"
		}
		if err = validate(kind, envelope); err != nil {
			recordError(err)
			return nil, err
		}
		if note {
			markSettled()
			mu.Lock()
			barrierErr := adapterError
			mu.Unlock()
			if barrierErr != nil {
				return nil, barrierErr
			}
			err = observe(request.Context(), envelope)
			mu.Lock()
			observationErrors[key] = err
			mu.Unlock()
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil)), Request: request}, nil
		}
		pending, err := send(request.Context(), envelope)
		if err != nil {
			recordError(err)
			return nil, err
		}
		if err = control("/wait", Object{"id": id, "count": count}); err != nil {
			recordError(err)
			cancel()
			<-pending
			return nil, err
		}
		if sc.Chain["interrupt"] == true {
			if err = control("/mark", Object{"scenario": sc.ID, "kind": "cancelled", "id": id}); err != nil {
				recordError(err)
			}
			cancel()  // Actual operation cancellation, not just a report marker.
			<-pending // Join cancellation/retirement, never normal receiver processing.
			return nil, request.Context().Err()
		}
		if err = control("/release", Object{"id": id}); err != nil {
			recordError(err)
			cancel()
		}
		reply := <-pending // Join/retire the real wire attempt; never detach a late reply.
		if request.Context().Err() != nil {
			return nil, request.Context().Err()
		}
		if reply.err != nil {
			return nil, reply.err
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(jsonBytes(reply.response))), Request: request}, nil
	})
	registration := ahp.ParseRegistration(jsonBytes(Object{"protocolVersion": "draft", "hooks": registrationBackends}))
	if !registration.OK {
		return nil, nil, fmt.Errorf("chain registration: %v", registration.Diagnostics)
	}
	var capabilities ahp.Capabilities
	if err := json.Unmarshal(jsonBytes(params["capabilities"]), &capabilities); err != nil {
		return nil, nil, err
	}
	client, err := hooks.New(registration.Value, hooks.Options{Source: str(event["source"]), Events: map[string]hooks.EventCapabilities{str(event["type"]): {Modes: []hooks.Mode{hooks.Intercept, hooks.Observe}, Capabilities: &capabilities}}, EventClient: &http.Client{Transport: transport}, ObservationTimeout: 20 * time.Second, Content: hooks.ContentOptions{ProjectOpaque: func(_ context.Context, _ hooks.ContentAuthorization, _ string, value any) (any, error) {
		return value, nil
	}}})
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()
	options := []hooks.InterceptOption{}
	if initial, exists := params["state"]; exists {
		var typed ahp.InterceptRequestParamsState
		if err = json.Unmarshal(jsonBytes(initial), &typed); err != nil {
			return nil, nil, err
		}
		options = append(options, hooks.WithInitialState(typed))
	}
	result, callErr := dispatchPublicBoundary(ctx, client, str(event["type"]), event, options)
	markSettled()
	if result != nil && result.Interrupted && len(called) > 0 {
		// The operation has already returned its interrupted prefix. Releasing
		// a late test response is controller cleanup, not ordinary call work.
		recordError(control("/release", Object{"id": id}))
	}
	// Join the optional controller and preserve its error without double draining.
	controllerErr := <-controllerDone
	controllerDone <- nil
	recordError(controllerErr)
	mu.Lock()
	fatal := adapterError
	mu.Unlock()
	if fatal != nil {
		return nil, nil, fatal
	}
	if callErr != nil && !(result != nil && result.Interrupted && errors.Is(callErr, context.Canceled)) {
		return nil, nil, callErr
	}
	if result == nil {
		return nil, nil, errors.New("chain returned no SDK result")
	}
	if sc.Chain["interrupt"] == true && !result.Interrupted {
		return nil, nil, errors.New("chain cancellation did not interrupt SDK operation")
	}
	failures := []any{}
	for _, failure := range result.Errors {
		if result.Interrupted && errors.Is(failure.Err, context.Canceled) {
			continue
		}
		group := backendIDs[failure.BackendID]
		if failure.Subscription < 0 || failure.Subscription >= len(group) {
			return nil, nil, errors.New("unknown SDK failure attribution")
		}
		failures = append(failures, group[failure.Subscription]["id"])
	}
	observed, diagnostics := []any{}, []any{}
	// Stable registration-order reporting is derived only from actual attempted
	// notifications, independent of concurrent completion order.
	for _, sub := range subscriptions {
		key := str(sub["id"])
		if !notified[key] {
			continue
		}
		observed = append(observed, sub["id"])
		if err := observationErrors[key]; err != nil {
			var acknowledgement *lifecycleObservationAcknowledgementError
			if !errors.As(err, &acknowledgement) {
				return nil, nil, fmt.Errorf("observation test drain: %w", err)
			}
			diagnostics = append(diagnostics, Object{"eventId": event["id"], "subscription": sub["id"], "kind": "invalid-observation-acknowledgement", "status": acknowledgement.Status, "response": clone(acknowledgement.Response)})
		}
	}
	if len(observed) > 0 {
		if err := control("/wait-observed", Object{"eventId": event["id"], "count": len(observed)}); err != nil {
			return nil, nil, err
		}
	}
	var effective any
	if err = json.Unmarshal(result.EffectiveInput, &effective); err != nil {
		return nil, nil, err
	}
	return Object{"called": called, "failures": failures, "observations": observed, "input": effective}, diagnostics, nil
}
