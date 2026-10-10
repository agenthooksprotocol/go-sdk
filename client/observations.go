package client

import (
	"context"
	"errors"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
	"sync"
)

// Observations retains completed best-effort delivery outcomes for compatibility.
// Boundary calls own and finish all deliveries before returning. Hosts may run the
// entire boundary call in their own goroutine; settlement never authorizes early execution.
type Observations struct {
	done   chan struct{}
	cancel context.CancelFunc
	mu     sync.Mutex
	errors []DeliveryError
}

func (o *Observations) Done() <-chan struct{} { return o.done }
func (o *Observations) Cancel()               { o.cancel() }
func (o *Observations) Wait(ctx context.Context) ([]DeliveryError, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-o.done:
		o.mu.Lock()
		defer o.mu.Unlock()
		return append([]DeliveryError(nil), o.errors...), nil
	}
}

type observationDelivery struct {
	backend registeredBackend
	sub     map[string]any
	index   int
}

func (c *Hooks) scheduleObservations(parent context.Context, event map[string]any, pending []observationDelivery, prepared ...*preparedBoundary) *Observations {
	ctx, cancel := context.WithCancel(parent)
	if len(prepared) > 0 && prepared[0] != nil {
		ctx = context.WithValue(ctx, preparedContextKey{}, prepared[0])
	}
	o := &Observations{done: make(chan struct{}), cancel: cancel}
	var wg sync.WaitGroup
	for _, delivery := range pending {
		// Interruption retires owned work, never starts best-effort follow-up.
		if ctx.Err() != nil {
			break
		}
		select {
		case c.observations <- struct{}{}:
		default:
			o.mu.Lock()
			o.errors = append(o.errors, DeliveryError{BackendID: delivery.backend.id, Subscription: delivery.index, Stage: "admission", Code: DeliveryCapacity, Err: errors.New("observation capacity exceeded")})
			o.mu.Unlock()
			continue
		}
		snapshot, _ := sdkMap(event)
		wg.Add(1)
		go func(d observationDelivery) {
			defer wg.Done()
			defer func() { <-c.observations }()
			task, done := context.WithTimeout(ctx, c.opts.ObservationTimeout)
			defer done()
			if task.Err() != nil {
				return
			}
			task = context.WithValue(task, uploadReceiverContextKey{}, uploadReceiver{d.backend.id, d.index})
			var err error
			if plan, _ := task.Value(uploadPlanContextKey{}).(*uploadPlan); plan != nil {
				err = plan.failure(uploadReceiver{d.backend.id, d.index})
			}
			stage := "prepare"
			var projected map[string]any
			if err == nil {
				projected, err = c.projectContent(task, snapshot, d.sub, d.backend.id)
			}
			if err == nil {
				stage = "observation"
				note := sdkJSON(map[string]any{"jsonrpc": "2.0", "method": "hooks/observe", "params": map[string]any{"protocolVersion": "draft", "event": projected}})
				if canonical.Validate("observe-notification", note) != nil || !ahp.ParseObserveNotification(note).OK {
					err = errors.New("invalid projected observation")
				} else {
					_, err = d.backend.transport.Exchange(task, note, true)
				}
			}
			if err != nil {
				o.mu.Lock()
				o.errors = append(o.errors, DeliveryError{BackendID: d.backend.id, Subscription: d.index, Stage: stage, Code: deliveryCode(stage, err), Err: err})
				o.mu.Unlock()
			}
		}(delivery)
	}
	wg.Wait()
	cancel()
	// Completed handles must not retain the delivery context and its source store.
	o.cancel = func() {}
	close(o.done)
	return o
}
