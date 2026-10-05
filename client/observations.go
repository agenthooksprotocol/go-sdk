package client

import (
	"context"
	"errors"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
	"sync"
)

// Observations tracks best-effort deliveries without delaying boundary settlement.
// Wait does not cancel delivery when its own context expires. Use Cancel explicitly.
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

func (c *Client) scheduleObservations(event map[string]any, pending []observationDelivery, prepared ...*preparedBoundary) *Observations {
	ctx, cancel := context.WithCancel(c.life)
	if len(prepared) > 0 && prepared[0] != nil {
		ctx = context.WithValue(ctx, preparedContextKey{}, prepared[0])
	}
	o := &Observations{done: make(chan struct{}), cancel: cancel}
	var wg sync.WaitGroup
	for _, delivery := range pending {
		select {
		case c.observations <- struct{}{}:
		default:
			o.mu.Lock()
			o.errors = append(o.errors, DeliveryError{BackendID: delivery.backend.id, Subscription: delivery.index, Stage: "admission", Err: errors.New("observation capacity exceeded")})
			o.mu.Unlock()
			continue
		}
		snapshot, _ := sdkMap(event)
		wg.Add(1)
		c.active.Add(1)
		go func(d observationDelivery) {
			defer wg.Done()
			defer c.active.Done()
			defer func() { <-c.observations }()
			task, done := context.WithTimeout(ctx, c.opts.ObservationTimeout)
			defer done()
			projected, err := c.projectContent(task, snapshot, d.sub, d.backend.id)
			if err == nil {
				note := sdkJSON(map[string]any{"jsonrpc": "2.0", "method": "hooks/observe", "params": map[string]any{"protocolVersion": "draft", "event": projected}})
				if canonical.Validate("observe-notification", note) != nil || !ahp.ParseObserveNotification(note).OK {
					err = errors.New("invalid projected observation")
				} else {
					_, err = d.backend.transport.Exchange(task, note, true)
				}
			}
			if err != nil {
				o.mu.Lock()
				o.errors = append(o.errors, DeliveryError{BackendID: d.backend.id, Subscription: d.index, Stage: "observation", Err: err})
				o.mu.Unlock()
			}
		}(delivery)
	}
	go func() { wg.Wait(); cancel(); close(o.done) }()
	return o
}
