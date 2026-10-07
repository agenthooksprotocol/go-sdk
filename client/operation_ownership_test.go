package client

import (
	"context"
	"errors"
	"github.com/agenthooksprotocol/go-sdk/content"
	"strings"
	"sync"
	"testing"
	"time"
)

type ownedDeliveryTransport struct {
	started  chan struct{}
	release  chan struct{}
	finished chan struct{}
	once     sync.Once
}

func (t *ownedDeliveryTransport) Exchange(ctx context.Context, _ []byte, _ bool) ([]byte, error) {
	t.once.Do(func() { close(t.started) })
	defer close(t.finished)
	select {
	case <-t.release:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (t *ownedDeliveryTransport) Close() error { return nil }

func TestBoundaryOwnsObservationCompletion(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	c.backends[0].subscriptions[0]["mode"] = "observe"
	tr := &ownedDeliveryTransport{started: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
	c.backends[0].transport = tr
	done := make(chan *Result, 1)
	go func() {
		r, e := c.intercept(context.Background(), "tool.before", testInput())
		if e != nil {
			t.Error(e)
		}
		done <- r
	}()
	<-tr.started
	select {
	case <-done:
		t.Fatal("boundary returned with owned observation running")
	default:
	}
	close(tr.release)
	r := <-done
	select {
	case <-tr.finished:
	default:
		t.Fatal("owned transport not retired")
	}
	select {
	case <-r.Observations.Done():
	default:
		t.Fatal("compatibility observations handle incomplete")
	}
	if r.Permission != "none" || r.Interrupted || len(r.Diagnostics) != 0 {
		t.Fatalf("unexpected settlement: %+v", r)
	}
}

func TestObservationUsesRemainingOperationBudget(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	c.backends[0].subscriptions[0]["mode"] = "observe"
	c.opts.ObservationTimeout = time.Hour
	tr := &ownedDeliveryTransport{started: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
	c.backends[0].transport = tr
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r, err := c.intercept(ctx, "tool.before", testInput())
	if !errors.Is(err, context.DeadlineExceeded) || r == nil || !r.Interrupted {
		t.Fatalf("result %+v error %v", r, err)
	}
	if len(r.Diagnostics) != 1 || r.Diagnostics[0].Code != DeliveryDeadlineExceeded || r.Diagnostics[0].BackendID != c.backends[0].id {
		t.Fatalf("diagnostics: %+v", r.Diagnostics)
	}
	if r.Permission != "none" {
		t.Fatal("observer changed decision")
	}
	select {
	case <-tr.finished:
	default:
		t.Fatal("deadline left owned transport running")
	}
}

func TestCancelledBoundaryDoesNotStartObservers(t *testing.T) {
	c, transports := testClient(t, "fail-open")
	c.backends[0].subscriptions[0]["mode"] = "observe"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := c.intercept(ctx, "tool.before", testInput())
	if !errors.Is(err, context.Canceled) || r == nil || !r.Interrupted {
		t.Fatalf("result %+v error %v", r, err)
	}
	if len(transports[0].calls) != 0 {
		t.Fatal("cancellation started best-effort observer")
	}
}

type blockingCloseTransport struct{ started, release chan struct{} }

func (t *blockingCloseTransport) Exchange(context.Context, []byte, bool) ([]byte, error) {
	return nil, nil
}
func (t *blockingCloseTransport) Close() error {
	close(t.started)
	<-t.release
	return errors.New("close failed")
}
func TestConcurrentCloseWaitsForSameRetirement(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	tr := &blockingCloseTransport{started: make(chan struct{}), release: make(chan struct{})}
	c.backends[0].transport = tr
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- c.Close() }()
	<-tr.started
	go func() { second <- c.Close() }()
	select {
	case <-second:
		t.Fatal("concurrent close returned before resource retirement")
	case <-time.After(20 * time.Millisecond):
	}
	close(tr.release)
	a, b := <-first, <-second
	if a == nil || a != b {
		t.Fatalf("concurrent close outcomes differ: %v %v", a, b)
	}
	if c.Close() != a {
		t.Fatal("repeated close lost outcome")
	}
}

type retirementReader struct{ started, release chan struct{} }

func (r *retirementReader) Read([]byte) (int, error) { return 0, errors.New("unexpected read") }
func (r *retirementReader) Close() error             { close(r.started); <-r.release; return nil }

func TestCloseIncludesUnusedSourceCleanup(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	reader := &retirementReader{started: make(chan struct{}), release: make(chan struct{})}
	source := NewContentSource(reader)
	call := make(chan error, 1)
	go func() {
		_, err := c.intercept(context.Background(), "tool.before", testInput(), WithContentSource("/items/0", source))
		call <- err
	}()
	<-reader.started // Invalid source binding still transfers and closes ownership.
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case <-closed:
		t.Fatal("Close returned before source cleanup")
	case <-time.After(20 * time.Millisecond):
	}
	close(reader.release)
	if err := <-call; err == nil {
		t.Fatal("invalid source binding admitted")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

// Mirrors the generated input-source interface without hand-writing wire models.
type generatedSourceInput struct {
	value  map[string]any
	source *content.Source
}

func (i generatedSourceInput) MarshalJSON() ([]byte, error) { return sdkJSON(i.value), nil }
func (i generatedSourceInput) AHPContentSources() map[string]*content.Source {
	return map[string]*content.Source{"/items/0": i.source}
}

func TestGeneratedSourceBindingClosesOnAdmissionFailure(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	reader := &sourceTestReader{Reader: strings.NewReader("never read")}
	source := content.NewSource(reader)
	_, err := c.intercept(nil, "tool.before", generatedSourceInput{value: testInput(), source: source})
	if err == nil || reader.reads.Load() != 0 || reader.closes.Load() != 1 {
		t.Fatalf("error=%v reads=%d closes=%d", err, reader.reads.Load(), reader.closes.Load())
	}
}
