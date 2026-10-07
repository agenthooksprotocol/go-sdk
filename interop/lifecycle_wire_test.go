package interop

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type cancellationWireWriter struct {
	bytes.Buffer
	sent chan struct{}
	once sync.Once
}

func (w *cancellationWireWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	w.once.Do(func() { close(w.sent) })
	return n, err
}

func TestLifecycleWireCancellationRetiresExactPendingRequest(t *testing.T) {
	writer := &cancellationWireWriter{sent: make(chan struct{})}
	pipe := &lifecyclePipe{writer: writer, pending: map[string][]chan lifecycleResult{}, discarded: map[string]int{}, changed: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request := request("wire-cancel")
	done := make(chan error, 1)
	go func() { _, err := lifecycleWireCall(ctx, request, pipe, nil, "", ""); done <- err }()
	<-writer.sent
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
	id := lifecycleID(request)
	pipe.mu.Lock()
	pending := len(pipe.pending[id])
	retired := pipe.retired[id]
	pipe.mu.Unlock()
	if pending != 0 || !retired {
		t.Fatalf("pending=%d retired=%v", pending, retired)
	}
	if err := pipe.send(request, make(chan lifecycleResult, 1)); err == nil {
		t.Fatal("canceled identity rebound before late reply")
	}
	pipe.read(bytes.NewReader(append(jsonBytes(response("wire-cancel")), '\n')))
	pipe.mu.Lock()
	discarded := pipe.discarded[id]
	pipe.mu.Unlock()
	if discarded != 1 {
		t.Fatal("late canceled response was not discarded", discarded)
	}
}
