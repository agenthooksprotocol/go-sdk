package interop

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"
)

// Cancellation must reach the HTTP receiver, but the fixture controller still
// owns the deliberately late reply. The second request is actually concurrent.
func TestLifecycleHTTPDisconnectPreservesControlledLateReply(t *testing.T) {
	life, stop := context.WithCancel(context.Background())
	defer stop()
	s := publicLifecycleReceiver()
	s.life = life
	for _, id := range []string{"old", "next"} {
		s.responses[lifecycleID(request(id))] = response(id)
	}
	h, err := s.publicHandler()
	if err != nil {
		t.Fatal(err)
	}
	disconnected := make(chan struct{})
	finished := make(chan struct{}, 2)
	var workers sync.WaitGroup
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			workers.Add(1)
			go func() { defer workers.Done(); <-r.Context().Done(); close(disconnected) }()
		}
		h.ServeHTTP(w, r)
		finished <- struct{}{}
	}))
	defer func() { stop(); peer.Close(); workers.Wait() }()
	deadline, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	send := func(id string, ctx context.Context) <-chan error {
		result := make(chan error, 1)
		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, peer.URL+"/"+id, bytes.NewReader(jsonBytes(request(id))))
			if err != nil {
				result <- err
				return
			}
			req.Header.Set("Content-Type", "application/json")
			res, err := peer.Client().Do(req)
			if err == nil {
				_, err = io.Copy(io.Discard, res.Body)
				res.Body.Close()
			}
			result <- err
		}()
		return result
	}
	waitReceipt := func(kind, id string) {
		t.Helper()
		if err := s.wait(deadline, func() bool {
			for _, raw := range s.entries {
				e := obj(raw)
				if e["kind"] == kind && e["id"] == id {
					return true
				}
			}
			return false
		}); err != nil {
			t.Fatal(err)
		}
	}
	release := func(id string) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.released[lifecycleID(request(id))] = true
		close(s.changed)
		s.changed = make(chan struct{})
	}
	oldCtx, cancelOld := context.WithCancel(deadline)
	defer cancelOld()
	old := send("old", oldCtx)
	waitReceipt("received", "old")
	cancelOld()
	select {
	case <-disconnected:
	case <-deadline.Done():
		t.Fatal("disconnect did not reach receiver")
	}
	if err := <-old; err == nil {
		t.Fatal("cancelled caller accepted a reply")
	}
	next := send("next", deadline)
	waitReceipt("received", "next")
	release("old")
	waitReceipt("replied", "old")
	select {
	case err := <-next:
		t.Fatalf("second request escaped its release gate: %v", err)
	default:
	}
	release("next")
	waitReceipt("replied", "next")
	if err := <-next; err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case <-finished:
		case <-deadline.Done():
			t.Fatal("handler did not finish")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	got := []string{}
	for _, raw := range s.entries {
		e := obj(raw)
		got = append(got, str(e["kind"])+":"+str(e["id"]))
	}
	want := []string{"received:old", "received:next", "replied:old", "replied:next"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("receipt order/multiplicity: %v", got)
	}
}

func TestLifecycleControlledReplyStopsWithFixture(t *testing.T) {
	life, stop := context.WithCancel(context.Background())
	defer stop()
	s := publicLifecycleReceiver()
	s.life = life
	m := request("shutdown")
	s.responses[lifecycleID(m)] = response("shutdown")
	done := make(chan error, 1)
	go func() { _, err := s.acceptedDispatch(context.Background(), m); done <- err }()
	deadline, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.wait(deadline, func() bool { return len(s.entries) == 1 }); err != nil {
		t.Fatal(err)
	}
	stop()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("shutdown: %v", err)
		}
	case <-deadline.Done():
		t.Fatal("fixture shutdown retained a held reply")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) != 1 {
		t.Fatal("shutdown fabricated a reply")
	}
}
