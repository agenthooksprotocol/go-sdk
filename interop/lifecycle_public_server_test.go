package interop

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Deliberately no lifecycleValidator: wire acceptance must use the public SDK.
func publicLifecycleReceiver() *lifecycleReceiver {
	return &lifecycleReceiver{changed: make(chan struct{}), responses: map[string]Object{}, released: map[string]bool{}, sequences: map[string][]Object{}, occurrences: map[string]int{}, uploads: map[string]string{}}
}
func publicLifecycleCall(t *testing.T, handler http.Handler, message Object) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/intercept", bytes.NewReader(jsonBytes(message)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}
func publicLifecycleObservation(id string) Object {
	return Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": obj(request(id)["params"])["event"]}}
}

func TestLifecycleReceiverPublicAcceptance(t *testing.T) {
	s := publicLifecycleReceiver()
	m := request("public")
	key := lifecycleID(m)
	s.responses[key] = response("public", Object{"type": "message", "text": "accepted"})
	s.released[key] = true
	h, err := s.publicHandler()
	if err != nil {
		t.Fatal(err)
	}
	w := publicLifecycleCall(t, h, m)
	var reply Object
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || reply["id"] != "public" || reply["result"] == nil {
		t.Fatalf("ordinary reply: %d %s", w.Code, w.Body.String())
	}
	invalid := obj(clone(m))
	delete(obj(obj(invalid["params"])["event"]), "id")
	before := len(s.entries)
	w = publicLifecycleCall(t, h, invalid)
	if len(s.entries) != before {
		t.Fatal("public schema rejection reached schedule callback")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"error"`)) {
		t.Fatalf("missing rejection: %s", w.Body.String())
	}
	// Schema-valid but unadvertised effects must be rejected by NewHandler.
	obj(m["params"])["capabilities"] = Object{"effects": []any{"deny"}}
	before = len(s.entries)
	w = publicLifecycleCall(t, h, m)
	if len(s.entries) != before+2 {
		t.Fatal("response rejection never reached callback")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"error"`)) {
		t.Fatalf("unadvertised fixture response escaped public acceptance: %s", w.Body.String())
	}
	w = publicLifecycleCall(t, h, publicLifecycleObservation("ordinary-observe"))
	if w.Code != 204 || w.Body.Len() != 0 {
		t.Fatalf("notification got protocol reply: %d %s", w.Code, w.Body.String())
	}
}

func TestLifecyclePublicCatalogueRejectedReceipt(t *testing.T) {
	s := publicLifecycleReceiver()
	s.suite = "catalogue"
	h, err := s.publicHandler()
	if err != nil {
		t.Fatal(err)
	}
	m := publicLifecycleObservation("rejected")
	delete(obj(obj(m["params"])["event"]), "source")
	w := publicLifecycleCall(t, h, m)
	if w.Body.Len() != 0 {
		t.Fatalf("rejected notification emitted body: %s", w.Body.String())
	}
	if len(s.entries) != 1 || obj(s.entries[0])["kind"] != "rejected" {
		t.Fatalf("missing public rejection receipt: %#v", s.entries)
	}
	w = publicLifecycleCall(t, h, publicLifecycleObservation("accepted"))
	if w.Code != 204 || len(s.entries) != 2 || obj(s.entries[1])["kind"] != "observed" {
		t.Fatalf("ordinary observe failed: %d %#v", w.Code, s.entries)
	}
	w = publicLifecycleCall(t, h, Object{"jsonrpc": "2.0", "id": "discovery", "method": "hooks/capabilities", "params": Object{"protocolVersion": "draft"}})
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"manifest"`)) {
		t.Fatalf("discovery: %d %s", w.Code, w.Body.String())
	}
}

func TestLifecyclePublicStdioHeldObserverAndRawEmit(t *testing.T) {
	s := publicLifecycleReceiver()
	m := request("next")
	key := lifecycleID(m)
	s.responses[key] = response("next", Object{"type": "message", "text": "accepted"})
	s.released[key] = true
	s.sequences["held:observers"] = []Object{}
	h, err := s.publicHandler()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	in, send := io.Pipe()
	receive, out := io.Pipe()
	defer send.Close()
	defer receive.Close()
	var outputMu sync.Mutex
	done := make(chan error, 1)
	go func() { done <- serveLifecycleStdio(ctx, in, out, &outputMu, h) }()
	frames := make(chan Object, 3)
	go func() {
		scanner := bufio.NewScanner(receive)
		for scanner.Scan() {
			var frame Object
			_ = json.Unmarshal(scanner.Bytes(), &frame)
			frames <- frame
		}
	}()
	if err := json.NewEncoder(send).Encode(publicLifecycleObservation("held")); err != nil {
		t.Fatal(err)
	}
	if err := s.wait(ctx, func() bool {
		for _, entry := range s.entries {
			if obj(entry)["kind"] == "observer-blocked" {
				return true
			}
		}
		return false
	}); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(send).Encode(m); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-frames:
		if frame["id"] != "next" || frame["result"] == nil {
			t.Fatalf("unexpected public frame: %#v", frame)
		}
	case <-ctx.Done():
		t.Fatal("held observer blocked the next intercept")
	}
	// Same serialized output boundary used by /emit, intentionally not accepted
	// or rewritten by the public server. An unsolicited ID must survive exactly.
	outputMu.Lock()
	err = json.NewEncoder(out).Encode(response("unsolicited", Object{"type": "message", "text": "raw"}))
	outputMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-frames:
		if frame["id"] != "unsolicited" {
			t.Fatalf("raw emit rewritten: %#v", frame)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	s.mu.Lock()
	s.released[lifecycleID(Object{"id": "held:observers"})] = true
	close(s.changed)
	s.changed = make(chan struct{})
	s.mu.Unlock()
	_ = send.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case frame := <-frames:
		t.Fatalf("observer emitted frame: %#v", frame)
	default:
	}
}

func TestLifecyclePublicStdioPreservesUnterminatedFrame(t *testing.T) {
	s := publicLifecycleReceiver()
	h, err := s.publicHandler()
	if err != nil {
		t.Fatal(err)
	}
	receive, output := io.Pipe()
	defer receive.Close()
	drained := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, receive); close(drained) }()
	var mu sync.Mutex
	// Do not let the fixture scheduler repair an invalid frame before the public
	// stdio adapter sees it.
	err = serveLifecycleStdio(context.Background(), io.NopCloser(bytes.NewReader(jsonBytes(publicLifecycleObservation("unterminated")))), output, &mu, h)
	if err == nil {
		t.Fatal("unterminated frame was repaired by scheduler")
	}
	<-drained
	if len(s.entries) != 0 {
		t.Fatal("unterminated frame reached callback")
	}
}

// dispatch retains the direct fixture test entry point. Live traffic is accepted
// by publicHandler before the schedule callback is invoked.
func (s *lifecycleReceiver) dispatch(ctx context.Context, m Object) (Object, error) {
	if s.suite == "catalogue" {
		return s.catalogueDispatch(m)
	}
	kind := "intercept-request"
	if m["method"] == "hooks/observe" {
		kind = "observe"
	}
	if err := s.validator.validate(kind, m); err != nil {
		return nil, err
	}
	return s.acceptedDispatch(ctx, m)
}

// Compatibility serializer used only by the pre-migration notification test.

func writeLifecycleReply(w http.ResponseWriter, reply Object) {
	if reply == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_ = json.NewEncoder(w).Encode(reply)
}
