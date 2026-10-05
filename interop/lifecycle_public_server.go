package interop

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/server"
)

// lifecycleAcceptance is request-local instrumentation, not a validator. A
// callback can only mark entry after NewHandler accepts the wire message.
type lifecycleAcceptance struct {
	entered   bool
	rejection string
}
type lifecycleAcceptanceKey struct{}

func lifecycleMessage(ctx context.Context, value any) Object {
	ctx.Value(lifecycleAcceptanceKey{}).(*lifecycleAcceptance).entered = true
	var message Object
	_ = json.Unmarshal(jsonBytes(value), &message)
	return message
}

func (s *lifecycleReceiver) publicHandler() (http.Handler, error) {
	callbacks := server.Handlers{
		Intercept: func(ctx context.Context, request ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
			message := lifecycleMessage(ctx, request)
			if s.suite == "catalogue" {
				return ahp.InterceptResponseResult{}, fmt.Errorf("unsupported catalogue method")
			}
			reply, err := s.acceptedDispatch(ctx, message)
			if err != nil {
				return ahp.InterceptResponseResult{}, err
			}
			var result ahp.InterceptResponseResult
			err = json.Unmarshal(jsonBytes(reply["result"]), &result)
			return result, err // NewHandler owns full response and effect acceptance.
		},
		Observe: func(ctx context.Context, notification ahp.ObserveNotification) error {
			message := lifecycleMessage(ctx, notification)
			if s.suite != "catalogue" {
				_, err := s.acceptedDispatch(ctx, message)
				return err
			}
			event := obj(obj(message["params"])["event"])
			s.mu.Lock()
			defer s.mu.Unlock()
			reject := func(kind string, err error) error {
				ctx.Value(lifecycleAcceptanceKey{}).(*lifecycleAcceptance).rejection = kind
				s.record(Object{"kind": "rejected", "eventId": event["id"], "message": clone(message), "errorKind": kind})
				return err
			}
			// These checks are host-owned content authorization and durable lineage,
			// not an alternative protocol/schema acceptance engine.
			if err := checkContent(event, "", s.eventContent()); err != nil {
				return reject("schema", err)
			}
			if err := s.lineage.Accept(event); err != nil {
				return reject("lineage", err)
			}
			s.record(Object{"kind": "observed", "eventId": event["id"], "event": clone(event), "message": clone(message)})
			return nil
		},
	}
	if s.suite == "catalogue" {
		callbacks.Capabilities = func(ctx context.Context, request ahp.CapabilitiesRequest) (ahp.CapabilitiesResponseResult, error) {
			message := lifecycleMessage(ctx, request)
			response := Object{"jsonrpc": "2.0", "id": message["id"], "result": Object{"protocolVersion": "draft", "manifest": catalogueManifest()}}
			var result ahp.CapabilitiesResponseResult
			err := json.Unmarshal(jsonBytes(response["result"]), &result)
			if err != nil {
				return result, err
			}
			s.mu.Lock()
			s.record(Object{"kind": "discovery", "request": clone(message), "response": clone(response)})
			s.mu.Unlock()
			return result, nil
		}
	}
	handler, err := server.NewHandler(callbacks, server.Options{})
	if err != nil {
		return nil, err
	}
	ordinary := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acceptance := &lifecycleAcceptance{}
		if s.suite != "catalogue" {
			handler.ServeHTTP(lifecycleStatusWriter{ResponseWriter: w, acceptance: acceptance}, r.WithContext(context.WithValue(r.Context(), lifecycleAcceptanceKey{}, acceptance)))
			return
		}
		// Preserve raw-notification rejection receipts for the catalogue schedule.
		// Decoding here is telemetry only: NewHandler exclusively decides acceptance.
		body, err := io.ReadAll(io.LimitReader(r.Body, server.DefaultMaxFrameBytes+1))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		handler.ServeHTTP(lifecycleStatusWriter{ResponseWriter: w, acceptance: acceptance}, r.WithContext(context.WithValue(r.Context(), lifecycleAcceptanceKey{}, acceptance)))
		if !acceptance.entered {
			var message Object
			if json.Unmarshal(body, &message) == nil && message["method"] == "hooks/observe" {
				event := obj(obj(message["params"])["event"])
				s.mu.Lock()
				s.record(Object{"kind": "rejected", "eventId": event["id"], "message": clone(message), "errorKind": "schema"})
				s.mu.Unlock()
			}
		}
	})
	return s.withAdversarialLifecycleReply(ordinary), nil
}

// Preserve fixture HTTP rejection diagnostics without intercepting RPC bodies.
type lifecycleStatusWriter struct {
	http.ResponseWriter
	acceptance *lifecycleAcceptance
}

func (w lifecycleStatusWriter) WriteHeader(status int) {
	if status == http.StatusInternalServerError && w.acceptance.rejection != "" {
		status = http.StatusConflict
		if w.acceptance.rejection == "schema" {
			status = http.StatusBadRequest
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

// serveLifecycleStdio is only a fixture scheduler. Every complete frame runs
// through the public stdio adapter and the same public HTTP handler. This lets a
// held observer coexist with a later intercept; the raw /emit control path is
// deliberately separate. Neither framing nor scheduling decides RPC acceptance.
func serveLifecycleStdio(parent context.Context, input io.ReadCloser, output io.WriteCloser, outputMu *sync.Mutex, handler http.Handler) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var closeOnce sync.Once
	closeStreams := func() { closeOnce.Do(func() { _ = input.Close(); _ = output.Close() }) }
	defer closeStreams()
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			closeStreams()
		case <-stopped:
		}
	}()
	var workers sync.WaitGroup
	failures := make(chan error, 1)
	slots := make(chan struct{}, 64)
	scan := bufio.NewScanner(input)
	scan.Buffer(make([]byte, 4096), int(server.DefaultMaxFrameBytes)+2)
	// Preserve terminators and a final unterminated fragment verbatim. The
	// public adapter, not this scheduler, decides whether framing is valid.
	scan.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i+1], nil
		}
		if atEOF && len(data) != 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	for scan.Scan() {
		frame := append([]byte(nil), scan.Bytes()...)
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			break
		}
		if ctx.Err() != nil {
			break
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			// The adapter owns its finite in-memory input and its output lease. Closing
			// a lease prevents further writes; only this scheduler owns the real stream.
			lease := &lifecycleOutputLease{writer: output, mu: outputMu}
			err := server.ServeStdio(ctx, io.NopCloser(bytes.NewReader(frame)), lease, handler)
			if err != nil && ctx.Err() == nil {
				select {
				case failures <- err:
				default:
				}
				cancel()
			}
		}()
	}
	scanErr := scan.Err()
	if scanErr != nil {
		cancel()
	}
	workers.Wait()
	select {
	case err := <-failures:
		return err
	default:
	}
	if parent.Err() != nil {
		return parent.Err()
	}
	return scanErr
}

type lifecycleOutputLease struct {
	writer io.Writer
	mu     *sync.Mutex
	state  sync.Mutex
	closed bool
}

func (w *lifecycleOutputLease) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.state.Lock()
	closed := w.closed
	w.state.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	return w.writer.Write(p)
}
func (w *lifecycleOutputLease) Close() error {
	w.state.Lock()
	w.closed = true
	w.state.Unlock()
	return nil
}

// Content readiness is a host authorization conflict, not a malformed AHP
// envelope. Public callback error handling still decides rejection and the body.
func markLifecyclePolicyConflict(ctx context.Context) {
	if acceptance, ok := ctx.Value(lifecycleAcceptanceKey{}).(*lifecycleAcceptance); ok {
		acceptance.rejection = "content"
	}
}
