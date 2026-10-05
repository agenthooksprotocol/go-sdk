package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sync"
	"unicode/utf8"
)

var ErrFrameTooLarge = errors.New("server: frame exceeds limit")
var ErrStdioResponse = errors.New("server: invalid stdio response")

// ServeStdio owns both streams and closes them on all exits and cancellation.
// Close must unblock concurrent Read/Write; no-op closers cannot satisfy this
// contract. Handlers must cooperate with context cancellation. Requests execute
// sequentially with write backpressure and 4 MiB request/response ceilings.
// Synthetic requests are POST http://stdio.invalid/hooks, with an empty
// RemoteAddr and no authenticated identity. HTTP credentials are not synthesized.
// Only ordinary buffered ResponseWriter operations are supported. Status and
// headers are ignored; canonical RPC bodies (including HTTP errors) are emitted.
func ServeStdio(ctx context.Context, input io.ReadCloser, output io.WriteCloser, handler http.Handler) (err error) {
	var once sync.Once
	var closeErr error
	closeBoth := func() {
		once.Do(func() {
			if input != nil {
				closeErr = errors.Join(closeErr, input.Close())
			}
			same := input != nil && output != nil && reflect.TypeOf(input) == reflect.TypeOf(output) && reflect.TypeOf(input).Comparable() && any(input) == any(output)
			if output != nil && !same {
				closeErr = errors.Join(closeErr, output.Close())
			}
		})
	}
	defer func() {
		closeBoth()
		err = errors.Join(err, closeErr)
		if ctx != nil && ctx.Err() != nil {
			err = errors.Join(ctx.Err(), err)
		}
	}()
	if ctx == nil || input == nil || output == nil || handler == nil {
		return errors.New("server: context, streams and handler required")
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-done:
		}
	}()
	reader := bufio.NewReader(input)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		frame, err := readFrame(reader)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://stdio.invalid/hooks", bytes.NewReader(frame))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		capture := &frameWriter{header: make(http.Header)}
		if err := serveFrame(handler, capture, req); err != nil {
			return err
		}
		if capture.err != nil {
			return capture.err
		}
		response := bytes.TrimSpace(capture.body.Bytes())
		if len(response) == 0 {
			continue
		}
		if !validStdioResponse(frame, response) {
			return ErrStdioResponse
		}
		// Compact multiline JSON so one response always occupies one protocol frame.
		var compact bytes.Buffer
		if json.Compact(&compact, response) != nil {
			return ErrStdioResponse
		}
		compact.WriteByte('\n')
		if _, err := io.Copy(output, &compact); err != nil {
			return fmt.Errorf("server: write frame: %w", err)
		}
	}
}
func readFrame(r *bufio.Reader) ([]byte, error) {
	var frame []byte
	for {
		piece, err := r.ReadSlice('\n')
		if int64(len(frame)+len(piece)) > DefaultMaxFrameBytes+1 {
			return nil, ErrFrameTooLarge
		}
		frame = append(frame, piece...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF && len(frame) > 0 {
			return nil, io.ErrUnexpectedEOF
		}
		if err != nil {
			return nil, err
		}
		frame = bytes.TrimSuffix(frame, []byte{'\n'})
		if int64(len(frame)) > DefaultMaxFrameBytes {
			return nil, ErrFrameTooLarge
		}
		return frame, nil
	}
}
func validStdioResponse(request, response []byte) bool {
	if !utf8.Valid(response) {
		return false
	}
	if !canonical("successResponse", response) && !canonical("errorResponse", response) {
		return false
	}
	if canonical("notification", request) {
		return false
	}
	var req, res map[string]json.RawMessage
	_ = json.Unmarshal(request, &req)
	_ = json.Unmarshal(response, &res)
	id := req["id"]
	if !canonical("request", request) && bytes.Equal(res["id"], []byte("null")) && res["error"] != nil {
		return true
	}
	if !canonical("jsonRpcId", id) {
		return bytes.Equal(res["id"], []byte("null")) && res["error"] != nil
	}
	var a, b any
	da := json.NewDecoder(bytes.NewReader(id))
	da.UseNumber()
	_ = da.Decode(&a)
	db := json.NewDecoder(bytes.NewReader(res["id"]))
	db.UseNumber()
	_ = db.Decode(&b)
	return reflect.DeepEqual(a, b)
}

type frameWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
	err    error
}

func (w *frameWriter) Header() http.Header { return w.header }
func (w *frameWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *frameWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if int64(w.body.Len()+len(p)) > DefaultMaxFrameBytes {
		w.err = ErrFrameTooLarge
		return 0, w.err
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}

// Recover only across a user handler boundary; never expose panic payloads.
func serveFrame(h http.Handler, w http.ResponseWriter, r *http.Request) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrStdioResponse
		}
	}()
	h.ServeHTTP(w, r)
	return nil
}
