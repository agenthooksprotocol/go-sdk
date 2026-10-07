package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + name + ".json")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func noEffect() ahp.InterceptResponseResult {
	v := ahp.ProtocolVersion("draft")
	return ahp.InterceptResponseResult{ProtocolVersion: &v, Effects: []*ahp.Effect{}}
}
func request(h http.Handler, b []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/hooks", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestHandlerCanonicalAndRedaction(t *testing.T) {
	var calls int
	h, e := NewHandler(Handlers{Intercept: func(context.Context, ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
		calls++
		return noEffect(), nil
	}}, Options{})
	if e != nil {
		t.Fatal(e)
	}
	b := fixture(t, "intercept")
	w := request(h, b)
	if w.Code != 200 || !ahp.ParseInterceptResponse(w.Body.Bytes()).OK || !strings.Contains(w.Body.String(), "evt_http_001") {
		t.Fatalf("response %d %s", w.Code, w.Body)
	}
	// Invalid RFC3339 time is accepted structurally but rejected canonically.
	invalid := bytes.ReplaceAll(b, []byte("2026-08-24T08:51:14Z"), []byte("not-a-time"))
	w = request(h, invalid)
	if calls != 1 || !strings.Contains(w.Body.String(), "-32602") {
		t.Fatalf("invalid reached callback: %s", w.Body)
	}
	for _, panicNow := range []bool{false, true} {
		h, e = NewHandler(Handlers{Intercept: func(context.Context, ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
			if panicNow {
				panic("SECRET")
			}
			return noEffect(), errors.New("SECRET")
		}}, Options{})
		if e != nil {
			t.Fatal(e)
		}
		w = request(h, b)
		if strings.Contains(w.Body.String(), "SECRET") || !strings.Contains(w.Body.String(), "-32004") {
			t.Fatal(w.Body.String())
		}
	}
}
func TestNotificationSilence(t *testing.T) {
	for _, panicNow := range []bool{false, true} {
		h, e := NewHandler(Handlers{Observe: func(context.Context, ahp.ObserveNotification) error {
			if panicNow {
				panic("SECRET")
			}
			return errors.New("SECRET")
		}}, Options{})
		if e != nil {
			t.Fatal(e)
		}
		w := request(h, fixture(t, "observe"))
		if w.Body.Len() != 0 {
			t.Fatal(w.Body.String())
		}
	}
}
func TestInvalidResultAndLimits(t *testing.T) {
	h, e := NewHandler(Handlers{Intercept: func(context.Context, ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
		return ahp.InterceptResponseResult{}, nil
	}}, Options{})
	if e != nil {
		t.Fatal(e)
	}
	if w := request(h, fixture(t, "intercept")); !strings.Contains(w.Body.String(), "-32004") {
		t.Fatal(w.Body.String())
	}
	h, e = NewHandler(Handlers{}, Options{MaxRequestBytes: 2})
	if e != nil {
		t.Fatal(e)
	}
	if w := request(h, []byte("123")); w.Code != 413 {
		t.Fatal(w.Code)
	}
	if _, e := NewHandler(Handlers{}, Options{MaxResponseBytes: 1}); e == nil {
		t.Fatal("accepted unusable ceiling")
	}
}

type readClose struct {
	io.Reader
	closed atomic.Int32
}

func (r *readClose) Close() error { r.closed.Add(1); return nil }

type writeClose struct {
	bytes.Buffer
	closed atomic.Int32
}

func (w *writeClose) Close() error { w.closed.Add(1); return nil }
func TestStdioFramesAndErrors(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":"x","method":"custom","params":{}}` + "\n"
	for _, tc := range []struct {
		name, body string
		status     int
		wantErr    bool
	}{
		{"non2xx", `{"jsonrpc":"2.0","id":"x","error":{"code":-32603,"message":"Internal error"}}`, 500, false},
		{"empty", "", 204, false}, {"html", "<html>bad</html>", 403, true},
		{"uncorrelated", `{"jsonrpc":"2.0","id":"y","result":{}}`, 200, true},
		{"too large", strings.Repeat("x", int(DefaultMaxFrameBytes)+1), 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := &readClose{Reader: strings.NewReader(input)}
			out := new(writeClose)
			err := ServeStdio(context.Background(), in, out, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RemoteAddr != "" || r.URL.Host != "stdio.invalid" {
					t.Error("synthetic identity")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			if (err != nil) != tc.wantErr {
				t.Fatalf("error: %v", err)
			}
			if in.closed.Load() != 1 || out.closed.Load() != 1 {
				t.Fatal("ownership")
			}
			if tc.wantErr && out.Len() != 0 {
				t.Fatal("partial frame")
			}
			if !tc.wantErr && tc.body != "" && out.String() != tc.body+"\n" {
				t.Fatal("missing error envelope")
			}
		})
	}
}
func TestStdioCancellationAndPartialFrame(t *testing.T) {
	in, feed := io.Pipe()
	defer feed.Close()
	out := new(writeClose)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ServeStdio(ctx, in, out, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	}()
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked read not canceled")
	}
	e := ServeStdio(context.Background(), &readClose{Reader: strings.NewReader("{")}, new(writeClose), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatal(e)
	}
}
func uploadRequest(body []byte) *http.Request {
	r := httptest.NewRequest("POST", "/upload", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	sum := sha256.Sum256(body)
	r.Header.Set("AHP-Content-SHA256", hex.EncodeToString(sum[:]))
	return r
}
func TestUploadVerificationAndReference(t *testing.T) {
	for _, body := range [][]byte{{}, {0, 255, 128, 13, 10}} {
		r := uploadRequest(body)
		u, e := ParseUpload(r, 10)
		if e != nil {
			t.Fatal(e)
		}
		if u.Verified() {
			t.Fatal("eager verification")
		}
		if _, e = u.Reference("x"); !errors.Is(e, ErrUploadUnverified) {
			t.Fatal(e)
		}
		got, e := io.ReadAll(u)
		if e != nil || !bytes.Equal(got, body) || !u.Verified() {
			t.Fatalf("read: %x %v", got, e)
		}
		ref, e := u.Reference("immutable")
		if e != nil {
			t.Fatal(e)
		}
		ref.Sha256 = "tampered"
		ref, e = u.Reference("immutable")
		if e != nil || ref.Sha256 == "tampered" {
			t.Fatal("mutable metadata")
		}
		w := httptest.NewRecorder()
		if e = WriteUploadResponse(w, ref); e != nil || w.Code != 201 || !json.Valid(w.Body.Bytes()) {
			t.Fatal(e)
		}
		if e = u.Close(); e != nil {
			t.Fatal(e)
		}
	}
}
func TestUploadFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
		want   error
	}{
		{"short", func(r *http.Request) { r.ContentLength = 4; r.Header.Set("Content-Length", "4") }, ErrUploadSize},
		{"long", func(r *http.Request) { r.ContentLength = 2; r.Header.Set("Content-Length", "2") }, ErrUploadSize},
		{"digest", func(r *http.Request) { r.Header.Set("AHP-Content-SHA256", strings.Repeat("0", 64)) }, ErrUploadDigest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := uploadRequest([]byte("abc"))
			tc.change(r)
			u, e := ParseUpload(r, 10)
			if e != nil {
				t.Fatal(e)
			}
			_, e = io.Copy(io.Discard, u)
			if !errors.Is(e, tc.want) || u.Verified() {
				t.Fatal(e)
			}
			_ = u.Close()
		})
	}
	r := uploadRequest([]byte("abc"))
	u, e := ParseUpload(r, 10)
	if e != nil {
		t.Fatal(e)
	}
	_ = u.Close()
	if u.Verified() {
		t.Fatal("early close")
	}
	r = uploadRequest(nil)
	r.TransferEncoding = []string{"chunked"}
	if _, e = ParseUpload(r, 10); !errors.Is(e, ErrUploadFraming) {
		t.Fatal(e)
	}
}

func TestRequestCorrelationAndVersion(t *testing.T) {
	calls := 0
	h, e := NewHandler(Handlers{Intercept: func(context.Context, ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
		calls++
		return noEffect(), nil
	}}, Options{})
	if e != nil {
		t.Fatal(e)
	}
	b := fixture(t, "intercept")
	mismatch := bytes.Replace(b, []byte(`"id": "evt_http_001"`), []byte(`"id": "other"`), 1)
	if w := request(h, mismatch); !strings.Contains(w.Body.String(), "-32602") || calls != 0 {
		t.Fatalf("correlation accepted: %s", w.Body)
	}
	version := bytes.Replace(b, []byte(`"protocolVersion": "draft"`), []byte(`"protocolVersion": "unsupported"`), 1)
	if w := request(h, version); !strings.Contains(w.Body.String(), "-32001") || calls != 0 {
		t.Fatalf("version accepted: %s", w.Body)
	}
}
func TestUnadvertisedCallbackEffectRejected(t *testing.T) {
	h, e := NewHandler(Handlers{Intercept: func(context.Context, ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
		var result ahp.InterceptResponseResult
		if e := json.Unmarshal([]byte(`{"protocolVersion":"draft","effects":[{"type":"message","text":"not advertised"}]}`), &result); e != nil {
			t.Fatal(e)
		}
		return result, nil
	}}, Options{})
	if e != nil {
		t.Fatal(e)
	}
	w := request(h, fixture(t, "intercept"))
	if !strings.Contains(w.Body.String(), "-32004") || strings.Contains(w.Body.String(), "not advertised") {
		t.Fatal(w.Body.String())
	}
}
func TestEffectOperationAndMergeValidation(t *testing.T) {
	request := []byte(`{"params":{"event":{"tool":{"input":{"a":1}}},"capabilities":{"effects":["modify","flow","inject"],"modify":{"input":{"replace":true}},"flow":{"operations":["continue"],"remainingContinuations":0},"inject":{"context":{"append":true,"deliverAt":["now"]}}}}}`)
	if !json.Valid(request) {
		t.Fatal("invalid test request")
	}
	for _, effect := range []string{
		`{"type":"modify","target":"input","operation":"merge","value":{}}`,
		`{"type":"modify","target":"input","operation":"replace","value":null}`,
		`{"type":"flow","operation":"continue"}`,
		`{"type":"inject","target":"context","operation":"append","deliverAt":"next_turn","value":[]}`,
	} {
		if validEffects(request, []byte(`{"result":{"effects":[`+effect+`]}}`)) {
			t.Fatalf("accepted %s", effect)
		}
	}
	if !validEffects(request, []byte(`{"result":{"effects":[{"type":"modify","target":"input","operation":"replace","value":{"arbitrary":"host schema remains userland"}}]}}`)) {
		t.Fatal("host schema unexpectedly enforced")
	}
}
func TestInvalidEnvelopeStillEmitsStdioError(t *testing.T) {
	h, e := NewHandler(Handlers{}, Options{})
	if e != nil {
		t.Fatal(e)
	}
	in := &readClose{Reader: strings.NewReader("{\"jsonrpc\":\"1.0\",\"id\":\"x\",\"method\":\"hooks/capabilities\",\"params\":{}}\n")}
	out := new(writeClose)
	if e = ServeStdio(context.Background(), in, out, h); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), `"id":null`) || !strings.Contains(out.String(), "-32600") {
		t.Fatal(out.String())
	}
}
func TestInvalidUTF8DoesNotReachCallback(t *testing.T) {
	calls := 0
	h, e := NewHandler(Handlers{Intercept: func(context.Context, ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
		calls++
		return noEffect(), nil
	}}, Options{})
	if e != nil {
		t.Fatal(e)
	}
	b := bytes.Replace(fixture(t, "intercept"), []byte("README.md"), []byte{255}, 1)
	w := request(h, b)
	if calls != 0 || !strings.Contains(w.Body.String(), "-32700") {
		t.Fatal(w.Body.String())
	}
}
func TestUploadExplicitLengthAndRealHTTP(t *testing.T) {
	r := uploadRequest(nil)
	r.Header.Del("Content-Length")
	if _, e := ParseUpload(r, 0); !errors.Is(e, ErrUploadFraming) {
		t.Fatal("accepted absent length", e)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, e := ParseUpload(r, 10)
		if e != nil {
			http.Error(w, "framing", 400)
			return
		}
		defer u.Close()
		if _, e = io.Copy(io.Discard, u); e != nil {
			http.Error(w, "verification", 400)
			return
		}
		ref, e := u.Reference("scoped-ref")
		if e != nil {
			http.Error(w, "ref", 500)
			return
		}
		_ = WriteUploadResponse(w, ref)
	})
	s := httptest.NewServer(h)
	defer s.Close()
	for _, body := range [][]byte{nil, []byte{0, 255, 3}} {
		r, err := http.NewRequest(http.MethodPost, s.URL, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header = uploadRequest(body).Header.Clone()
		response, e := s.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		_ = response.Body.Close()
		if response.StatusCode != 201 {
			t.Fatal(response.StatusCode)
		}
	}
}
func TestStdioBlockedWriteCancellation(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":"x","method":"custom","params":{}}` + "\n"
	outRead, outWrite := io.Pipe()
	defer outRead.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	called := make(chan struct{})
	go func() {
		done <- ServeStdio(ctx, &readClose{Reader: strings.NewReader(input)}, outWrite, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"x","result":{}}`)
			close(called)
		}))
	}()
	<-called
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked write not canceled")
	}
}
