package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/content"
)

func uploadPlanClient(t *testing.T, endpoint string, limit int, policies ...string) (*Hooks, []*testTransport) {
	t.Helper()
	base, _ := testClient(t, policies...)
	caps := targetTestCaps("request")
	caps["effects"] = []any{"modify", "message", "deny"}
	setDispatchBoundary(base, "model.request.before", caps)
	var manifest ahp.StaticCapabilityManifest
	if err := json.Unmarshal(sdkJSON(base.manifest), &manifest); err != nil {
		t.Fatal(err)
	}
	hooks := []any{}
	for i, policy := range policies {
		sub := contentTestSubscription(endpoint)
		sub["events"], sub["mode"], sub["failurePolicy"] = []any{"model.request.before"}, "intercept", policy
		sub["timeoutMs"] = 1000
		hooks = append(hooks, map[string]any{"id": fmt.Sprintf("com.example.plan%d", i), "transport": map[string]any{"type": "http", "url": "http://127.0.0.1/hooks"}, "subscriptions": []any{sub}})
	}
	reg := ahp.ParseRegistration(sdkJSON(map[string]any{"protocolVersion": "draft", "hooks": hooks}))
	if !reg.OK {
		t.Fatal(reg.Diagnostics)
	}
	c, err := New(reg.Value, Options{Source: "urn:test:upload-plan", Manifest: manifest, MaxConcurrentUploads: limit, Content: ContentOptions{AuthorizeContent: contentTestAllow, AllowLoopbackHTTP: true, ProjectOpaque: base.opts.Content.ProjectOpaque}})
	if err != nil {
		t.Fatal(err)
	}
	setDispatchBoundary(c, "model.request.before", caps)
	trs := make([]*testTransport, len(c.backends))
	for i := range c.backends {
		_ = c.backends[i].transport.Close()
		trs[i] = &testTransport{}
		c.backends[i].transport = trs[i]
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, trs
}

func uploadPlanInput(t *testing.T) map[string]any {
	t.Helper()
	attachment := contentTestItem(nil)
	delete(attachment, "body")
	attachment["selection"] = "metadata"
	input := targetTestCanonicalEvent(t, "model.request.before", []any{targetInlineMessage("message", targetInlineText("text", "inline text"), attachment)})
	delete(input, "source")
	delete(input, "type")
	return input
}

const uploadPlanPath = "/items/0/parts/1"

func TestUploadPlanOverlapCapAndReceiptBarrier(t *testing.T) {
	for _, tc := range []struct {
		name             string
		configured, want int
	}{{"explicit", 2, 2}, {"default", 0, 8}} {
		t.Run(tc.name, func(t *testing.T) {
			var active, peak, receipts, callbacks atomic.Int32
			entered := make(chan struct{}, 10)
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := active.Add(1)
				for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
				}
				entered <- struct{}{}
				<-release
				raw, _ := io.ReadAll(r.Body)
				active.Add(-1)
				receipts.Add(1)
				contentTestConfirm(w, fmt.Sprintf("receipt-%d", receipts.Load()), raw)
			}))
			defer server.Close()
			policies := make([]string, 10)
			for i := range policies {
				policies[i] = "fail-closed"
			}
			c, trs := uploadPlanClient(t, server.URL, tc.configured, policies...)
			for _, tr := range trs {
				tr.reply = func(map[string]any) []any {
					callbacks.Add(1)
					if receipts.Load() != 10 {
						t.Errorf("interceptor preceded receipt barrier: %d", receipts.Load())
					}
					return []any{}
				}
			}
			done := make(chan error, 1)
			go func() {
				result, err := c.Dispatch(context.Background(), "model.request.before", uploadPlanInput(t), WithContentSource(uploadPlanPath, content.NewAttachment([]byte("body"))))
				if result != nil {
					if len(result.Errors) != 0 {
						err = fmt.Errorf("delivery errors: %v", result.Errors)
					}
					_ = result.Close()
				}
				done <- err
			}()
			for i := 0; i < tc.want; i++ {
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					close(release)
					t.Fatal("uploads did not overlap")
				}
			}
			select {
			case <-entered:
				t.Error("upload concurrency exceeded cap")
			case <-time.After(30 * time.Millisecond):
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if peak.Load() != int32(tc.want) || receipts.Load() != 10 || callbacks.Load() != 10 {
				t.Fatalf("peak=%d receipts=%d callbacks=%d", peak.Load(), receipts.Load(), callbacks.Load())
			}
		})
	}
}

func TestUploadPlanSharedLazyOwnerAndObservationReuse(t *testing.T) {
	var uploads, opens atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		uploads.Add(1)
		contentTestConfirm(w, fmt.Sprintf("ref-%d", uploads.Load()), raw)
	}))
	defer server.Close()
	c, trs := uploadPlanClient(t, server.URL, 2, "fail-closed", "fail-closed")
	trs[0].reply = func(map[string]any) []any { return []any{map[string]any{"type": "deny", "reason": "stop"}} }
	source := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
		opens.Add(1)
		return io.NopCloser(strings.NewReader("body")), nil
	}, nil)
	result, err := c.Dispatch(context.Background(), "model.request.before", uploadPlanInput(t), WithContentSource(uploadPlanPath, source))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	waitObservations(t, result)
	if opens.Load() != 1 || uploads.Load() != 2 {
		t.Fatalf("opens=%d uploads=%d", opens.Load(), uploads.Load())
	}
	for i, tr := range trs {
		tr.mu.Lock()
		calls := append([]map[string]any(nil), tr.calls...)
		tr.mu.Unlock()
		if len(calls) != 1 {
			t.Fatalf("backend %d calls=%d", i, len(calls))
		}
		want := "hooks/intercept"
		if i == 1 {
			want = "hooks/observe"
		}
		if calls[0]["method"] != want {
			t.Fatalf("backend %d method=%v", i, calls[0]["method"])
		}
		wire := string(sdkJSON(calls[0]))
		if !strings.Contains(wire, "ref-") {
			t.Errorf("backend %d missing confirmed receipt", i)
		}
	}
}

func TestUploadPlanNoAuthorizedDemandLeavesLazyBodyUnread(t *testing.T) {
	for _, mode := range []string{"metadata", "unauthorized", "inline"} {
		t.Run(mode, func(t *testing.T) {
			c, trs := uploadPlanClient(t, "http://127.0.0.1:1/upload", 2, "fail-open")
			if mode == "metadata" {
				c.backends[0].subscriptions[0]["content"] = map[string]any{"default": "metadata"}
			}
			if mode == "unauthorized" {
				c.opts.Content.AuthorizeContent = func(context.Context, ContentAuthorization) (bool, error) { return false, nil }
			}
			var opens atomic.Int32
			source := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
				opens.Add(1)
				return io.NopCloser(strings.NewReader("body")), nil
			}, nil)
			input := uploadPlanInput(t)
			opts := []InterceptOption{WithContentSource(uploadPlanPath, source)}
			if mode == "inline" {
				input = targetTestCanonicalEvent(t, "model.request.before", []any{targetInlineMessage("message", targetInlineText("text", "inline only"))})
				opts = nil
				delete(input, "source")
				delete(input, "type")
			}
			result, err := c.Dispatch(context.Background(), "model.request.before", input, opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer result.Close()
			if opens.Load() != 0 || len(trs[0].calls) != 1 || len(result.Errors) != 0 {
				t.Fatalf("opens=%d callbacks=%d errors=%v", opens.Load(), len(trs[0].calls), result.Errors)
			}
		})
	}
}

func TestUploadPlanLaterFailureDoesNotPreemptHealthyInterceptor(t *testing.T) {
	for _, policy := range []string{"fail-open", "fail-closed"} {
		t.Run(policy, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				contentTestConfirm(w, "healthy-ref", raw)
			}))
			defer server.Close()
			c, trs := uploadPlanClient(t, server.URL, 2, "fail-closed", policy)
			// A separate receiver guarantees failure without depending on upload order.
			failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "failed", http.StatusBadRequest) }))
			defer failing.Close()
			c.backends[1].subscriptions[0]["upload"].(map[string]any)["endpoint"] = failing.URL
			result, err := c.Dispatch(context.Background(), "model.request.before", uploadPlanInput(t), WithContentSource(uploadPlanPath, content.NewAttachment([]byte("body"))))
			if err != nil {
				t.Fatal(err)
			}
			defer result.Close()
			if len(trs[0].calls) != 1 || len(trs[1].calls) != 0 || len(result.Errors) != 1 {
				t.Fatalf("callbacks=%d/%d errors=%v", len(trs[0].calls), len(trs[1].calls), result.Errors)
			}
			if (result.State.Permission == "deny") != (policy == "fail-closed") {
				t.Fatalf("permission=%s policy=%s", result.State.Permission, policy)
			}
		})
	}
}

func TestUploadPlanNegativeLimitRejected(t *testing.T) {
	base, _ := testClient(t, "fail-open")
	reg := ahp.ParseRegistration(sdkJSON(map[string]any{"protocolVersion": "draft", "hooks": []any{}}))
	if !reg.OK {
		t.Fatal(reg.Diagnostics)
	}
	c, err := New(reg.Value, Options{Source: "urn:test:upload-plan", Manifest: base.opts.Manifest, MaxConcurrentUploads: -1})
	if c != nil {
		_ = c.Close()
	}
	if err == nil {
		t.Fatal("negative upload limit accepted")
	}
}

func TestUploadPlanRemovalDoesNotReuploadOrRestoreAttachment(t *testing.T) {
	var uploads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		uploads.Add(1)
		contentTestConfirm(w, "receipt", raw)
	}))
	defer server.Close()
	c, trs := uploadPlanClient(t, server.URL, 2, "fail-closed", "fail-closed")
	replacement := []any{targetInlineMessage("message", targetInlineText("text", "inline text"))}
	trs[0].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "modify", "target": "request", "operation": "replace", "value": replacement}}
	}
	trs[1].reply = func(req map[string]any) []any {
		wire := string(sdkJSON(sdkObj(req["params"])["event"]))
		if strings.Contains(wire, "attachment") || strings.Contains(wire, "receipt") {
			t.Errorf("removed attachment restored: %s", wire)
		}
		return []any{}
	}
	result, err := c.Dispatch(context.Background(), "model.request.before", uploadPlanInput(t), WithContentSource(uploadPlanPath, content.NewAttachment([]byte("body"))))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if len(result.Errors) != 0 || len(trs[1].calls) != 1 || uploads.Load() != 2 {
		t.Fatalf("uploads=%d later callbacks=%d errors=%v", uploads.Load(), len(trs[1].calls), result.Errors)
	}
	if strings.Contains(string(result.Event), "attachment") {
		t.Fatal("settled event retains removed attachment")
	}
}

func TestUploadPlanCredentialsAndReceiptsRemainSubscriptionScoped(t *testing.T) {
	t.Setenv("AHP_PLAN_TOKEN_ONE", "one")
	t.Setenv("AHP_PLAN_TOKEN_TWO", "two")
	var uploads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		uploads.Add(1)
		token := r.Header.Get("Authorization")
		if token != "Bearer one" && token != "Bearer two" {
			t.Errorf("wrong upload credential: %q", token)
		}
		contentTestConfirm(w, "ref-"+strings.TrimPrefix(token, "Bearer "), raw)
	}))
	defer server.Close()
	// Identical URL and owner do not combine even two subscriptions on one backend.
	c, trs := uploadPlanClient(t, server.URL, 2, "fail-closed")
	first := c.backends[0].subscriptions[0]
	second := contentClone(first).(map[string]any)
	second["id"] = "subscription-2"
	c.backends[0].subscriptions = append(c.backends[0].subscriptions, second)
	first["upload"].(map[string]any)["auth"] = map[string]any{"type": "bearer", "tokenEnv": "AHP_PLAN_TOKEN_ONE"}
	second["upload"].(map[string]any)["auth"] = map[string]any{"type": "bearer", "tokenEnv": "AHP_PLAN_TOKEN_TWO"}
	var callbacks int
	trs[0].reply = func(req map[string]any) []any {
		callbacks++
		want := "ref-one"
		if callbacks == 2 {
			want = "ref-two"
		}
		if !strings.Contains(string(sdkJSON(sdkObj(req["params"])["event"])), want) {
			t.Errorf("callback %d missing scoped %s", callbacks, want)
		}
		return []any{}
	}
	result, err := c.Dispatch(context.Background(), "model.request.before", uploadPlanInput(t), WithContentSource(uploadPlanPath, content.NewAttachment([]byte("body"))))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if uploads.Load() != 2 || callbacks != 2 || len(result.Errors) != 0 {
		t.Fatalf("uploads=%d callbacks=%d errors=%v", uploads.Load(), callbacks, result.Errors)
	}
}

func TestUploadPlanSharedDemandReceiverLimitsAreIndependent(t *testing.T) {
	for _, constraint := range []string{"timeout", "maxBytes"} {
		t.Run(constraint, func(t *testing.T) {
			var uploads, opens, cancelled atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				uploads.Add(1)
				contentTestConfirm(w, "healthy-receipt", raw)
			}))
			defer server.Close()
			c, trs := uploadPlanClient(t, server.URL, 2, "fail-open", "fail-closed")
			short := c.backends[0].subscriptions[0]["upload"].(map[string]any)
			healthy := c.backends[1].subscriptions[0]["upload"].(map[string]any)
			healthy["maxBytes"], healthy["timeoutMs"] = 100, 1000
			if constraint == "timeout" {
				short["timeoutMs"] = 20
			} else {
				short["maxBytes"] = 2
			}
			source := content.NewLazyAttachment(func(ctx context.Context) (io.ReadCloser, error) {
				opens.Add(1)
				if constraint == "timeout" {
					timer := time.NewTimer(60 * time.Millisecond)
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						cancelled.Add(1)
						return nil, ctx.Err()
					}
				}
				return io.NopCloser(strings.NewReader("body")), nil
			}, nil)
			result, err := c.Dispatch(context.Background(), "model.request.before", uploadPlanInput(t), WithContentSource(uploadPlanPath, source))
			if err != nil {
				t.Fatal(err)
			}
			defer result.Close()
			if opens.Load() != 1 || cancelled.Load() != 0 || uploads.Load() != 1 {
				t.Fatalf("opens=%d cancelled=%d uploads=%d", opens.Load(), cancelled.Load(), uploads.Load())
			}
			if len(trs[0].calls) != 0 || len(trs[1].calls) != 1 || len(result.Errors) != 1 || result.State.Permission == "deny" {
				t.Fatalf("callbacks=%d/%d errors=%v permission=%s", len(trs[0].calls), len(trs[1].calls), result.Errors, result.State.Permission)
			}
			if raw, err := result.ReadContent(context.Background(), uploadPlanPath); err != nil || string(raw) != "body" {
				t.Fatalf("shared owner lost healthy bytes: %q %v", raw, err)
			}
		})
	}
}

type uploadPlanCountingReader struct {
	io.Reader
	bytes, closes atomic.Int32
}

func (r *uploadPlanCountingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytes.Add(int32(n))
	return n, err
}
func (r *uploadPlanCountingReader) Close() error { r.closes.Add(1); return nil }

func TestUploadPlanOnlyTinyDemandBoundsLazyRead(t *testing.T) {
	var uploads, opens atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploads.Add(1)
		raw, _ := io.ReadAll(r.Body)
		contentTestConfirm(w, "unexpected-receipt", raw)
	}))
	defer server.Close()
	c, trs := uploadPlanClient(t, server.URL, 2, "fail-open")
	c.backends[0].subscriptions[0]["upload"].(map[string]any)["maxBytes"] = 2
	reader := &uploadPlanCountingReader{Reader: strings.NewReader("body-and-many-more-bytes")}
	source := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) { opens.Add(1); return reader, nil }, nil)
	result, err := c.Dispatch(context.Background(), "model.request.before", uploadPlanInput(t), WithContentSource(uploadPlanPath, source))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if opens.Load() != 1 || reader.bytes.Load() > 3 || reader.closes.Load() != 1 || uploads.Load() != 0 || len(trs[0].calls) != 0 || len(result.Errors) != 1 {
		t.Fatalf("opens=%d bytes=%d closes=%d uploads=%d callbacks=%d errors=%v", opens.Load(), reader.bytes.Load(), reader.closes.Load(), uploads.Load(), len(trs[0].calls), result.Errors)
	}
}

func TestUploadPlanCancellationJoinsSharedMaterialization(t *testing.T) {
	c, trs := uploadPlanClient(t, "http://127.0.0.1:1/upload", 2, "fail-open", "fail-closed")
	entered, exited := make(chan struct{}), make(chan struct{})
	var opens, cleaned atomic.Int32
	source := content.NewLazyAttachment(func(ctx context.Context) (io.ReadCloser, error) {
		opens.Add(1)
		close(entered)
		defer close(exited)
		<-ctx.Done()
		return nil, ctx.Err()
	}, func() error { cleaned.Add(1); return nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input := uploadPlanInput(t)
	done := make(chan error, 1)
	go func() {
		result, err := c.Dispatch(ctx, "model.request.before", input, WithContentSource(uploadPlanPath, source))
		if result != nil {
			_ = result.Close()
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("shared materialization did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dispatch cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled materialization did not join")
	}
	select {
	case <-exited:
	default:
		t.Fatal("dispatch returned before opener exited")
	}
	if opens.Load() != 1 || cleaned.Load() != 1 || len(trs[0].calls) != 0 || len(trs[1].calls) != 0 {
		t.Fatalf("opens=%d cleanup=%d callbacks=%d/%d", opens.Load(), cleaned.Load(), len(trs[0].calls), len(trs[1].calls))
	}
}

type uploadPlanBlockingTransport struct {
	entered        chan struct{}
	active, exited atomic.Int32
}

func (tr *uploadPlanBlockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.active.Add(1)
	defer func() { tr.active.Add(-1); tr.exited.Add(1) }()
	tr.entered <- struct{}{}
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestUploadPlanHooksCloseJoinsConcurrentTransfers(t *testing.T) {
	c, trs := uploadPlanClient(t, "http://127.0.0.1:1/upload", 2, "fail-open", "fail-closed")
	blocking := &uploadPlanBlockingTransport{entered: make(chan struct{}, 2)}
	c.opts.UploadClient = &http.Client{Transport: blocking}
	input := uploadPlanInput(t)
	source := content.NewAttachment([]byte("body"))
	done := make(chan error, 1)
	go func() {
		result, err := c.Dispatch(context.Background(), "model.request.before", input, WithContentSource(uploadPlanPath, source))
		if result != nil {
			_ = result.Close()
		}
		done <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-blocking.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent transfers did not start")
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Hooks.Close did not join transfers")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("closed dispatch: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch did not retire")
	}
	if blocking.active.Load() != 0 || blocking.exited.Load() != 2 || len(trs[0].calls) != 0 || len(trs[1].calls) != 0 {
		t.Fatalf("active=%d exited=%d callbacks=%d/%d", blocking.active.Load(), blocking.exited.Load(), len(trs[0].calls), len(trs[1].calls))
	}
}

func TestUploadPlanReadyOwnerUploadsBeforeUnrelatedMaterialization(t *testing.T) {
	fastUploaded := make(chan struct{})
	var uploads, fastOpens, slowOpens atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upload: %v", err)
			return
		}
		switch string(raw) {
		case "fast-file":
			uploads.Add(1)
			contentTestConfirm(w, "fast-file-receipt", raw)
			close(fastUploaded)
		case "slow-image":
			uploads.Add(1)
			contentTestConfirm(w, "slow-image-receipt", raw)
		default:
			t.Errorf("unexpected upload: %q", raw)
			http.Error(w, "unexpected body", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	c, trs := uploadPlanClient(t, server.URL, 2, "fail-closed", "fail-closed")
	c.backends[0].subscriptions[0]["content"] = map[string]any{"default": "metadata", "files": "body"}
	c.backends[1].subscriptions[0]["content"] = map[string]any{"default": "metadata", "images": "body"}
	c.backends[0].subscriptions[0]["upload"].(map[string]any)["timeoutMs"] = 100
	c.backends[1].subscriptions[0]["upload"].(map[string]any)["timeoutMs"] = 1000
	for _, tr := range trs {
		tr.reply = func(map[string]any) []any {
			if uploads.Load() != 2 {
				t.Errorf("interceptor preceded both uploads: %d", uploads.Load())
			}
			return []any{}
		}
	}
	fast := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
		fastOpens.Add(1)
		return io.NopCloser(strings.NewReader("fast-file")), nil
	}, nil)
	slow := content.NewLazyAttachment(func(ctx context.Context) (io.ReadCloser, error) {
		slowOpens.Add(1)
		// This dependency detects an all-owner materialization barrier: the fast
		// destination must receive its upload while this unrelated opener waits.
		waitCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		select {
		case <-fastUploaded:
			return io.NopCloser(strings.NewReader("slow-image")), nil
		case <-waitCtx.Done():
			return nil, waitCtx.Err()
		}
	}, nil)
	input := uploadPlanInput(t)
	parts := sdkObj(input["items"].([]any)[0])["parts"].([]any)
	file := sdkObj(parts[1])
	file["id"], file["category"] = "fast-file", "files"
	image := map[string]any{"id": "slow-image", "kind": "attachment", "mediaType": "image/png", "category": "images", "selection": "metadata"}
	sdkObj(input["items"].([]any)[0])["parts"] = append(parts, image)
	result, err := c.Dispatch(context.Background(), "model.request.before", input, WithContentSource(uploadPlanPath, fast), WithContentSource("/items/0/parts/2", slow))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if uploads.Load() != 2 || fastOpens.Load() != 1 || slowOpens.Load() != 1 || len(result.Errors) != 0 || len(trs[0].calls) != 1 || len(trs[1].calls) != 1 {
		t.Fatalf("uploads=%d opens=%d/%d callbacks=%d/%d errors=%v", uploads.Load(), fastOpens.Load(), slowOpens.Load(), len(trs[0].calls), len(trs[1].calls), result.Errors)
	}
}
