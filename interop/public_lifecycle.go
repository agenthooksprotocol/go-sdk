package interop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	hooks "github.com/agenthooksprotocol/go-sdk/client"
	"io"
	"net/http"
	"strings"
	"sync"
)

// lifecyclePublicCall leaves fixture release/cancel barriers in the host while
// delegating ordinary envelope construction and acceptance to the SDK.
func lifecyclePublicCall(ctx context.Context, request Object, pipe *lifecyclePipe, httpClient *http.Client, token, endpoint string, options ...PublicBoundaryOptions) (Object, error) {
	var invalidAcknowledgement *lifecycleObservationAcknowledgementError
	exchange := func(ctx context.Context, method string, data []byte) ([]byte, error) {
		var sent Object
		if err := json.Unmarshal(data, &sent); err != nil {
			return nil, err
		}
		reply, err := lifecycleWireCall(ctx, sent, pipe, httpClient, token, endpoint)
		if err != nil {
			// PublicBoundary deliberately redacts transport errors. Retain only
			// this fixture-specific, typed acknowledgement evidence out of band.
			errors.As(err, &invalidAcknowledgement)
			return nil, err
		}
		if method == "hooks/observe" {
			return nil, nil
		}
		return jsonBytes(reply), nil
	}
	// Sending after an already-stopped native prefix is deliberately a lifecycle
	// race probe. The ordinary public runtime correctly emits only observations
	// in this state, so this exact post-settlement probe uses raw delivery.
	state := obj(obj(request["params"])["state"])
	if request["method"] == "hooks/intercept" && (state["flow"] == "stop" || state["permission"] == "deny") {
		raw, err := exchange(ctx, "hooks/intercept", jsonBytes(request))
		var response Object
		if err == nil {
			err = json.Unmarshal(raw, &response)
		}
		return response, err
	}
	response, _, err := PublicBoundary(ctx, request, exchange, options...)
	// The public transport redacts its underlying exchange error. Preserve the
	// fixture wire evidence only after the public boundary reports failure.
	if err != nil && invalidAcknowledgement != nil {
		return nil, invalidAcknowledgement
	}
	return response, err
}

// lifecycleWireCall owns one raw transport exchange, not a Hooks operation. The
// caller supplies the operation context and owns any surrounding test barriers.
// Chain composition must invoke this helper from its one public SDK operation.
func lifecycleWireCall(ctx context.Context, request Object, pipe *lifecyclePipe, httpClient *http.Client, token, endpoint string) (Object, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	method := str(request["method"])
	if pipe != nil {
		if method == "hooks/observe" {
			return nil, pipe.send(request, nil)
		}
		pipe.mu.Lock()
		if pipe.ordinary == nil {
			pipe.ordinary = make(chan struct{}, 1)
			pipe.ordinary <- struct{}{}
		}
		slot := pipe.ordinary
		pipe.mu.Unlock()
		select {
		case <-slot:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		defer func() { slot <- struct{}{} }()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		done := make(chan lifecycleResult, 1)
		if err := pipe.send(request, done); err != nil {
			pipe.retire(lifecycleID(request), done)
			return nil, err
		}
		select {
		case reply := <-done:
			return reply.response, reply.err
		case <-ctx.Done():
			// Remove only this subscription. An eventual frame is discarded by
			// the shared reader, never left on an abandoned per-call goroutine.
			pipe.retire(lifecycleID(request), done)
			return nil, ctx.Err()
		}
	}
	path := "/intercept"
	if method == "hooks/observe" {
		path = "/observe"
	}
	reply, status, err := lifecycleCallWith(ctx, httpClient, token, endpoint+path, request)
	if err != nil {
		return nil, err
	}
	if method == "hooks/intercept" && status != http.StatusOK {
		return nil, fmt.Errorf("intercept HTTP %d", status)
	}
	if method == "hooks/observe" {
		if (status != http.StatusAccepted && status != http.StatusNoContent) || reply != nil {
			return nil, &lifecycleObservationAcknowledgementError{Status: status, Response: reply}
		}
		return nil, nil
	}
	return reply, nil
}

// Snapshot only the authorized subscription's confirmed immutable uploads.
func lifecycleContentOptions(c LifecycleConfig, sub string, confirmed map[string]string, events ...Object) PublicBoundaryOptions {
	bodies := map[string]string{}
	prefix := contentKey(sub, "")
	for key, body := range confirmed {
		if strings.HasPrefix(key, prefix) {
			bodies[strings.TrimPrefix(key, prefix)] = body
		}
	}
	cache := &confirmedUploadTransport{bodies: bodies}
	options := PublicBoundaryOptions{Content: hooks.ContentOptions{AllowLoopbackHTTP: true, Resolver: func(_ context.Context, ref string) (io.ReadCloser, error) {
		body, ok := bodies[ref]
		if !ok {
			return nil, fmt.Errorf("unconfirmed content reference")
		}
		cache.mu.Lock()
		cache.reference = ref
		cache.mu.Unlock()
		return io.NopCloser(bytes.NewBufferString(body)), nil
	}}}
	binding, ok := c.Uploads[sub]
	if !ok && len(c.Uploads) == 0 && c.Upload.Endpoint != "" {
		binding = c.Upload
		ok = true
	}
	if ok {
		if binding.TimeoutMs <= 0 {
			binding.TimeoutMs = 5000
		}
		if binding.MaxBytes == nil {
			limit := int64(4 << 20)
			binding.MaxBytes = &limit
		}
		var upload Object
		_ = json.Unmarshal(jsonBytes(binding), &upload)
		options.Upload = upload
		cache.endpoint = binding.Endpoint
		options.UploadClient = &http.Client{Transport: cache}
	}
	return options
}

// confirmedUploadTransport is a host transport cache of real, earlier successful
// uploads in this receiver subscription scope. It does not mint references or authorize
// new bytes: the SDK still resolves, bounds, hashes, and validates confirmation.
// Reusing these confirmations preserves immutable fixture references and avoids
// manufacturing additional upload operations in a controlled lifecycle schedule.
type confirmedUploadTransport struct {
	endpoint  string
	bodies    map[string]string
	mu        sync.Mutex
	reference string // exact immutable ref most recently resolved for this projection
}

func (t *confirmedUploadTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(io.LimitReader(request.Body, (4<<20)+1))
	if err != nil {
		return nil, err
	}
	if request.URL.String() != t.endpoint || len(raw) > 4<<20 {
		return nil, fmt.Errorf("upload cache scope mismatch")
	}
	t.mu.Lock()
	ref := t.reference
	t.mu.Unlock()
	if body, ok := t.bodies[ref]; !ok || body != string(raw) {
		return nil, fmt.Errorf("upload has no prior scoped confirmation")
	}
	response := Object{"ref": ref, "size": len(raw), "sha256": fmt.Sprintf("%x", sha256.Sum256(raw))}
	return &http.Response{StatusCode: 201, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(jsonBytes(response))), Request: request}, nil
}

// A failed acknowledgement is diagnostic evidence, not an interception result.
// Keep the malicious envelope intact; never pass its effects to composition.
type lifecycleObservationAcknowledgementError struct {
	Status   int
	Response Object
}

func (e *lifecycleObservationAcknowledgementError) Error() string {
	return fmt.Sprintf("invalid observation acknowledgement: HTTP %d, body=%s", e.Status, jsonBytes(e.Response))
}
