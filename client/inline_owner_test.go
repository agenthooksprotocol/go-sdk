package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/event"
)

func TestInlineDirectHostOwnedAttachment(t *testing.T) {
	c, transports := testClient(t, "fail-closed")
	setDispatchBoundary(c, "model.request.before", map[string]any{"effects": []any{}})
	c.backends[0].subscriptions[0]["content"] = map[string]any{"default": "metadata"}
	opened := 0
	owner := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
		opened++
		return io.NopCloser(strings.NewReader("binary")), nil
	}, nil)
	messages := []*event.ModelVisibleItemInput{{
		ModelVisibleItem: ahp.ModelVisibleItem{Role: ahp.ModelVisibleItemRoleUser},
		Parts: []*event.ContentPartInput{
			{Text: &ahp.TextBodyPart{Text: "review"}},
			{Attachment: &event.AttachmentBodyInput{AttachmentBodyPart: ahp.AttachmentBodyPart{MediaType: "application/pdf"}, Body: owner}},
		},
	}}
	result, err := c.ModelRequestBefore(context.Background(), event.ModelRequestBeforeInput{
		Attempt: &ahp.ExecutionEventAttempt{ID: "attempt", Number: json.Number("1")},
		Model:   &ahp.ExecutionEventModel{ID: "model", Provider: "provider"}, ItemsHost: &messages,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if opened != 0 {
		t.Fatalf("conversion/metadata opened attachment: %d", opened)
	}
	if len(transports[0].calls) != 1 {
		t.Fatalf("delivery: %+v", result.Errors)
	}
	if bytes.Contains(sdkJSON(transports[0].calls[0]), []byte("ahp:owned:pending")) {
		t.Fatal("pending reference reached wire")
	}
	if result.attachments["/items/0/parts/1"] != owner {
		t.Fatal("result lost exact owner")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := result.ReadContent(context.Background(), "/items/0/parts/1")
	if err != nil || string(raw) != "binary" || opened != 1 {
		t.Fatalf("retained owner after shutdown: %q %v %d", raw, err, opened)
	}
}

func TestInlineSuppliedCanonicalValues(t *testing.T) {
	for _, tc := range []struct {
		kind      string
		good, bad any
	}{
		{"context.compact.before", []any{inlineTestText("summary", "summary")}, "summary"},
		{"model.request.before", []any{inlineTestMessage("m", "assistant", inlineTestText("p", "result"))}, map[string]any{"native": "result"}},
	} {
		if err := validateSuppliedValue(tc.kind, tc.good); err != nil {
			t.Fatal(err)
		}
		if err := validateSuppliedValue(tc.kind, tc.bad); err == nil {
			t.Fatal("invalid supplied value accepted")
		}
	}
}

func TestInlineDirectHostSelectedUploadUsesExactOwner(t *testing.T) {
	var uploads atomic.Int32
	opens := 0
	upload := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(raw) != "binary" {
			t.Errorf("uploaded %q", raw)
		}
		uploads.Add(1)
		contentTestConfirm(w, "receiver-ref", raw)
	}))
	defer upload.Close()
	c, transports := testClient(t, "fail-closed", "fail-closed")
	setDispatchBoundary(c, "model.request.before", map[string]any{"effects": []any{"modify"}, "modify": map[string]any{"request": map[string]any{"replace": true, "merge": true}}})
	transports[0].reply = func(request map[string]any) []any {
		received := sdkArray(sdkObj(sdkObj(request["params"])["event"])["items"])
		value := append([]any{inlineTestMessage("prepended", "user", inlineTestText("new", "accepted"))}, received...)
		return []any{map[string]any{"type": "modify", "target": "request", "operation": "replace", "value": value}}
	}
	c.opts.Content.AuthorizeContent = contentTestAllow
	c.opts.Content.Resolver = func(context.Context, string) (io.ReadCloser, error) {
		t.Fatal("selected host owner used descriptor resolver")
		return nil, nil
	}
	c.opts.Content.AllowLoopbackHTTP = true
	for _, backend := range c.backends {
		sub := backend.subscriptions[0]
		config := contentTestSubscription(upload.URL)
		sub["content"], sub["upload"] = config["content"], config["upload"]
	}
	owner := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
		opens++
		return io.NopCloser(strings.NewReader("binary")), nil
	}, nil)
	messages := []*event.ModelVisibleItemInput{{ModelVisibleItem: ahp.ModelVisibleItem{Role: ahp.ModelVisibleItemRoleUser}, Parts: []*event.ContentPartInput{
		{Text: &ahp.TextBodyPart{Text: "review"}},
		{Attachment: &event.AttachmentBodyInput{AttachmentBodyPart: ahp.AttachmentBodyPart{MediaType: "application/pdf"}, Body: owner, Descriptor: &ahp.ContentReference{Ref: "unrelated-host-descriptor"}}},
	}}}
	input := event.ModelRequestBeforeInput{Attempt: &ahp.ExecutionEventAttempt{ID: "attempt", Number: json.Number("1")}, Model: &ahp.ExecutionEventModel{ID: "model", Provider: "provider"}, ItemsHost: &messages}
	if _, err := json.Marshal(input); err != nil {
		t.Fatal(err)
	}
	if opens != 0 || uploads.Load() != 0 {
		t.Fatal("host conversion started I/O")
	}
	result, err := c.ModelRequestBefore(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if len(result.Errors) != 0 || uploads.Load() != 2 || opens != 1 {
		t.Fatalf("selected fan-out: uploads=%d opens=%d errors=%v", uploads.Load(), opens, result.Errors)
	}
	if result.attachments["/items/1/parts/1"] != owner {
		t.Fatal("upload/result owner differs")
	}
	for _, transport := range transports {
		if len(transport.calls) != 1 || bytes.Contains(sdkJSON(transport.calls[0]), []byte("ahp:owned:pending")) {
			t.Fatal("invalid selected delivery")
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := result.ReadContent(context.Background(), "/items/1/parts/1")
	if err != nil || string(raw) != "binary" || opens != 1 {
		t.Fatalf("retained exact owner: %q %v opens=%d", raw, err, opens)
	}
}
