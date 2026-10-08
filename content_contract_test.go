package ahp_test

import (
	"encoding/json"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

func TestContentReferenceAndReceiptBoundaries(t *testing.T) {
	hash := strings.Repeat("a", 64)
	receiptJSON := []byte(`{"ref":"opaque","size":3,"sha256":"` + hash + `"}`)
	receipt := ahp.ParseContentUploadReceipt(receiptJSON)
	if !receipt.OK {
		t.Fatal(receipt.Diagnostics)
	}
	if err := canonical.Validate("content-upload-receipt", receiptJSON); err != nil {
		t.Fatal(err)
	}
	ref := content.ReferenceFromReceipt(receipt.Value)
	raw, err := ahp.EncodeContentReference(ref)
	if err != nil || string(raw) != `{"ref":"opaque"}` {
		t.Fatalf("receipt metadata escaped into reference: %s %v", raw, err)
	}
	if !ahp.ParseContentReference(raw).OK || canonical.Validate("content-reference", raw) != nil {
		t.Fatal("ref-only reference rejected")
	}
	if ahp.ParseContentUploadReceipt(raw).OK || canonical.Validate("content-upload-receipt", raw) == nil {
		t.Fatal("ref-only upload confirmation accepted")
	}
	for _, deprecated := range []string{`"size":null`, `"sha256":null`, `"size":3`, `"sha256":"` + hash + `"`, `"size":3,"sha256":"` + hash + `"`} {
		old := []byte(`{"ref":"opaque",` + deprecated + `}`)
		if ahp.ParseContentReference(old).OK || canonical.Validate("content-reference", old) == nil {
			t.Fatalf("deprecated reference metadata accepted: %s", old)
		}
	}
}

// Both actual request envelopes must expose the same public Event type, not
// independently generated event unions requiring caller-side adapters.
func TestSharedRequestEventConsumer(t *testing.T) {
	consume := func(event *ahp.Event) []byte {
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	event := `{"id":"event","source":"urn:test:host","time":"2026-09-15T12:00:00Z","type":"user.message.inbound","session":{"id":"session"},"message":{"channel":"chat","sender":"user","text":[{"id":"item","kind":"text","mediaType":"text/plain","role":"user","selection":"body","body":{"ref":"opaque"}}]}}`
	intercept := func(event string) []byte {
		return []byte(`{"jsonrpc":"2.0","id":"event","method":"hooks/intercept","params":{"protocolVersion":"draft","event":` + event + `,"capabilities":{"effects":[]}}}`)
	}
	observe := func(event string) []byte {
		return []byte(`{"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":` + event + `}}`)
	}
	observeOnly := `{"id":"event","source":"urn:test:host","time":"2026-09-15T12:00:00Z","type":"session.end","session":{"id":"session"},"outcome":"completed","reason":"done"}`
	if !ahp.ParseEvent([]byte(observeOnly)).OK || !ahp.ParseObserveNotification(observe(observeOnly)).OK || canonical.Validate("observe-notification", observe(observeOnly)) != nil {
		t.Fatal("valid observe-only event rejected")
	}
	if ahp.ParseInterceptRequest(intercept(observeOnly)).OK || canonical.Validate("intercept-request", intercept(observeOnly)) == nil {
		t.Fatal("shared Event erased intercept known-event subset")
	}
	i := ahp.ParseInterceptRequest(intercept(event))
	o := ahp.ParseObserveNotification(observe(event))
	if err := canonical.Validate("intercept-request", intercept(event)); err != nil {
		t.Fatal(err)
	}
	if err := canonical.Validate("observe-notification", observe(event)); err != nil {
		t.Fatal(err)
	}
	if !i.OK || !o.OK {
		t.Fatalf("shared event request rejected: %v %v", i.Diagnostics, o.Diagnostics)
	}
	if string(consume(i.Value.Params.Event)) != string(consume(o.Value.Params.Event)) {
		t.Fatal("shared event changed across envelopes")
	}
	for _, changed := range []string{
		strings.Replace(event, `"ref":"opaque"`, `"ref":"opaque","size":null`, 1),
		strings.Replace(event, `"ref":"opaque"`, `"ref":"opaque","sha256":null`, 1),
		strings.Replace(event, `"selection":"body"`, `"selection":"body","size":null`, 1),
		strings.Replace(event, `"selection":"body"`, `"selection":"body","sha256":null`, 1),
		strings.Replace(event, `"ref":"opaque"`, `"ref":"opaque","size":3`, 1),
		strings.Replace(event, `"selection":"body"`, `"selection":"body","size":3`, 1),
		strings.Replace(event, `"selection":"body"`, `"selection":"body","sha256":"`+strings.Repeat("a", 64)+`"`, 1),
	} {
		if ahp.ParseInterceptRequest(intercept(changed)).OK || ahp.ParseObserveNotification(observe(changed)).OK {
			t.Fatal("deprecated event metadata accepted structurally")
		}
		if canonical.Validate("intercept-request", intercept(changed)) == nil || canonical.Validate("observe-notification", observe(changed)) == nil {
			t.Fatal("deprecated event metadata accepted canonically")
		}
	}
}

func TestMetadataOnlyAndGapKeepDisclosure(t *testing.T) {
	for _, selected := range []string{`"selection":"metadata"`, `"selection":"body","gap":{"reason":"withheld"}`} {
		raw := []byte(`{"id":"item","kind":"text","mediaType":"text/plain","size":3,"sha256":"` + strings.Repeat("a", 64) + `",` + selected + `}`)
		if !ahp.ParseContentItem(raw).OK {
			t.Fatalf("metadata disclosure rejected structurally: %s", raw)
		}
		if err := canonical.Validate("content-item", raw); err != nil {
			t.Fatal(err)
		}
	}
}
