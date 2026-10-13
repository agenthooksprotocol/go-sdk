package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

func TestObserveAnyCatchAll(t *testing.T) {
	var got []ObserveAnyContext
	var diagnostics int
	opts := Options{Diagnostic: func(context.Context, error) { diagnostics++ }}
	h, err := NewHandler(Handlers{Observe: ObserveHandlers{Any: func(_ context.Context, c ObserveAnyContext) error {
		got = append(got, c)
		return nil
	}}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	b := bytes.Replace(fixture(t, "observe"), []byte(`"protocolVersion": "draft",`), []byte(`"protocolVersion": "draft", "x-extra": 1,`), 1)
	w := request(h, b)
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 || diagnostics != 0 {
		t.Fatalf("%d %q diagnostics=%d", w.Code, w.Body, diagnostics)
	}
	if len(got) != 1 || got[0].Type != "tool.after" || got[0].Event == nil || !got[0].Event.ToolAfterEvent.Present || got[0].Event.ToolAfterEvent.Value.Call.ID != "call_observe_789" {
		t.Fatalf("catch-all context: %+v", got)
	}
	if string(got[0].AdditionalProperties["x-extra"]) != "1" {
		t.Fatalf("params extras lost: %v", got[0].AdditionalProperties)
	}
}

func TestObserveAnyOnlyWhenPerEventObserverAbsent(t *testing.T) {
	var specific, catchAll int
	h, err := NewHandler(Handlers{Observe: ObserveHandlers{
		ToolAfter: func(context.Context, ObserveContext[ahp.ToolAfterEvent]) error { specific++; return nil },
		Any:       func(context.Context, ObserveAnyContext) error { catchAll++; return nil },
	}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if w := request(h, fixture(t, "observe")); w.Code != http.StatusNoContent || specific != 1 || catchAll != 0 {
		t.Fatalf("%d specific=%d any=%d", w.Code, specific, catchAll)
	}
}

func TestObserveAnyFailureIsEmptyTransportFailure(t *testing.T) {
	h, err := NewHandler(Handlers{Observe: ObserveHandlers{Any: func(context.Context, ObserveAnyContext) error { return errors.New("SECRET") }}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if w := request(h, fixture(t, "observe")); w.Code != http.StatusInternalServerError || w.Body.Len() != 0 {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
}
