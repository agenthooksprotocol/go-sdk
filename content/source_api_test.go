package content_test

import (
	"context"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/content"
)

// This consumer uses only public API imports. Keep the alias's method set free
// of SDK ownership controls while preserving its ordinary caller operations.
var _ interface {
	Close() error
	Snapshot(context.Context, int64) ([]byte, error)
	Available() ([]byte, bool)
} = (*content.Source)(nil)

func TestSourcePublicMethodSet(t *testing.T) {
	typ := reflect.TypeOf((*content.Source)(nil))
	for _, name := range []string{"Claim", "Claimed", "Retire"} {
		if _, ok := typ.MethodByName(name); ok {
			t.Errorf("SDK lifecycle method %s must not be public", name)
		}
	}
	for _, name := range []string{"Close", "Snapshot", "Available"} {
		if _, ok := typ.MethodByName(name); !ok {
			t.Errorf("public source operation %s is missing", name)
		}
	}
	if got := typ.NumMethod(); got != 3 {
		t.Errorf("public source method count = %d, want 3", got)
	}
}

func TestSourceExternalConsumer(t *testing.T) {
	source := content.NewSource(io.NopCloser(strings.NewReader("body")))
	defer source.Close()
	if _, ok := source.Available(); ok {
		t.Fatal("source is available before materialization")
	}
	raw, err := source.Snapshot(context.Background(), 4)
	if err != nil || string(raw) != "body" {
		t.Fatalf("Snapshot = %q, %v", raw, err)
	}
	if raw, ok := source.Available(); !ok || string(raw) != "body" {
		t.Fatalf("Available = %q, %v", raw, ok)
	}
}
