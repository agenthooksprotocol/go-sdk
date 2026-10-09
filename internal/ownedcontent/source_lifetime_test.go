package ownedcontent

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestRetireReleasesRetainedSource(t *testing.T) {
	s := NewSource(io.NopCloser(strings.NewReader("original")))
	raw, err := s.Snapshot(context.Background(), 64)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := s.Snapshot(context.Background(), 64); err != nil || string(again) != "original" {
		t.Fatal("close broke fan-out", err)
	}
	if err := s.Retire(); err != nil {
		t.Fatal(err)
	}
	if s.raw != nil || s.reader != nil {
		t.Fatal("retired source retains storage")
	}
	if _, ok := s.Available(); ok {
		t.Fatal("retired snapshot available")
	}
	if _, err := s.Snapshot(context.Background(), 64); err == nil {
		t.Fatal("retired source readable")
	}
	if s.Claim() {
		t.Fatal("retired source reusable")
	}
	if string(raw) != "original" {
		t.Fatal("detached snapshot invalidated")
	}
	if err := s.Retire(); err != nil {
		t.Fatal(err)
	}
}

func TestRetireInterruptsActiveSnapshot(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	s := NewSource(r)
	done := make(chan error, 1)
	go func() { _, err := s.Snapshot(context.Background(), 64); done <- err }()
	// Writing one byte joins the active read before retirement interrupts its EOF wait.
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := s.Retire(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("interrupted snapshot succeeded")
	}
	if s.reader != nil || s.raw != nil {
		t.Fatal("active snapshot retained storage")
	}
}
