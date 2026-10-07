package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hostTestPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "state.json")
}
func hostTestMessage(source, id, parent string) O {
	return O{"id": id, "params": O{"event": O{"source": source, "id": id, "parentEventId": parent}}}
}
func hostTestOpen(t *testing.T, path string) *hostState {
	t.Helper()
	s, err := openHostState(context.Background(), "https://example.invalid/hooks", "secret-token", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func TestHostStatePersistenceCorrelationAndOwnership(t *testing.T) {
	path := hostTestPath(t)
	s := hostTestOpen(t, path)
	p := pinnedRequest{Request: hostTestMessage("source", "req", ""), Bodies: map[string][]byte{"original": {0, 255, '\n', ' '}}}
	if err := s.put(p); err != nil {
		t.Fatal(err)
	}
	if err := s.put(p); err != nil {
		t.Fatalf("identical request: %v", err)
	}
	// Neither caller inputs nor returned snapshots can mutate the pinned original.
	p.Bodies["original"][0] = 7
	p.Request["extra"] = "mutation"
	if err := s.put(p); err == nil {
		t.Fatal("changed duplicate accepted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = hostTestOpen(t, path)
	result := hostTestMessage("source", "res", "req")
	got, err := s.get(result)
	if err != nil {
		t.Fatal(err)
	}
	if got.Request["extra"] != nil || !bytes.Equal(got.Bodies["original"], []byte{0, 255, '\n', ' '}) {
		t.Fatal("original changed")
	}
	got.Bodies["original"][0] = 3
	got.Request["extra"] = "changed"
	again, err := s.get(result)
	if err != nil || again.Bodies["original"][0] != 0 || again.Request["extra"] != nil {
		t.Fatal("get aliases storage")
	}
	for _, r := range []O{hostTestMessage("other", "res", "req"), hostTestMessage("source", "req", "missing"), hostTestMessage("source", "req", "")} {
		if _, err := s.get(r); err == nil {
			t.Fatal("uncorrelated result found original")
		}
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret-token")) || bytes.Contains(raw, []byte("https://example.invalid/hooks")) {
		t.Fatal("credential or endpoint persisted")
	}
	info, _ := os.Stat(s.path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("public state file")
	}
	if err := s.remove(result); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = hostTestOpen(t, path)
	if _, err := s.get(result); err == nil {
		t.Fatal("consumed request remains")
	}
}
func TestHostStateScopeAndLockCancellation(t *testing.T) {
	path := hostTestPath(t)
	s := hostTestOpen(t, path)
	if err := s.put(pinnedRequest{Request: hostTestMessage("source", "req", "")}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, err := openHostState(ctx, "endpoint", "token", path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock cancellation: %v", err)
	}
	s.Close()
	for _, pair := range [][2]string{{"https://example.invalid/hooks", "other"}, {"other", "secret-token"}} {
		if other, err := openHostState(context.Background(), pair[0], pair[1], path); err == nil {
			other.Close()
			t.Fatal("scope mismatch accepted")
		}
	}
}
func TestHostStateLimitsAndExpiry(t *testing.T) {
	s := hostTestOpen(t, hostTestPath(t))
	for i := 0; i < hostStateMaxRecords; i++ {
		if err := s.put(pinnedRequest{Request: hostTestMessage("source", fmt.Sprint(i), "")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.put(pinnedRequest{Request: hostTestMessage("source", "overflow", "")}); err == nil {
		t.Fatal("record limit ignored")
	}
	key, _ := hostKey(hostTestMessage("source", "0", ""), false)
	r := s.disk.Records[key]
	r.Expires = time.Now().Add(-time.Second)
	s.disk.Records[key] = r
	if err := s.write(); err != nil {
		t.Fatal(err)
	}
	path := s.path
	s.Close()
	s = hostTestOpen(t, path)
	if _, err := s.get(hostTestMessage("source", "res", "0")); err == nil {
		t.Fatal("expired request found")
	}
	if err := s.put(pinnedRequest{Request: hostTestMessage("source", "replacement", "")}); err != nil {
		t.Fatal(err)
	}
}
func TestHostStateByteAndSelectedBodyLimits(t *testing.T) {
	s := hostTestOpen(t, hostTestPath(t))
	if err := s.put(pinnedRequest{Request: hostTestMessage("s", "multiple", ""), Bodies: map[string][]byte{"a": {1}, "b": {2}}}); err == nil {
		t.Fatal("multiple bodies accepted")
	}
	for i := 0; i < 2; i++ {
		err := s.put(pinnedRequest{Request: hostTestMessage("s", fmt.Sprint(i), ""), Bodies: map[string][]byte{"a": bytes.Repeat([]byte{'x'}, 4<<20)}})
		if (i == 0 && err != nil) || (i == 1 && err == nil) {
			t.Fatalf("aggregate byte limit: attempt %d: %v", i, err)
		}
	}
	info, _ := os.Stat(s.path)
	if info.Size() > hostStateMaxBytes || len(s.disk.Records) != 1 {
		t.Fatal("failed write changed state")
	}
	if err := s.put(pinnedRequest{Request: hostTestMessage("s", "huge", ""), Bodies: map[string][]byte{"a": bytes.Repeat([]byte{'x'}, hostStateMaxBytes)}}); err == nil {
		t.Fatal("oversized body accepted")
	}
}
func TestHostStateRejectsUnsafeFilesAndDirectories(t *testing.T) {
	for _, kind := range []string{"file-symlink", "directory-symlink", "permissions", "hardlink", "directory-permissions"} {
		t.Run(kind, func(t *testing.T) {
			path := hostTestPath(t)
			dir := filepath.Dir(path)
			switch kind {
			case "file-symlink":
				if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
			case "directory-symlink":
				if err := os.Symlink(dir, filepath.Join(dir, "alias")); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(dir, "alias", "state.json")
			case "permissions":
				if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				original := filepath.Join(dir, "original")
				if err := os.WriteFile(original, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(original, path); err != nil {
					t.Fatal(err)
				}
			case "directory-permissions":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if s, err := openHostState(context.Background(), "e", "t", path); err == nil {
				s.Close()
				t.Fatal("unsafe state accepted")
			}
		})
	}
}
func TestHostStateDefaultScopesBounded(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	for i := 0; i < hostStateMaxScopes; i++ {
		s, err := openHostState(context.Background(), "endpoint", fmt.Sprint(i), "")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.put(pinnedRequest{Request: hostTestMessage("s", "req", "")}); err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
	if s, err := openHostState(context.Background(), "endpoint", "overflow", ""); err == nil {
		s.Close()
		t.Fatal("scope limit ignored")
	}
	s, err := openHostState(context.Background(), "endpoint", "0", "")
	if err != nil {
		t.Fatal(err)
	}
	scopeDir := filepath.Dir(s.path)
	s.Close()
	old := time.Now().Add(-hostStateTTL - time.Second)
	if err := os.Chtimes(scopeDir, old, old); err != nil {
		t.Fatal(err)
	}
	s, err = openHostState(context.Background(), "endpoint", "overflow", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.get(hostTestMessage("s", "res", "req")); err == nil || !strings.Contains(err.Error(), "missing prior") {
		t.Fatalf("scope leaked or missing request fabricated: %v", err)
	}
}
