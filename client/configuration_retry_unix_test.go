//go:build unix

package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestConfigurationRetryStdioHelper(t *testing.T) {
	if os.Getenv("AHP_RETRY_HELPER") != "1" {
		return
	}
	f, _ := os.OpenFile(os.Getenv("AHP_RETRY_PIDS"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	fmt.Fprintln(f, os.Getpid())
	f.Close()
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req map[string]any
		_ = json.Unmarshal(scanner.Bytes(), &req)
		if _, err := os.Stat(os.Getenv("AHP_RETRY_FAIL")); err == nil {
			os.Exit(4)
		}
		subs := []any{map[string]any{"events": []any{"tool.before"}, "mode": "intercept", "timeoutMs": 5000, "failurePolicy": "fail-open", "content": map[string]any{"default": "metadata"}}}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"protocolVersion": "draft", "configuration": map[string]any{"subscriptions": subs}}})
	}
	os.Exit(0)
}

// Close during a re-attempt closes a discovery that succeeded but was not
// installed: its persistent stdio child does not outlive the client.
func TestConfigurationCloseDuringRetryClosesTransports(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pids, failFlag := filepath.Join(dir, "pids"), filepath.Join(dir, "fail")
	if err := os.WriteFile(failFlag, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newRetryServer(t, "500")
	r := &retryHarness{}
	stdio := map[string]any{"id": "com.example.stdio-retry", "transport": map[string]any{"type": "stdio", "command": exe, "args": []string{"-test.run=^TestConfigurationRetryStdioHelper$"}, "lifecycle": "persistent", "env": map[string]string{"AHP_RETRY_HELPER": "1", "AHP_RETRY_PIDS": pids, "AHP_RETRY_FAIL": failFlag}}}
	h := newRetryHooks(t, r, retryRegistration(t, stdio, retryBackend(s.URL)), r.options(nil))
	if len(h.routes()) != 0 || r.count() != 2 {
		t.Fatalf("both backends not skipped: %d", r.count())
	}
	_ = os.Remove(failFlag)
	r.advance(time.Minute)
	g := s.holdDiscovery()
	t.Cleanup(func() { s.gate.Store(nil); close(g.release) })
	done := make(chan struct{})
	go func() { _, _ = h.intercept(context.Background(), "tool.before", testInput()); close(done) }()
	<-g.entered // the stdio re-attempt succeeded; the HTTP one is in flight
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
	data, _ := os.ReadFile(pids)
	lines := strings.Fields(string(data))
	if len(lines) != 2 {
		t.Fatalf("stdio children started: %v", lines)
	}
	pid, _ := strconv.Atoi(lines[1])
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatal("uninstalled re-attempt leaked its stdio child")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
