package main

import "testing"

func TestLocalFixtureRejectsWireAndMalformedHooks(t *testing.T) {
	for _, request := range []O{
		{"jsonrpc": "2.0", "id": "rpc", "method": "hooks/intercept"},
		{"jsonrpc": "2.0", "id": "rpc", "method": "compaction/run", "params": O{"instructions": "base", "before": []any{true}}},
	} {
		reply := receive(request)
		if reply["error"] == nil || reply["id"] != "rpc" {
			t.Fatalf("unexpected reply: %v", reply)
		}
	}
}
