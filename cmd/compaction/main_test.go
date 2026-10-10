package main

import (
	"reflect"
	"testing"
)

func TestSyntheticCompactionAcceptsCanonicalInstructions(t *testing.T) {
	parts := []any{O{"id": "first", "kind": "text", "mediaType": "text/plain", "selection": "body", "text": "ba"}, O{"id": "second", "kind": "text", "mediaType": "text/plain", "selection": "body", "text": "se"}}
	reply := receive(O{"jsonrpc": "2.0", "id": "inline", "method": "compaction/run", "params": O{"instructions": parts}})
	if reply["error"] != nil {
		t.Fatal(reply)
	}
	result := reply["result"].(map[string]any)
	if result["applied"] != true || !reflect.DeepEqual(result["instructions"], parts) {
		t.Fatalf("canonical instructions lost: %v", result)
	}
	summary := result["summary"].([]any)
	if summary[0].(map[string]any)["text"] != "summary:base" {
		t.Fatal(summary)
	}
	for _, bad := range []any{"base", []any{O{"id": "bad", "kind": "text", "mediaType": "text/plain", "selection": "body", "text": "base", "body": O{"ref": "hidden"}}}} {
		reply = receive(O{"jsonrpc": "2.0", "id": "invalid", "method": "compaction/run", "params": O{"instructions": bad}})
		if reply["error"] == nil {
			t.Fatalf("invalid instruction shape accepted: %v", bad)
		}
	}
}

func TestLocalFixtureRejectsWireAndMalformedHooks(t *testing.T) {
	for _, request := range []O{
		{"jsonrpc": "2.0", "id": "rpc", "method": "hooks/intercept"},
		{"jsonrpc": "2.0", "id": "rpc", "method": "compaction/run", "params": O{"instructions": []any{O{"id": "base", "kind": "text", "mediaType": "text/plain", "selection": "body", "text": "base"}}, "before": []any{true}}},
	} {
		reply := receive(request)
		if reply["error"] == nil || reply["id"] != "rpc" {
			t.Fatalf("unexpected reply: %v", reply)
		}
	}
}
