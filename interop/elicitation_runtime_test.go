package interop

import (
	"bytes"
	"strings"
	"testing"
)

func TestElicitationPublicEffects(t *testing.T) {
	requestBody := []byte(`{"message":"Choose","requestedSchema":{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"]}}`)
	resultBody := []byte(`{"action":"accept","content":{"answer":"original"},"_meta":{"preserve":true}}`)
	bodies := map[string][]byte{"urn:request": requestBody, "urn:result": resultBody}
	makeRequest := func(stage string) Object {
		meta := Object{"server": "requester", "mode": "form", stage: Object{"id": stage + "-item", "kind": "elicitation." + stage, "mediaType": "application/json", "selection": "body", "body": Object{"ref": "urn:" + stage}}}
		event := Object{"id": stage, "type": "user.elicitation." + stage, "source": "urn:test:host", "time": "2026-09-15T12:00:00Z", "session": Object{"id": "session"}, "elicitation": meta}
		caps := Object{"effects": []any{"return", "deny"}}
		if stage == "result" {
			event["parentEventId"] = "request"
			meta["action"] = "accept"
			caps = Object{"effects": []any{"modify"}, "modify": Object{"content": Object{"replace": true, "merge": true}}}
		}
		caps["elicitation"] = Object{"form": Object{}}
		return Object{"jsonrpc": "2.0", "id": stage, "method": "hooks/intercept", "params": Object{"protocolVersion": "draft", "event": event, "capabilities": caps}}
	}
	resolve := func(ref Object) ([]byte, error) { return bodies[str(ref["ref"])], nil }
	for _, tc := range []struct {
		name    string
		result  Object
		effects []any
		valid   bool
	}{
		{"return", nil, []any{Object{"type": "return", "value": Object{"action": "accept", "content": Object{"answer": "returned"}}}}, true},
		{"deny", nil, []any{Object{"type": "deny", "reason": "policy"}}, true},
		{"replace", makeRequest("result"), []any{Object{"type": "modify", "target": "content", "operation": "replace", "value": Object{"answer": "replaced"}}}, true},
		{"merge", makeRequest("result"), []any{Object{"type": "modify", "target": "content", "operation": "merge", "value": Object{"answer": "merged"}}}, true},
		{"invalid answer", nil, []any{Object{"type": "return", "value": Object{"action": "accept", "content": Object{"answer": 9}}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := acceptElicitationEffects(makeRequest("request"), tc.result, resolve, tc.effects)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}

// These are runtime-bridge regressions, not fixture-only capability checks.
func TestElicitationPublicModeAdmission(t *testing.T) {
	for _, effect := range []string{"return", "deny", "modify"} {
		for _, grant := range []string{"absent", "empty", "opposite", "correct"} {
			t.Run(effect+"/"+grant, func(t *testing.T) {
				bodies := map[string][]byte{
					"urn:request": []byte(`{"message":"Choose","requestedSchema":{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"]}}`),
					"urn:result":  []byte(`{"action":"accept","content":{"answer":"original"}}`),
				}
				makeBoundary := func(stage string, caps Object) Object {
					meta := Object{"server": "requester", "mode": "form", stage: Object{"id": stage + "-item", "kind": "elicitation." + stage, "mediaType": "application/json", "selection": "body", "body": Object{"ref": "urn:" + stage}}}
					event := Object{"id": stage, "type": "user.elicitation." + stage, "source": "urn:test:host", "time": "2026-09-15T12:00:00Z", "session": Object{"id": "session"}, "elicitation": meta}
					if stage == "result" {
						event["parentEventId"] = "request"
						meta["action"] = "accept"
					}
					return Object{"jsonrpc": "2.0", "id": stage, "method": "hooks/intercept", "params": Object{"protocolVersion": "draft", "event": event, "capabilities": caps}}
				}
				caps := Object{"effects": []any{effect}}
				switch grant {
				case "empty":
					caps["elicitation"] = Object{}
				case "opposite":
					caps["elicitation"] = Object{"url": Object{}}
				case "correct":
					caps["elicitation"] = Object{"form": Object{}}
				}
				candidate := Object{"type": effect}
				request := makeBoundary("request", caps)
				var result Object
				switch effect {
				case "return":
					candidate["value"] = Object{"action": "accept", "content": Object{"answer": "returned"}}
				case "deny":
					candidate["reason"] = "policy"
				case "modify":
					caps["modify"] = Object{"content": Object{"replace": true, "merge": false}}
					candidate["target"] = "content"
					candidate["operation"] = "replace"
					candidate["value"] = Object{"answer": "modified"}
					// Establishing a passive request snapshot needs no mode grant.
					request = makeBoundary("request", Object{"effects": []any{"message"}})
					result = makeBoundary("result", caps)
				}
				legacyResult := result
				if legacyResult == nil {
					legacyResult = makeBoundary("result", Object{"effects": []any{"message"}})
				}
				effects := []any{candidate}
				before := jsonBytes(Object{"request": request, "result": result, "legacyResult": legacyResult, "effects": effects, "bodies": bodies})
				for _, entry := range []string{"runtime", "apply", "legacy", "legacy-neutral"} {
					reads := map[string]int{}
					deliveries := map[string]int{}
					resolve := func(ref Object) ([]byte, error) { key := str(ref["ref"]); reads[key]++; return bodies[key], nil }
					var published Object
					var err error
					switch entry {
					case "apply":
						published, err = ApplyElicitationEffects(request, result, resolve, func(string, any) error { return nil }, "authenticated", effects)
					case "legacy":
						published, err = ValidateElicitationExchange(request, legacyResult, resolve, func(string, any) error { return nil }, "authenticated", candidate)
					case "legacy-neutral":
						published, err = ValidateElicitationExchange(request, legacyResult, resolve, func(string, any) error { return nil }, "authenticated", nil)
					default:
						err = acceptElicitationEffectsObserved(request, result, resolve, effects, func(event string) { deliveries[event]++ })
					}
					if grant == "correct" || entry == "legacy-neutral" {
						if err != nil {
							t.Fatalf("entry=%s: correct grant rejected: %v", entry, err)
						}
						if entry != "runtime" && published == nil {
							t.Fatal("correct grant produced no publication")
						}
						if entry == "legacy" || entry == "legacy-neutral" {
							if obj(obj(published["result"])["content"])["answer"] != "original" {
								t.Fatal("legacy validation applied the effect instead of preserving the exchange")
							}
							provenance := obj(published["provenance"])
							if (entry == "legacy" && (provenance["kind"] != "hook" || provenance["effect"] != effect)) || (entry == "legacy-neutral" && provenance["kind"] != "mcp") {
								t.Fatalf("legacy provenance changed: %v", provenance)
							}
						}
					} else {
						if err == nil || !strings.Contains(err.Error(), "mode") {
							t.Fatalf("entry=%s: expected runtime mode admission error, got %v", entry, err)
						}
						if deliveries["user.elicitation.result"] != 0 || (effect != "modify" && deliveries["user.elicitation.request"] != 0) {
							t.Fatalf("rejected boundary reached transport: %v", deliveries)
						}
						if published != nil {
							t.Fatalf("partial publication: %#v", published)
						}
						// A result dispatch may read the preceding passive request to establish
						// its snapshot, but must not resolve the rejected result boundary.
						if reads["urn:result"] != 0 || (effect != "modify" && reads["urn:request"] != 0) {
							t.Fatalf("entry=%s: rejected boundary resolved: %v", entry, reads)
						}
					}
					after := jsonBytes(Object{"request": request, "result": result, "legacyResult": legacyResult, "effects": effects, "bodies": bodies})
					if !bytes.Equal(before, after) {
						t.Fatal("bridge mutated inputs")
					}
				}
			})
		}
	}
}
