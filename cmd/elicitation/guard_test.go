package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestCanonicalElicitationGuardAdmissionAndProvenance(t *testing.T) {
	for _, kind := range []string{"return", "deny", "modify"} {
		for _, variant := range []string{"granted", "missing grant", "cross boundary", "missing mode", "invalid shape", "uncorrelated", "missing principal"} {
			t.Run(kind+"/"+variant, func(t *testing.T) {
				request := senderFixture("request", []byte(`{"message":"Choose","requestedSchema":{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"]}}`))
				result := senderFixture("result", []byte(`{"action":"accept","content":{"answer":"original"},"_meta":{"opaque":[1,"x"]}}`))
				answer := O{"action": "accept", "content": O{"answer": "returned"}}
				effect := O{"type": kind}
				switch kind {
				case "return":
					effect["value"] = answer
				case "deny":
					effect["reason"] = "Policy"
				case "modify":
					effect["target"] = "content"
					effect["operation"] = "replace"
					effect["value"] = O{"answer": "modified"}
				}
				rp, sp := obj(request["params"]), obj(result["params"])
				rc, sc := obj(rp["capabilities"]), obj(sp["capabilities"])
				rc["elicitation"] = O{"form": O{}}
				sc["elicitation"] = O{"form": O{}}
				caps, other := rc, sc
				if kind == "modify" {
					caps, other = sc, rc
					caps["modify"] = O{"content": O{"replace": true, "merge": false}}
				}
				caps["effects"] = []any{kind}
				principal := "authenticated:hook"
				switch variant {
				case "missing grant":
					caps["effects"] = []any{}
				case "cross boundary":
					caps["effects"] = []any{}
					other["effects"] = []any{kind}
				case "missing mode":
					delete(caps, "elicitation")
				case "invalid shape":
					delete(effect, "value")
					delete(effect, "reason")
				case "uncorrelated":
					obj(sp["event"])["parentEventId"] = "other"
				case "missing principal":
					principal = ""
				}
				input := O{"request": request, "result": result, "effect": effect}
				before, _ := json.Marshal(input)
				resolve := func(O) ([]byte, error) { return nil, fmt.Errorf("unexpected upload resolution") }
				summary, err := checkElicitationGuard(request, result, effect, resolve, func(string, any) error { return nil }, principal)
				after, _ := json.Marshal(input)
				if string(before) != string(after) {
					t.Fatal("guard mutated input")
				}
				if variant != "granted" {
					if err == nil || summary != nil {
						t.Fatalf("rejected guard exposed summary: %v %v", summary, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				want := O{"kind": "hook", "authenticatedSource": "authenticated:hook", "effect": kind}
				if !reflect.DeepEqual(summary["provenance"], want) || summary["externalCompletion"] != false {
					t.Fatalf("wrong provenance: %v", summary)
				}
				var original O
				json.Unmarshal([]byte(str(obj(obj(obj(sp["event"])["elicitation"])["result"])["text"])), &original)
				if !reflect.DeepEqual(summary["result"], original) {
					t.Fatalf("guard settled rather than probed: %v", summary)
				}
			})
		}
	}
}
