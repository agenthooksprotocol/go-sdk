package server

import "testing"

func TestDescriptorIsNotAMergeBase(t *testing.T) {
	request := []byte(`{"params":{"event":{"elicitation":{"result":{"id":"answer","kind":"json","mediaType":"application/json","selection":"body","body":{"ref":"receiver-answer"}}}},"capabilities":{"effects":["modify"],"modify":{"content":{"merge":true,"replace":true}}}}}`)
	if !validEffects(request, []byte(`{"result":{"effects":[{"type":"modify","target":"content","operation":"merge","value":{"field":1}}]}}`)) {
		t.Fatal("unresolved descriptor incorrectly treated as an absent/scalar merge base")
	}
	if validEffects(request, []byte(`{"result":{"effects":[{"type":"modify","target":"content","operation":"merge","value":null}]}}`)) {
		t.Fatal("non-object merge patch accepted")
	}
	if validEffects(request, []byte(`{"result":{"effects":[{"type":"modify","target":"content","operation":"replace","value":"scalar"},{"type":"modify","target":"content","operation":"merge","value":{}}]}}`)) {
		t.Fatal("known staged scalar incorrectly accepted as object base")
	}
	if !validEffects(request, []byte(`{"result":{"effects":[{"type":"modify","target":"content","operation":"replace","value":{}},{"type":"modify","target":"content","operation":"merge","value":{"field":1}}]}}`)) {
		t.Fatal("known staged object merge rejected")
	}
}
func TestContinuationIntegerRepresentations(t *testing.T) {
	for _, count := range []string{"0", "0.0", "0e2"} {
		request := []byte(`{"id":"event","params":{"event":{"id":"event"},"capabilities":{"flow":{"operations":["continue"],"remainingContinuations":1.0,"continuationCount":` + count + `,"maxContinuations":1e0}}}}`)
		if !validInterceptContext(request) {
			t.Fatalf("mathematically integral count rejected: %s", count)
		}
	}
}
