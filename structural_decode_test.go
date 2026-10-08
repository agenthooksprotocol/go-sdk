package ahp_test

import (
	"encoding/json"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

func TestDirectCandidateStructuralValidation(t *testing.T) {
	for _, text := range []string{`{}`, `null`} {
		var value ahp.InterceptRequestParamsStateCandidateValue
		if err := json.Unmarshal([]byte(text), &value); err == nil {
			t.Fatalf("candidate payload %s must contain value", text)
		}
	}
	for _, test := range []struct {
		input          string
		valid, nonnull bool
	}{
		{`{}`, false, false},
		{`{"permission":"allow"}`, false, false},
		{`{"candidate":null}`, false, false},
		{`{"permission":"allow","candidate":{}}`, false, false},
		{`{"permission":"allow","candidate":null}`, true, false},
		{`{"permission":"allow","candidate":{"value":null}}`, true, true},
		{`{"permission":"future","candidate":{"value":9007199254740993},"extension":true}`, true, true},
	} {
		var value ahp.InterceptRequestParamsState
		err := json.Unmarshal([]byte(test.input), &value)
		if (err == nil) != test.valid {
			t.Fatalf("%s: %v", test.input, err)
		}
		if test.valid && value.Candidate.Valid != test.nonnull {
			t.Fatalf("null state changed: %+v", value)
		}
		if test.valid {
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var roundTrip ahp.InterceptRequestParamsState
			if err := json.Unmarshal(raw, &roundTrip); err != nil {
				t.Fatal(err)
			}
		}
	}
}
