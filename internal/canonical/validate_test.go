package canonical

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBundledCanonicalConstraints(t *testing.T) {
	if err := Load(); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{`{"effects":["deny","deny"]}`, `{"effects":["deny"],"flow":{"operations":["stop"]}}`, `{"effects":["modify"],"modify":{"input":{"replace":false,"merge":false}}}`} {
		if Validate("capabilities", []byte(data)) == nil {
			t.Fatalf("canonical constraint accepted %s", data)
		}
	}
	if err := Validate("capabilities", []byte(`{"effects":["deny"],"future":{"anything":true}}`)); err != nil {
		t.Fatal(err)
	}
}
func TestMalformedProtocolJSON(t *testing.T) {
	for _, data := range [][]byte{[]byte(`{"effects":[]} {}`), {0xff}, []byte(`null`)} {
		if Validate("capabilities", data) == nil {
			t.Fatal("malformed accepted")
		}
	}
	if Validate("external-url", []byte(`{}`)) == nil {
		t.Fatal("unknown schema accepted")
	}
}

func TestPinnedMCPDocuments(t *testing.T) {
	for _, data := range []string{
		`{"message":"hello","requestedSchema":{"type":"object","properties":{}},"_meta":{"progressToken":1,"extra":{}},"task":{"ttl":42},"extension":true}`,
		`{"mode":"url","message":"hello","url":"https://example.test/","elicitationId":"opaque"}`,
	} {
		if err := Validate("mcp-elicitation#request", []byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	for _, field := range []string{
		`{"type":"object","properties":{}}`,
		`{"type":"array","items":{"type":"string"}}`,
		`{"type":"string","pattern":".*"}`,
		`{"type":"string","enum":[1]}`,
		`{"type":"string","format":"hostname"}`,
		`{"type":"string","enum":["x"],"enumNames":[1]}`,
		`{"type":"string","oneOf":[{"const":"x"}]}`,
		`{"type":"array","items":{"anyOf":[{"const":"x","title":"X","extra":true}]}}`,
	} {
		data := `{"message":"hello","requestedSchema":{"type":"object","properties":{"x":` + field + `}}}`
		if Validate("mcp-elicitation#request", []byte(data)) == nil {
			t.Fatalf("unsupported form vocabulary: %s", field)
		}
	}
	for _, data := range []string{`{"action":"accept","content":{"x":{}}}`, `{"action":"other"}`, `{"action":"accept","content":{"x":[1]}}`} {
		if Validate("mcp-elicitation#result", []byte(data)) == nil {
			t.Fatalf("invalid result: %s", data)
		}
	}
}

func TestPinnedFormAnswers(t *testing.T) {
	cases := []struct{ name, field, good, bad string }{
		{"unicode lengths", `{"type":"string","minLength":2,"maxLength":2}`, `"é😊"`, `"é"`},
		{"fractional lengths", `{"type":"string","minLength":1.5,"maxLength":2.5}`, `"ab"`, `"a"`},
		{"number precision", `{"type":"number","minimum":9007199254740993,"maximum":9007199254740994}`, `9007199254740993`, `9007199254740992`},
		{"integer", `{"type":"integer","minimum":0,"maximum":5}`, `3.0`, `3.5`},
		{"boolean", `{"type":"boolean"}`, `true`, `"true"`},
		{"email", `{"type":"string","format":"email"}`, `"a@example.test"`, `"invalid"`},
		{"date", `{"type":"string","format":"date"}`, `"2024-02-29"`, `"2023-02-29"`},
		{"date-time", `{"type":"string","format":"date-time"}`, `"2025-01-01T00:00:00Z"`, `"2025-01-01"`},
		{"uri", `{"type":"string","format":"uri"}`, `"https://example.test"`, `"relative/path"`},
		{"untitled single", `{"type":"string","enum":["a","b"]}`, `"a"`, `"c"`},
		{"legacy single", `{"type":"string","enum":["a"],"enumNames":["A"]}`, `"a"`, `"A"`},
		{"titled single", `{"type":"string","oneOf":[{"const":"a","title":"A"}]}`, `"a"`, `"A"`},
		{"untitled multi", `{"type":"array","minItems":1,"maxItems":2,"items":{"type":"string","enum":["a"]}}`, `["a","a"]`, `["b"]`},
		{"titled multi", `{"type":"array","items":{"anyOf":[{"const":"a","title":"A"}]}}`, `["a"]`, `["A"]`},
		{"defaults not applied", `{"type":"integer","default":1.5}`, `1`, `1.5`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var schema any
			if err := json.Unmarshal([]byte(`{"$schema":"https://untrusted.invalid/never-load","type":"object","properties":{"x":`+tc.field+`},"required":["x"]}`), &schema); err != nil {
				t.Fatal(err)
			}
			// Decode the schema losslessly as production request decoding does.
			d := json.NewDecoder(strings.NewReader(`{"type":"object","properties":{"x":` + tc.field + `},"required":["x"],"$schema":"https://untrusted.invalid/never-load"}`))
			d.UseNumber()
			_ = d.Decode(&schema)
			for i, input := range []string{tc.good, tc.bad} {
				var value any
				d := json.NewDecoder(strings.NewReader(`{"x":` + input + `}`))
				d.UseNumber()
				if err := d.Decode(&value); err != nil {
					t.Fatal(err)
				}
				err := ValidateFormAnswer(schema, value)
				if (err == nil) != (i == 0) {
					t.Fatalf("answer %s: %v", input, err)
				}
			}
			if ValidateFormAnswer(schema, map[string]any{}) == nil {
				t.Fatal("missing required property accepted")
			}
		})
	}
}
