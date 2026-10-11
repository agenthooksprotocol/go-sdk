package client

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

func TestFormContractRoundTrip(t *testing.T) {
	type choice string
	type answer struct {
		Name    string      `json:"name"`
		Count   int         `json:"count"`
		Amount  json.Number `json:"amount"`
		Enabled bool        `json:"enabled,omitempty"`
		Choice  choice      `json:"choice"`
		Many    []choice    `json:"many"`
	}
	c, err := NewFormContract[answer](
		WithFormField("name", FormFieldOptions{MinLength: "2", MaxLength: "4"}),
		WithFormField("count", FormFieldOptions{Minimum: "1", Maximum: "4"}),
		WithFormField("amount", FormFieldOptions{Minimum: "9007199254740993"}),
		WithFormField("choice", FormFieldOptions{Enum: []string{"a", "b"}}),
		WithFormField("many", FormFieldOptions{Enum: []string{"a", "b"}, MinItems: "1", MaxItems: "2"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"action":"accept","content":{"name":"éé","count":2,"amount":9007199254740993.000000000000000001,"choice":"a","many":["a","b"]}}`)
	got, err := c.DecodeResult(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Available || got.Answer.Amount != "9007199254740993.000000000000000001" || got.Answer.Choice != "a" || got.Answer.Enabled {
		t.Fatalf("unexpected answer: %+v", got)
	}
	schema := c.RequestedSchema()
	var field ahp.McpElicitationUntitledMultiSelectEnumSchema
	if err := json.Unmarshal(sdkJSON(schema.Properties["many"]), &field); err != nil {
		t.Fatal(err)
	}
	if field.Type != "array" || len(field.Items.Enum) != 2 {
		t.Fatal("not a generated multiselect union")
	}
	schema.Properties["name"].McpElicitationStringSchema.Value.MinLength = ahp.Some(json.Number("100"))
	schema.Required.Value[0] = "other"
	if _, err := c.DecodeResult(raw); err != nil {
		t.Fatalf("schema mutation affected contract: %v", err)
	}
	for _, change := range [][2]string{
		{`"name":"éé"`, `"name":"x"`},
		{`"count":2`, `"count":2.5`},
		{`"count":2`, `"count":5`},
		{`9007199254740993.000000000000000001`, `9007199254740992.999999999999999999`},
		{`"choice":"a"`, `"choice":"c"`},
		{`"many":["a","b"]`, `"many":[]`},
		{`"many":["a","b"]`, `"many":["c"]`},
		{`"name":"éé"`, `"name":null`},
		{`"name":"éé"`, `"Name":"éé"`},
		{`"name":"éé"`, `"extra":1,"name":"éé"`},
		{`"name":"éé",`, ``},
	} {
		bad := strings.Replace(string(raw), change[0], change[1], 1)
		if _, err := c.DecodeResult([]byte(bad)); err == nil {
			t.Errorf("accepted invalid content for replacement %s", change[1])
		}
	}
}

func TestFormContractActions(t *testing.T) {
	c, err := NewFormContract[struct {
		X string `json:"x"`
	}]()
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"decline", "cancel"} {
		got, err := c.DecodeResult([]byte(`{"action":"` + action + `"}`))
		if err != nil || got.Available || string(got.Result.Action) != action {
			t.Fatalf("%s: %+v %v", action, got, err)
		}
	}
	for _, raw := range []string{
		`{"action":"accept","action":"decline"}`, `{"action":"accept","content":{"x":"a","x":"b"}}`, `{"action":"accept"}`, `{"action":"decline","content":{}}`,
		`{"action":"cancel","content":{}}`, `{"action":"unknown"}`,
		`{"action":"accept","content":null}`, `{"action":"accept","content":{"x":12}}`,
		`{"action":"accept","content":{"x":"a"}} {}`, `{"action":"accept","content":{"x":"a","X":"b"}}`,
	} {
		if _, err := c.DecodeResult([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func formReject[T any](t *testing.T, opts ...FormContractOption) {
	t.Helper()
	if _, err := NewFormContract[T](opts...); err == nil {
		t.Error("accepted unsupported declaration")
	}
}

func TestFormContractRejectDeclaration(t *testing.T) {
	formReject[string](t)
	formReject[*struct{ X string }](t)
	formReject[struct{ X *string }](t)
	formReject[struct{ X map[string]string }](t)
	formReject[struct{ X any }](t)
	formReject[struct{ X struct{ Y string } }](t)
	formReject[struct{ X []string }](t)
	formReject[struct{ X [2]string }](t)
	formReject[struct{ X []int }](t, WithFormField("X", FormFieldOptions{Enum: []string{"a"}}))
	duplicate := reflect.StructOf([]reflect.StructField{{Name: "X", Type: reflect.TypeFor[string](), Tag: reflect.StructTag(`json:"x"`)}, {Name: "Y", Type: reflect.TypeFor[string](), Tag: reflect.StructTag(`json:"x"`)}})
	if _, err := newFormContract[struct{}](duplicate); err == nil {
		t.Fatal("duplicate JSON declaration accepted")
	}
	formReject[struct {
		X int `json:"x,string"`
	}](t)
	formReject[struct{ x string }](t)
	type embedded struct{ X string }
	formReject[struct{ embedded }](t)
	formReject[struct{ X string }](t, WithFormField("missing", FormFieldOptions{}))
	formReject[struct{ X string }](t, WithFormField("X", FormFieldOptions{}), WithFormField("X", FormFieldOptions{}))
	formReject[struct{ X string }](t, WithFormField("X", FormFieldOptions{Minimum: "1"}))
	formReject[struct{ X int }](t, WithFormField("X", FormFieldOptions{Minimum: "2", Maximum: "1"}))
	formReject[struct{ X string }](t, WithFormField("X", FormFieldOptions{MinLength: "-1"}))
	formReject[struct{ X string }](t, WithFormField("X", FormFieldOptions{MinLength: "1.5"}))
	formReject[struct{ X string }](t, WithFormField("X", FormFieldOptions{Enum: []string{"a", "a"}}))
	formReject[struct{ X string }](t, WithFormField("X", FormFieldOptions{Format: "hostname"}))
	formReject[struct{ X int }](t, WithFormField("X", FormFieldOptions{Maximum: "NaN"}))
	formReject[struct{ X formCodec }](t)
	formReject[formCodecStruct](t)
}

type formCodec string

func (*formCodec) UnmarshalJSON([]byte) error { return nil }

type formCodecStruct struct{ X string }

func (formCodecStruct) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }

func TestFormContractFormatsAndOverflow(t *testing.T) {
	c, err := NewFormContract[struct {
		Email string `json:"email"`
		Small int8   `json:"small"`
	}](WithFormField("email", FormFieldOptions{Format: "email"}))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"action":"accept","content":{"email":"invalid","small":1}}`, `{"action":"accept","content":{"email":"a@example.com","small":128}}`} {
		if _, err := c.DecodeResult([]byte(raw)); err == nil {
			t.Error("accepted format violation or overflow")
		}
	}
	if _, err := c.DecodeResult([]byte(`{"action":"accept","content":{"email":"a@example.com","small":1}}`)); err != nil {
		t.Fatal(err)
	}
}

func TestFormContractDerivesIntegerRepresentationBounds(t *testing.T) {
	type answer struct {
		Small int8   `json:"small"`
		Large uint64 `json:"large"`
	}
	form, err := NewFormContract[answer]()
	if err != nil {
		t.Fatal(err)
	}
	schema := form.RequestedSchema()
	var small, large ahp.McpElicitationNumberSchema
	if err := json.Unmarshal(sdkJSON(schema.Properties["small"]), &small); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(sdkJSON(schema.Properties["large"]), &large); err != nil {
		t.Fatal(err)
	}
	if small.Minimum.Value != "-128" || small.Maximum.Value != "127" || large.Minimum.Value != "0" || large.Maximum.Value != "18446744073709551615" {
		t.Fatal("requested schema omitted declared integer bounds")
	}
	if _, err := NewFormContract[answer](WithFormField("small", FormFieldOptions{Minimum: "128"})); err == nil {
		t.Fatal("unrepresentable integer constraints accepted")
	}
}
