package ahp

import (
	"encoding/json"
	"reflect"
	"testing"
)

func assertSameJSON(t *testing.T, want, got []byte) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(want, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("round trip changed JSON: %s", got)
	}
}

func TestCapabilityExtensionsRoundTrip(t *testing.T) {
	raw := []byte(`{"effects":["deny","com.example.effect"],"modify":{"input":{"replace":true,"merge":false,"future":null},"future":{}},"future":{"enabled":true}}`)
	parsed := ParseCapabilities(raw)
	if !parsed.OK {
		t.Fatal(parsed.Diagnostics)
	}
	encoded, err := EncodeCapabilities(parsed.Value)
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, raw, encoded)
	if ParseCapabilities([]byte(`{"effects":["deny"],"modify":{"input":{"replace":"yes","merge":false}}}`)).OK {
		t.Fatal("malformed recognized capability accepted")
	}
}

func TestUploadExtensionsRoundTrip(t *testing.T) {
	raw := []byte(`{"endpoint":"https://content.example.test/bytes","timeoutMs":1000,"maxBytes":0,"auth":{"type":"bearer","tokenEnv":"UPLOAD_TOKEN","future":true},"future":[1,null]}`)
	parsed := ParseContentUpload(raw)
	if !parsed.OK {
		t.Fatal(parsed.Diagnostics)
	}
	encoded, err := EncodeContentUpload(parsed.Value)
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, raw, encoded)
	for _, raw := range []string{
		`{"endpoint":"https://content.example.test/bytes","timeoutMs":"1000","maxBytes":0}`,
		`{"endpoint":"https://content.example.test/bytes","timeoutMs":1000,"maxBytes":0,"auth":{"type":"bearer","tokenEnv":false}}`,
	} {
		if ParseContentUpload([]byte(raw)).OK {
			t.Fatal("malformed recognized upload field accepted")
		}
	}
}
