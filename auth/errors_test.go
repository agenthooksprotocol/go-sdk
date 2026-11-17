package auth

import (
	"encoding/json"
	"testing"
)

func TestErrorJSONAllowlist(t *testing.T) {
	codes := []Code{
		CodeInvalidConfiguration, CodeUnsupportedBinding, CodeCredentialUnavailable,
		CodeInteractionRequired, CodeAccessDenied, CodeRefreshRejected,
		CodeDiscoveryFailed, CodeUntrustedDestination, CodeProviderFailed,
		Code("host-secret-must-not-escape"),
	}
	for _, code := range codes {
		t.Run(string(code), func(t *testing.T) {
			value := Error{Code: code}
			expected := code
			if code == Code("host-secret-must-not-escape") {
				expected = CodeProviderFailed
			}
			for _, form := range []struct {
				name  string
				value any
			}{{"value", value}, {"pointer", &value}} {
				t.Run(form.name, func(t *testing.T) {
					encoded, err := json.Marshal(form.value)
					if err != nil {
						t.Fatal(err)
					}
					// Exact output checks both redaction and the existing public field spelling.
					if got, want := string(encoded), `{"Code":"`+string(expected)+`"}`; got != want {
						t.Fatalf("JSON = %s; want %s", got, want)
					}
				})
			}
			if value.Code != code {
				t.Fatal("serialization mutated host-owned error")
			}
		})
	}
}
