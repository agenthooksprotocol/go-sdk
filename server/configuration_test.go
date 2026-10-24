package server

import (
	"encoding/json"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

func configurationFixture(t *testing.T) *ahp.Configuration {
	t.Helper()
	var value ahp.Configuration
	if err := json.Unmarshal([]byte(`{"subscriptions":[{"events":["tool.before"],"mode":"intercept","timeoutMs":750,"failurePolicy":"fail-open","content":{"default":"metadata"}}]}`), &value); err != nil {
		t.Fatal(err)
	}
	return &value
}

func TestConfigurationDiscoverySnapshot(t *testing.T) {
	configuration := configurationFixture(t)
	h, err := NewHandler(Handlers{Configuration: configuration}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// Snapshot ownership: replacing the caller model cannot change the response.
	*configuration = ahp.Configuration{}
	reply := request(h, []byte(`{"jsonrpc":"2.0","id":"config-1","method":"hooks/configuration","params":{"protocolVersion":"draft"}}`))
	if reply.Code != 200 || !canonical("configuration-response", reply.Body.Bytes()) {
		t.Fatalf("invalid discovery: %d %s", reply.Code, reply.Body.String())
	}
	var envelope struct {
		ID     string `json:"id"`
		Result struct {
			Configuration json.RawMessage `json:"configuration"`
		} `json:"result"`
	}
	if err := json.Unmarshal(reply.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ID != "config-1" || !strings.Contains(string(envelope.Result.Configuration), "tool.before") {
		t.Fatal(reply.Body.String())
	}
}

func TestConfigurationDiscoveryAdmission(t *testing.T) {
	if _, err := NewHandler(Handlers{Configuration: &ahp.Configuration{}}, Options{}); err == nil {
		t.Fatal("invalid advertisement accepted")
	}
	for _, tc := range []struct {
		name, body, code string
		configured       bool
	}{
		{"unavailable", `{"jsonrpc":"2.0","id":1,"method":"hooks/configuration","params":{"protocolVersion":"draft"}}`, "-32601", false},
		{"unsupported version", `{"jsonrpc":"2.0","id":1,"method":"hooks/configuration","params":{"protocolVersion":"old"}}`, "-32001", true},
		{"missing version", `{"jsonrpc":"2.0","id":1,"method":"hooks/configuration","params":{}}`, "-32602", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handlers := Handlers{}
			if tc.configured {
				handlers.Configuration = configurationFixture(t)
			}
			h, err := NewHandler(handlers, Options{})
			if err != nil {
				t.Fatal(err)
			}
			response := request(h, []byte(tc.body))
			if !strings.Contains(response.Body.String(), tc.code) {
				t.Fatal(response.Body.String())
			}
		})
	}
}
