package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

// ErrConfigurationSkipped reports that a backend without explicit subscriptions
// was skipped. It contains no endpoint, credentials, or backend response data.
var ErrConfigurationSkipped = errors.New("backend configuration unavailable or inapplicable")

func (c *Hooks) configurationSkipped(id string) {
	if c.opts.TransportDiagnostic != nil {
		c.opts.TransportDiagnostic(id, ErrConfigurationSkipped)
	}
}

func (c *Hooks) discoverConfiguration(transport backendTransport) ([]map[string]any, error) {
	ctx, cancel := context.WithTimeout(c.opts.InitializationContext, c.opts.ConfigurationTimeout)
	defer cancel()
	// Each transport is bound to exactly one backend. The request has no event,
	// content, or session and uses the ordinary endpoint credential boundary.
	id := "ahp-configuration"
	request := sdkJSON(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "hooks/configuration",
		"params": map[string]any{"protocolVersion": ahp.ProtocolVersionValue},
	})
	response, err := transport.Exchange(ctx, request, false)
	if c.opts.InitializationContext.Err() != nil {
		return nil, c.opts.InitializationContext.Err()
	}
	if err != nil {
		return nil, ErrConfigurationSkipped
	}
	if ctx.Err() != nil || canonical.Validate("configuration-response", response) != nil {
		return nil, ErrConfigurationSkipped
	}
	var envelope map[string]any
	decoder := json.NewDecoder(bytes.NewReader(response))
	decoder.UseNumber()
	if decoder.Decode(&envelope) != nil || envelope["id"] != id || envelope["jsonrpc"] != "2.0" {
		return nil, ErrConfigurationSkipped
	}
	if _, exists := envelope["error"]; exists {
		return nil, ErrConfigurationSkipped
	}
	result := sdkObj(envelope["result"])
	if result["protocolVersion"] != ahp.ProtocolVersionValue {
		return nil, ErrConfigurationSkipped
	}
	configuration := sdkObj(result["configuration"])
	needsAuthorization := false
	for _, raw := range sdkArray(configuration["subscriptions"]) {
		if _, present := sdkObj(raw)["upload"]; present {
			needsAuthorization = true
		}
	}
	if needsAuthorization || c.opts.AuthorizeConfiguration != nil {
		if c.opts.AuthorizeConfiguration == nil {
			return nil, ErrConfigurationSkipped
		}
		var snapshot ahp.Configuration
		if json.Unmarshal(sdkJSON(configuration), &snapshot) != nil {
			return nil, ErrConfigurationSkipped
		}
		allowed, err := c.opts.AuthorizeConfiguration(ctx, &snapshot)
		if c.opts.InitializationContext.Err() != nil {
			return nil, c.opts.InitializationContext.Err()
		}
		if err != nil || !allowed || ctx.Err() != nil {
			return nil, ErrConfigurationSkipped
		}
	}
	var resolved []map[string]any
	for _, raw := range sdkArray(configuration["subscriptions"]) {
		sub := sdkObj(raw)
		var events []any
		for _, rawEvent := range sdkArray(c.manifest["events"]) {
			entry := sdkObj(rawEvent)
			name, _ := entry["event"].(string)
			if !sdkHas(entry["modes"], sub["mode"]) {
				continue
			}
			for _, selector := range sdkArray(sub["events"]) {
				if sdkMatch(selector, name) {
					events = append(events, name)
					break
				}
			}
		}
		if len(events) == 0 {
			continue
		}
		sub["events"] = events
		// Settings are not rewritten to fit local limits or policy scope. An
		// unsupported non-selector setting skips the backend as a whole.
		if validateSubscription(c.manifest, sub) != nil {
			return nil, ErrConfigurationSkipped
		}
		resolved = append(resolved, sub)
	}
	return resolved, nil
}
