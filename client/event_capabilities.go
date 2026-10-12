package client

import (
	"encoding/json"
	"sort"
	"strconv"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/capability"
)

// manifestForOptions transfers typed declarations and metadata directly.
// External registration and final wire admission are validated independently.
// Host declarations never infer interest or authority from receivers.
func manifestForOptions(reg ahp.Registration, opts Options) (map[string]any, error) {
	declarations := opts.Events.Wire()
	keys := make([]string, 0, len(declarations))
	for name := range declarations {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	events := make([]any, 0, len(keys))
	for _, name := range keys {
		declaration := declarations[name]
		entry := map[string]any{"event": name, "modes": wireStrings(declaration.Modes)}
		if declaration.Capabilities != nil {
			entry["capabilities"] = wireCapabilities(declaration.Capabilities)
		}
		events = append(events, entry)
	}
	transports, authentication := []string{}, []string{}
	for _, backend := range reg.Hooks {
		if backend.Transport.HttpTransport.Present && backend.Transport.HttpTransport.Value != nil {
			transports = append(transports, "http")
		}
		if backend.Transport.StdioTransport.Present && backend.Transport.StdioTransport.Value != nil {
			transports = append(transports, "stdio")
		}
		if backend.Authentication.Present && backend.Authentication.Value != nil {
			a := backend.Authentication.Value
			if a.Bearer.Present {
				authentication = append(authentication, "bearer")
			}
			if a.Oauth.Present {
				authentication = append(authentication, "oauth")
			}
		}
	}
	unique := func(values []string) []any {
		sort.Strings(values)
		out := []any{}
		for _, v := range values {
			if len(out) == 0 || out[len(out)-1] != v {
				out = append(out, v)
			}
		}
		return out
	}
	manifest := map[string]any{"events": events, "transports": unique(transports), "authentication": unique(authentication), "gaps": []any{}, "toolPaths": []any{}, "contentCategories": []any{}, "correlationIdentityFields": []any{}, "limits": map[string]any{}, "managedPolicy": map[string]any{"scopes": []any{"user"}, "disableable": true}}
	if err := applyManifestMetadata(manifest, opts.Metadata); err != nil {
		return nil, err
	}
	return manifest, nil
}

func wireStrings(values []string) []any {
	out := make([]any, 0, len(values))
	for _, v := range values {
		out = append(out, v)
	}
	return out
}

func wireCapabilities(c *capability.WireCapabilities) map[string]any {
	out := map[string]any{"effects": wireStrings(c.Effects)}
	if len(c.Modify) != 0 {
		modifications := map[string]any{}
		for target, grant := range c.Modify {
			modifications[target] = map[string]any{"replace": grant.Replace, "merge": grant.Merge}
		}
		out["modify"] = modifications
	}
	if c.Flow != nil {
		flow := map[string]any{"operations": wireStrings(c.Flow.Operations)}
		if c.Flow.RemainingContinuations != nil {
			flow["remainingContinuations"] = json.Number(strconv.FormatUint(*c.Flow.RemainingContinuations, 10))
		}
		if c.Flow.ContinuationCount != nil {
			flow["continuationCount"] = json.Number(strconv.FormatUint(*c.Flow.ContinuationCount, 10))
		}
		if c.Flow.MaxContinuations != nil {
			flow["maxContinuations"] = json.Number(strconv.FormatUint(*c.Flow.MaxContinuations, 10))
		}
		out["flow"] = flow
	}
	if c.Inject != nil {
		out["inject"] = map[string]any{"context": map[string]any{"append": c.Inject.Context.Append, "deliverAt": wireStrings(c.Inject.Context.DeliverAt)}}
	}
	if len(c.Elicitation) != 0 {
		modes := map[string]any{}
		for mode := range c.Elicitation {
			modes[mode] = map[string]any{}
		}
		out["elicitation"] = modes
	}
	return out
}
