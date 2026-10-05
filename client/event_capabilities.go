package client

import (
	"errors"
	"fmt"
	"reflect"
	"sort"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

// Mode is an explicitly supported delivery mode for a boundary.
type Mode = ahp.StaticCapabilityManifestEventsItemModesItem

const (
	Intercept Mode = ahp.StaticCapabilityManifestEventsItemModesItemIntercept
	Observe   Mode = ahp.StaticCapabilityManifestEventsItemModesItemObserve
)

// EventCapabilities declares host authority for one exact boundary. Modes must
// be nonempty and unique. Intercept requires an explicit Capabilities value,
// including when its Effects list is empty. Observe-only entries omit Capabilities.
// Neither registration subscriptions nor per-occurrence options grant authority.
type EventCapabilities struct {
	Modes        []Mode
	Capabilities *ahp.Capabilities
}

// manifestForOptions synthesizes only the metadata needed by the ordinary path.
// Events are host declarations, never inferred from registration. Transport and
// authentication lists describe the supplied registration, not blanket native
// support. Policy is user-only and disableable; stronger policy admission needs
// an explicit Manifest. Gaps, tool paths, content categories, correlation fields,
// and limits are left empty rather than claiming unconfigured feature support.
// The same manifest is delivered on session.start. The caller validates it with
// the canonical schema and root codec before acquiring any transport.
func manifestForOptions(reg ahp.Registration, opts Options) (map[string]any, error) {
	if opts.Events == nil {
		return sdkMap(opts.Manifest)
	}
	if !reflect.ValueOf(opts.Manifest).IsZero() {
		return nil, errors.New("Events and Manifest are mutually exclusive")
	}
	keys := make([]string, 0, len(opts.Events))
	for name := range opts.Events {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	events := make([]any, 0, len(keys))
	for _, name := range keys {
		cfg := opts.Events[name]
		if len(cfg.Modes) == 0 {
			return nil, fmt.Errorf("event %q requires explicit modes", name)
		}
		seen := map[Mode]bool{}
		intercept := false
		for _, mode := range cfg.Modes {
			if seen[mode] {
				return nil, fmt.Errorf("event %q repeats a mode", name)
			}
			seen[mode] = true
			intercept = intercept || mode == Intercept
		}
		if intercept && cfg.Capabilities == nil {
			return nil, fmt.Errorf("event %q requires explicit intercept capabilities", name)
		}
		if !intercept && cfg.Capabilities != nil {
			return nil, fmt.Errorf("event %q observe-only entry must omit capabilities", name)
		}
		entry := map[string]any{"event": name, "modes": cfg.Modes}
		if cfg.Capabilities != nil {
			entry["capabilities"] = cfg.Capabilities
		}
		events = append(events, entry)
	}
	transports, authentication := []string{}, []string{}
	for _, backend := range reg.Hooks {
		bm, err := sdkMap(backend)
		if err != nil {
			return nil, err
		}
		if kind, ok := sdkObj(bm["transport"])["type"].(string); ok {
			transports = append(transports, kind)
		}
		if kind, ok := sdkObj(bm["authentication"])["type"].(string); ok {
			authentication = append(authentication, kind)
		}
	}
	unique := func(values []string) []string {
		sort.Strings(values)
		out := make([]string, 0, len(values))
		for _, v := range values {
			if len(out) == 0 || out[len(out)-1] != v {
				out = append(out, v)
			}
		}
		return out
	}
	return sdkMap(map[string]any{
		"events": events, "transports": unique(transports), "authentication": unique(authentication),
		"gaps": []any{}, "toolPaths": []string{}, "contentCategories": []string{},
		"correlationIdentityFields": []string{}, "limits": map[string]any{},
		"managedPolicy": map[string]any{"scopes": []string{"user"}, "disableable": true},
	})
}
