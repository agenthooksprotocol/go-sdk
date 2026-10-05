package client

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

func eventOptionsRegistration(t *testing.T, name, mode string, policy map[string]any) ahp.Registration {
	t.Helper()
	hooks := []any{}
	if name != "" {
		sub := map[string]any{"events": []string{name}, "mode": mode, "timeoutMs": 1000, "failurePolicy": "fail-open", "content": map[string]any{"default": "metadata"}}
		if mode == "observe" {
			delete(sub, "timeoutMs")
			delete(sub, "failurePolicy")
		}
		for k, v := range policy {
			sub[k] = v
		}
		hooks = append(hooks, map[string]any{"id": "dev.example.events", "transport": map[string]any{"type": "http", "url": "http://127.0.0.1:1/hooks"}, "subscriptions": []any{sub}})
	}
	parsed := ahp.ParseRegistration(sdkJSON(map[string]any{"protocolVersion": "draft", "hooks": hooks}))
	if !parsed.OK {
		t.Fatal(parsed.Diagnostics)
	}
	return parsed.Value
}

func eventOptionsCaps(effects ...string) *ahp.Capabilities {
	caps := &ahp.Capabilities{Effects: []ahp.CapabilitiesEffectsItem{}}
	for _, effect := range effects {
		var value ahp.CapabilitiesEffectsItem
		if err := json.Unmarshal(sdkJSON(effect), &value); err != nil {
			panic(err)
		}
		caps.Effects = append(caps.Effects, value)
	}
	return caps
}

func TestEventOptionsRejectInvalidAuthority(t *testing.T) {
	cases := map[string]map[string]EventCapabilities{
		"absent":                 {},
		"no modes":               {"tool.before": {Capabilities: eventOptionsCaps("deny")}},
		"empty mode":             {"tool.before": {Modes: []Mode{""}}},
		"duplicate mode":         {"tool.before": {Modes: []Mode{Intercept, Intercept}, Capabilities: eventOptionsCaps()}},
		"unknown mode":           {"tool.before": {Modes: []Mode{"execute"}}},
		"unknown event":          {"tool.unknown": {Modes: []Mode{Observe}}},
		"intercept missing caps": {"tool.before": {Modes: []Mode{Intercept}}},
		"observe decision caps":  {"tool.before": {Modes: []Mode{Observe}, Capabilities: eventOptionsCaps("deny")}},
		"observe empty caps":     {"tool.before": {Modes: []Mode{Observe}, Capabilities: eventOptionsCaps()}},
		"noninterceptable event": {"session.end": {Modes: []Mode{Intercept}, Capabilities: eventOptionsCaps()}},
		"wrong mode":             {"tool.before": {Modes: []Mode{Observe}}},
	}
	for name, events := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := New(eventOptionsRegistration(t, "tool.before", "intercept", nil), Options{Source: "urn:test:events", Events: events})
			if c != nil {
				c.Close()
				t.Fatal("invalid configuration acquired a client")
			}
			if err == nil {
				t.Fatal("expected admission error")
			}
		})
	}
}

func TestEventOptionsExplicitModesAndPolicy(t *testing.T) {
	for _, mode := range []Mode{Intercept, Observe} {
		t.Run(string(mode), func(t *testing.T) {
			caps := (*ahp.Capabilities)(nil)
			if mode == Intercept {
				caps = eventOptionsCaps()
			}
			c, err := New(eventOptionsRegistration(t, "tool.before", string(mode), nil), Options{Source: "urn:test:events", Events: map[string]EventCapabilities{"tool.before": {Modes: []Mode{mode}, Capabilities: caps}}})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if !sdkHas(sdkObj(sdkArray(c.manifest["events"])[0])["modes"], string(mode)) {
				t.Fatal("explicit mode lost")
			}
		})
	}
	for _, policy := range []map[string]any{{"scope": "project"}, {"scope": "managed", "disableable": false}, {"disableable": false}} {
		c, err := New(eventOptionsRegistration(t, "tool.before", "intercept", policy), Options{Source: "urn:test:events", Events: map[string]EventCapabilities{"tool.before": {Modes: []Mode{Intercept}, Capabilities: eventOptionsCaps()}}})
		if err == nil {
			c.Close()
			t.Fatal("ordinary options admitted stronger policy")
		}
	}
}

func TestEventOptionsSnapshotAndNarrowing(t *testing.T) {
	caps := eventOptionsCaps("deny", "allow")
	modes := []Mode{Intercept}
	events := map[string]EventCapabilities{"tool.before": {Modes: modes, Capabilities: caps}}
	c, err := New(eventOptionsRegistration(t, "tool.before", "intercept", nil), Options{Source: "urn:test:events", Events: events})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	before := string(sdkJSON(c.manifest))
	modes[0] = Observe
	caps.Effects[0] = eventOptionsCaps("modify").Effects[0]
	delete(events, "tool.before")
	if string(sdkJSON(c.manifest)) != before {
		t.Fatal("manifest aliases caller data")
	}
	base := sdkObj(sdkObj(sdkArray(c.manifest["events"])[0])["capabilities"])
	if _, _, _, err := resolveOptions(base, []InterceptOption{WithCapabilities(*eventOptionsCaps("deny"))}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := resolveOptions(base, []InterceptOption{WithCapabilities(*eventOptionsCaps("modify"))}); err == nil {
		t.Fatal("per-occurrence options added authority")
	}
	if _, err := c.intercept(context.Background(), "tool.after", map[string]any{}); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("unadvertised boundary: %v", err)
	}
}

func TestEventOptionsManifestCompatibility(t *testing.T) {
	reg := eventOptionsRegistration(t, "tool.before", "intercept", nil)
	opts := Options{Source: "urn:test:events", Events: map[string]EventCapabilities{"tool.before": {Modes: []Mode{Intercept}, Capabilities: eventOptionsCaps()}}}
	m, err := manifestForOptions(reg, opts)
	if err != nil {
		t.Fatal(err)
	}
	var full ahp.StaticCapabilityManifest
	if err := json.Unmarshal(sdkJSON(m), &full); err != nil {
		t.Fatal(err)
	}
	opts.Manifest = full
	if _, err := New(reg, opts); err == nil {
		t.Fatal("accepted both configuration inputs")
	}
	opts.Events = nil
	c, err := New(reg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !reflect.DeepEqual(c.manifest, m) {
		t.Fatal("advanced manifest changed")
	}
}

func TestEventOptionsMinimalMetadata(t *testing.T) {
	reg := eventOptionsRegistration(t, "session.start", "intercept", nil)
	c, err := New(reg, Options{Source: "urn:test:events", Events: map[string]EventCapabilities{
		"tool.before":   {Modes: []Mode{Observe}},
		"session.start": {Modes: []Mode{Intercept}, Capabilities: eventOptionsCaps()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	entries := sdkArray(c.manifest["events"])
	if sdkObj(entries[0])["event"] != "session.start" || sdkObj(entries[1])["event"] != "tool.before" {
		t.Fatal("events not sorted")
	}
	for _, key := range []string{"gaps", "authentication", "toolPaths", "contentCategories", "correlationIdentityFields"} {
		if !reflect.DeepEqual(c.manifest[key], []any{}) {
			t.Fatalf("invented %s metadata", key)
		}
	}
	if !reflect.DeepEqual(c.manifest["transports"], []any{"http"}) || !reflect.DeepEqual(c.manifest["limits"], map[string]any{}) {
		t.Fatal("invented transport or limits")
	}
	tr := &testTransport{}
	c.backends[0].transport = tr
	r, err := c.intercept(context.Background(), "session.start", map[string]any{"session": map[string]any{"id": "session-1"}, "harness": map[string]any{"name": "test", "version": "1"}, "trigger": "startup", "permissionMode": "default", "items": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	var delivered map[string]any
	if err := json.Unmarshal(r.Event, &delivered); err != nil {
		t.Fatal(err)
	}
	if string(sdkJSON(delivered["manifest"])) != string(sdkJSON(c.manifest)) {
		t.Fatal("session.start manifest differs from admitted metadata")
	}
	if len(tr.calls) != 1 {
		t.Fatalf("expected session.start delivery, got %d", len(tr.calls))
	}
}
