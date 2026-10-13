package client

import (
	"encoding/json"
	"reflect"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/capability"
)

func TestManifestMetadataDirectTransferAndSnapshot(t *testing.T) {
	metadata := testManifestMetadata()
	metadata.Authentication = ahp.Some([]ahp.StaticCapabilityManifestAuthenticationItem{"bearer", "oauth"})
	opaque := json.RawMessage(` {"nested":[1,2]} `)
	metadata.AdditionalProperties = map[string]json.RawMessage{"vendor": opaque}
	metadata.Gaps = ahp.Some([]ahp.StaticCapabilityManifestGapsItem{{Path: "unsupported.path", Reason: "unavailable", AdditionalProperties: map[string]json.RawMessage{"vendor": opaque}}})
	limits := metadata.Limits.Value
	limits.AdditionalProperties = map[string]json.RawMessage{"vendor": opaque}
	metadata.Limits = ahp.Some(limits)
	policy := metadata.ManagedPolicy.Value
	policy.AdditionalProperties = map[string]json.RawMessage{"vendor": opaque}
	metadata.ManagedPolicy = ahp.Some(policy)
	reg := eventOptionsRegistration(t, "tool.before", "intercept", nil)
	c, err := New(reg, Options{Harness: ahp.Harness{Name: "test", Version: "1"}, Source: "urn:test:metadata", Events: testHost(), Metadata: metadata})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Direct transfer retains the number and opaque byte representations, not a
	// JSON-decoded float/map. Canonical validation is still performed by New.
	if got := sdkObj(c.manifest["limits"])["maxUploadBytes"]; got != json.Number("4096") {
		t.Fatalf("number transfer: %T %v", got, got)
	}
	for _, value := range []any{c.manifest["vendor"], sdkObj(c.manifest["limits"])["vendor"], sdkObj(c.manifest["managedPolicy"])["vendor"], sdkObj(sdkArray(c.manifest["gaps"])[0])["vendor"]} {
		raw, ok := value.(json.RawMessage)
		if !ok || string(raw) != string(opaque) {
			t.Fatalf("opaque transfer changed: %T %v", value, value)
		}
	}
	if !reflect.DeepEqual(c.manifest["transports"], []any{"http", "stdio"}) || !reflect.DeepEqual(c.manifest["toolPaths"], []any{"execute"}) || !reflect.DeepEqual(c.manifest["correlationIdentityFields"], []any{"event.id", "call.id"}) {
		t.Fatal("metadata transfer lost fields")
	}
	snapshot := string(sdkJSON(c.manifest))
	metadata.Transports.Value[0] = "stdio"
	metadata.Authentication.Value[0] = "oauth"
	metadata.ToolPaths.Value[0] = "changed"
	metadata.ContentCategories.Value[0] = "changed"
	metadata.CorrelationIdentityFields.Value[0] = "changed"
	metadata.Gaps.Value[0].Path = "changed"
	metadata.Gaps.Value[0].AdditionalProperties["new"] = json.RawMessage(`true`)
	metadata.ManagedPolicy.Value.Scopes[0] = "managed"
	metadata.ManagedPolicy.Value.AdditionalProperties["new"] = json.RawMessage(`true`)
	metadata.Limits.Value.AdditionalProperties["new"] = json.RawMessage(`true`)
	metadata.Limits.Value.MaxUploadBytes = ahp.Some(json.Number("1"))
	metadata.AdditionalProperties["new"] = json.RawMessage(`true`)
	opaque[1] = '['
	if got := string(sdkJSON(c.manifest)); got != snapshot {
		t.Fatalf("manifest aliases metadata: %s", got)
	}
}

func TestManifestMetadataExplicitEmptyLists(t *testing.T) {
	metadata := &ManifestMetadata{
		Transports:     ahp.Some([]ahp.StaticCapabilityManifestTransportsItem{}),
		Authentication: ahp.Some([]ahp.StaticCapabilityManifestAuthenticationItem{}),
		Gaps:           ahp.Some([]ahp.StaticCapabilityManifestGapsItem{}),
		ToolPaths:      ahp.Some([]string{}), ContentCategories: ahp.Some([]string{}), CorrelationIdentityFields: ahp.Some([]string{}),
	}
	reg := eventOptionsRegistration(t, "tool.before", "intercept", nil)
	manifest, err := manifestForOptions(reg, Options{Events: testHost(), Metadata: metadata})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"transports", "authentication", "gaps", "toolPaths", "contentCategories", "correlationIdentityFields"} {
		if !reflect.DeepEqual(manifest[key], []any{}) {
			t.Fatalf("explicit empty %s changed: %#v", key, manifest[key])
		}
	}
	// An explicit empty transport list must not silently regain registration's
	// HTTP transport during admission.
	c, err := New(reg, Options{Harness: ahp.Harness{Name: "test", Version: "1"}, Source: "urn:test:metadata", Events: testHost(), Metadata: metadata})
	if c != nil {
		c.Close()
		t.Fatal("empty transports silently regained HTTP")
	}
	if err == nil {
		t.Fatal("unsupported transport admitted")
	}
	manifest, err = manifestForOptions(reg, Options{Metadata: testManifestMetadata()})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(manifest["events"], []any{}) {
		t.Fatal("metadata generated an event grant")
	}
}

func TestManifestMetadataRejectsExtrasCollisions(t *testing.T) {
	groups := []struct {
		name         string
		keys         []string
		makeMetadata func(map[string]json.RawMessage) *ManifestMetadata
	}{
		{"manifest", []string{"events", "transports", "authentication", "gaps", "toolPaths", "contentCategories", "correlationIdentityFields", "limits", "managedPolicy"}, func(extras map[string]json.RawMessage) *ManifestMetadata {
			return &ManifestMetadata{AdditionalProperties: extras}
		}},
		{"limits", []string{"maxContinuations", "maxTimeoutMs", "maxUploadBytes", "minTimeoutMs"}, func(extras map[string]json.RawMessage) *ManifestMetadata {
			return &ManifestMetadata{Limits: ahp.Some(ahp.StaticCapabilityManifestLimits{AdditionalProperties: extras})}
		}},
		{"policy", []string{"scopes", "disableable"}, func(extras map[string]json.RawMessage) *ManifestMetadata {
			return &ManifestMetadata{ManagedPolicy: ahp.Some(ahp.StaticCapabilityManifestManagedPolicy{Scopes: []ahp.StaticCapabilityManifestManagedPolicyScopesItem{"user"}, Disableable: true, AdditionalProperties: extras})}
		}},
		{"gap", []string{"path", "reason"}, func(extras map[string]json.RawMessage) *ManifestMetadata {
			return &ManifestMetadata{Gaps: ahp.Some([]ahp.StaticCapabilityManifestGapsItem{{Path: "unsupported.path", Reason: "unavailable", AdditionalProperties: extras}})}
		}},
	}
	reg := eventOptionsRegistration(t, "tool.before", "intercept", nil)
	for _, group := range groups {
		for _, key := range group.keys {
			t.Run(group.name+"/"+key, func(t *testing.T) {
				metadata := group.makeMetadata(map[string]json.RawMessage{key: json.RawMessage(`null`)})
				c, err := New(reg, Options{Harness: ahp.Harness{Name: "test", Version: "1"}, Source: "urn:test:metadata", Events: testHost(), Metadata: metadata})
				if c != nil {
					c.Close()
					t.Fatal("colliding metadata acquired a client")
				}
				if err == nil {
					t.Fatal("known-key collision accepted")
				}
			})
		}
	}
}

func TestManifestMetadataCanonicalAdmission(t *testing.T) {
	cases := map[string]*ManifestMetadata{
		"invalid transport":        {Transports: ahp.Some([]ahp.StaticCapabilityManifestTransportsItem{"networksettings"})},
		"invalid authentication":   {Authentication: ahp.Some([]ahp.StaticCapabilityManifestAuthenticationItem{"networksettings"})},
		"invalid policy":           {ManagedPolicy: ahp.Some(ahp.StaticCapabilityManifestManagedPolicy{Scopes: []ahp.StaticCapabilityManifestManagedPolicyScopesItem{"networksettings"}, Disableable: true})},
		"unsupported policy":       {ManagedPolicy: ahp.Some(ahp.StaticCapabilityManifestManagedPolicy{Scopes: []ahp.StaticCapabilityManifestManagedPolicyScopesItem{"project"}, Disableable: true})},
		"negative upload limit":    {Limits: ahp.Some(ahp.StaticCapabilityManifestLimits{MaxUploadBytes: ahp.Some(json.Number("-1"))})},
		"fractional continuations": {Limits: ahp.Some(ahp.StaticCapabilityManifestLimits{MaxContinuations: ahp.Some(json.Number("0.5"))})},
		"timeout below minimum":    {Limits: ahp.Some(ahp.StaticCapabilityManifestLimits{MinTimeoutMs: ahp.Some(json.Number("1001"))})},
		"timeout above maximum":    {Limits: ahp.Some(ahp.StaticCapabilityManifestLimits{MaxTimeoutMs: ahp.Some(json.Number("999"))})},
		"invalid opaque JSON":      {AdditionalProperties: map[string]json.RawMessage{"vendor": json.RawMessage(`{`)}},
	}
	reg := eventOptionsRegistration(t, "tool.before", "intercept", nil)
	for name, metadata := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := New(reg, Options{Harness: ahp.Harness{Name: "test", Version: "1"}, Source: "urn:test:metadata", Events: capability.Host{ToolBefore: capability.ToolBefore{Deny: true}}, Metadata: metadata})
			if c != nil {
				c.Close()
				t.Fatal("invalid metadata acquired a client")
			}
			if err == nil {
				t.Fatal("invalid metadata bypassed canonical admission")
			}
		})
	}
}
