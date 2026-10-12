package ahp_test

import (
	"encoding/json"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/capability"
	"testing"
)

func TestCapabilitySupports(t *testing.T) {
	if (ahp.Capabilities{}).Supports(ahp.EffectDeny) {
		t.Fatal("zero grants")
	}
	for _, effects := range [][]ahp.CapabilitiesEffectsItem{
		{{Known: ahp.Some(ahp.CapabilitiesEffectsItemKnownDeny)}},
		{{Custom: ahp.Some("deny")}},
	} {
		caps := ahp.Capabilities{Effects: effects}
		if !caps.Supports(ahp.EffectDeny) || caps.Supports(ahp.EffectNameAllow) {
			t.Fatal("family membership")
		}
	}
	extension := ahp.Capabilities{Effects: []ahp.CapabilitiesEffectsItem{{Custom: ahp.Some("vendor.custom")}}}
	if !extension.Supports(ahp.EffectName("vendor.custom")) || extension.Supports(ahp.EffectDeny) {
		t.Fatal("custom family")
	}
	rawExtension, err := json.Marshal(extension)
	if err != nil {
		t.Fatal(err)
	}
	var decodedExtension ahp.Capabilities
	if err := json.Unmarshal(rawExtension, &decodedExtension); err != nil {
		t.Fatal(err)
	}
	if !decodedExtension.Supports(ahp.EffectName("vendor.custom")) || decodedExtension.Supports(ahp.EffectDeny) {
		t.Fatal("codec changed custom family")
	}
	// Queries follow the encoder's known-arm precedence, even for malformed manual unions.
	invalid := ahp.Capabilities{Effects: []ahp.CapabilitiesEffectsItem{{Known: ahp.Some(ahp.CapabilitiesEffectsItemKnownAllow), Custom: ahp.Some("deny")}}}
	if invalid.Supports(ahp.EffectDeny) {
		t.Fatal("inactive arm advertised")
	}
	req := ahp.InterceptRequest{}
	for _, wire := range []string{`{"effects":["deny"]}`, `{"effects":["vendor.custom","deny"]}`} {
		if err := json.Unmarshal([]byte(wire), &req.Params.Capabilities); err != nil {
			t.Fatal(err)
		}
		if !req.Params.Capabilities.Supports(ahp.EffectDeny) {
			t.Fatal("request capability query")
		}
	}
	req.Params.Capabilities.Effects = []ahp.InterceptRequestParamsCapabilitiesEffectsItem{{Custom: ahp.Some("deny")}}
	if !req.Params.Capabilities.Supports(ahp.EffectDeny) {
		t.Fatal("request custom representation")
	}
	wire := capability.Host{ToolBefore: capability.ToolBefore{Deny: true, ModifyInput: capability.Replace()}}.Wire()["tool.before"]
	raw, err := json.Marshal(wire.Capabilities)
	if err != nil {
		t.Fatal(err)
	}
	var caps ahp.Capabilities
	if err := json.Unmarshal(raw, &caps); err != nil {
		t.Fatal(err)
	}
	if !caps.Supports(ahp.EffectDeny) || !caps.Supports(ahp.EffectNameModify) || len(caps.Effects) != 2 {
		t.Fatal("shared grant membership")
	}
	// Family support is deliberately not an operation or target authorization query.
	if caps.Modify.Value.Input.Value.Merge || caps.Modify.Value.Output.Present {
		t.Fatal("ungranted operations/targets")
	}
	nestedOnly := ahp.Capabilities{Modify: caps.Modify}
	if nestedOnly.Supports(ahp.EffectNameModify) {
		t.Fatal("nested grant implied family support")
	}
	familyOnly := ahp.Capabilities{Effects: []ahp.CapabilitiesEffectsItem{{Known: ahp.Some(ahp.CapabilitiesEffectsItemKnownModify)}}}
	if !familyOnly.Supports(ahp.EffectNameModify) || familyOnly.Modify.Present {
		t.Fatal("family query implied nested grant")
	}
}
