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
	extension := capability.New([]string{"vendor.custom"})
	if !extension.Supports(ahp.EffectName("vendor.custom")) || extension.Supports(ahp.EffectDeny) {
		t.Fatal("custom family")
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
	event, err := capability.Intercept(capability.Deny(), capability.Deny(), capability.ModifyInput(capability.Replace))
	if err != nil {
		t.Fatal(err)
	}
	if !event.Capabilities.Supports(ahp.EffectDeny) || !event.Capabilities.Supports(ahp.EffectNameModify) || len(event.Capabilities.Effects) != 2 {
		t.Fatal("shared grant membership")
	}
	// Family support is deliberately not an operation or target authorization query.
	if event.Capabilities.Modify.Value.Input.Value.Merge || event.Capabilities.Modify.Value.Output.Present {
		t.Fatal("ungranted operations/targets")
	}
	if _, err := capability.Intercept(capability.ModifyInput(capability.ModifyOperation("unknown"))); err == nil {
		t.Fatal("unknown operation accepted")
	}
	if _, err := capability.Intercept(capability.ModifyInput()); err == nil {
		t.Fatal("empty operation grant accepted")
	}
	nestedOnly := capability.New([]string{}, capability.WithModify(event.Capabilities.Modify.Value))
	if nestedOnly.Supports(ahp.EffectNameModify) {
		t.Fatal("nested grant implied family support")
	}
	familyOnly := capability.New([]string{"modify"})
	if !familyOnly.Supports(ahp.EffectNameModify) || familyOnly.Modify.Present {
		t.Fatal("family query implied nested grant")
	}
}
