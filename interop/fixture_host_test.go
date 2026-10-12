package interop

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func TestFixtureHostAlwaysNarrowsOccurrence(t *testing.T) {
	for _, noGrants := range []bool{false, true} {
		req := request("typed-fixture-grants")
		caps := obj(obj(req["params"])["capabilities"])
		if noGrants {
			caps = Object{"effects": []any{}}
			obj(req["params"])["capabilities"] = caps
		}
		caps["future"] = Object{"nested": []any{true, Object{"opaque": "retained"}}}
		if !noGrants {
			obj(obj(caps["modify"])["input"])["future"] = Object{"opaque": true}
		}
		expected := clone(caps)
		called := false
		_, _, err := PublicBoundary(context.Background(), req, func(_ context.Context, _ string, raw []byte) ([]byte, error) {
			var sent Object
			if err := json.Unmarshal(raw, &sent); err != nil {
				return nil, err
			}
			called = true
			if !reflect.DeepEqual(obj(sent["params"])["capabilities"], expected) {
				t.Errorf("dynamic occurrence capabilities changed: got %v, want %v", obj(sent["params"])["capabilities"], expected)
			}
			return jsonBytes(response(str(sent["id"]), []any{}...)), nil
		})
		if err != nil || !called {
			t.Fatalf("occurrence rejected: called=%v err=%v", called, err)
		}
	}
}

func TestFixtureHostNoGrantsCannotAcquireMessageAuthority(t *testing.T) {
	req := request("no-grants")
	obj(req["params"])["capabilities"] = Object{"effects": []any{}}
	_, _, err := PublicBoundary(context.Background(), req, func(_ context.Context, _ string, raw []byte) ([]byte, error) {
		var sent Object
		if err := json.Unmarshal(raw, &sent); err != nil {
			return nil, err
		}
		return jsonBytes(response(str(sent["id"]), Object{"type": "message", "text": "not granted"})), nil
	})
	if err == nil {
		t.Fatal("broad fixture host leaked message authority into no-grant occurrence")
	}
}

func TestFixtureHostRejectsUnrepresentableContinuationCounters(t *testing.T) {
	for _, flow := range []Object{
		{"operations": []any{"continue"}, "remainingContinuations": 2},
		{"operations": []any{"continue"}, "continuationCount": 0},
		{"operations": []any{"continue"}, "remainingContinuations": 1.5, "continuationCount": 0},
		{"operations": []any{"stop"}, "maxContinuations": json.Number("18446744073709551616")},
	} {
		_, err := fixtureHost([]any{Object{"event": "turn.finish.before", "modes": []any{"intercept"}, "capabilities": Object{"effects": []any{"flow"}, "flow": flow}}})
		if err == nil {
			t.Fatalf("unrepresentable counters silently accepted: %v", flow)
		}
	}
}

func TestFixtureDiscoveredManifestValidationPrecedesTypedMapping(t *testing.T) {
	manifest := obj(clone(catalogueManifest()))
	if err := validateFixtureManifest(manifest); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []any{Object{"effects": "wrong-type"}, Object{"effects": []any{"flow"}, "flow": Object{"operations": "wrong-type"}}} {
		bad := obj(clone(manifest))
		obj(array(bad["events"])[0])["capabilities"] = invalid
		if err := validateFixtureManifest(bad); err == nil {
			t.Fatal("invalid original discovered manifest was sanitized")
		}
	}
}
