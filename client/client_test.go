package client

import (
	"context"
	"encoding/json"
	"errors"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"reflect"
	"sync"
	"testing"
	"time"
)

type testTransport struct {
	mu    sync.Mutex
	calls []map[string]any
	reply func(map[string]any) []any
	err   error
}

func (t *testTransport) Exchange(ctx context.Context, b []byte, note bool) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var req map[string]any
	_ = json.Unmarshal(b, &req)
	t.calls = append(t.calls, req)
	if t.err != nil {
		return nil, t.err
	}
	if note {
		return nil, nil
	}
	effects := []any{}
	if t.reply != nil {
		effects = t.reply(req)
	}
	return sdkJSON(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"protocolVersion": "draft", "effects": effects}}), nil
}
func (t *testTransport) Close() error { return nil }
func testCaps() map[string]any {
	return map[string]any{"effects": []any{"deny", "allow", "ask", "modify", "return"}, "modify": map[string]any{"input": map[string]any{"replace": true, "merge": true}}}
}
func testClient(t *testing.T, policies ...string) (*Client, []*testTransport) {
	t.Helper()
	hooks := []any{}
	for i, p := range policies {
		hooks = append(hooks, map[string]any{"id": "com.example.backend" + string(rune('a'+i)), "transport": map[string]any{"type": "http", "url": "http://127.0.0.1/hooks"}, "subscriptions": []any{map[string]any{"events": []any{"tool.before"}, "mode": "intercept", "timeoutMs": 1000, "failurePolicy": p, "content": map[string]any{"default": "metadata"}}}})
	}
	reg := ahp.ParseRegistration(sdkJSON(map[string]any{"protocolVersion": "draft", "hooks": hooks}))
	if !reg.OK {
		t.Fatal(reg.Diagnostics)
	}
	manifest := map[string]any{"events": []any{map[string]any{"event": "tool.before", "modes": []any{"intercept", "observe"}, "capabilities": testCaps()}}, "gaps": []any{}, "transports": []any{"http", "stdio"}, "authentication": []any{}, "toolPaths": []any{"execute"}, "contentCategories": []any{"text"}, "limits": map[string]any{"maxUploadBytes": 4096, "maxContinuations": 0}, "managedPolicy": map[string]any{"scopes": []any{"user"}, "disableable": true}, "correlationIdentityFields": []any{"event.id", "call.id"}}
	var typed ahp.StaticCapabilityManifest
	if err := json.Unmarshal(sdkJSON(manifest), &typed); err != nil {
		t.Fatal(err)
	}
	c, err := New(reg.Value, Options{Source: "urn:test:host", Manifest: typed, Content: ContentOptions{ProjectOpaque: func(_ context.Context, _ ContentAuthorization, _ string, v any) (any, error) { return v, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	ts := []*testTransport{}
	for i := range c.backends {
		_ = c.backends[i].transport.Close()
		tr := &testTransport{}
		c.backends[i].transport = tr
		ts = append(ts, tr)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, ts
}
func testInput() map[string]any {
	return map[string]any{"id": "event-1", "time": "2026-01-01T00:00:00Z", "call": map[string]any{"id": "call-1"}, "path": "execute", "tool": map[string]any{"name": "task", "kind": "task", "origin": "native", "input": map[string]any{"count": 1}}}
}
func waitObservations(t *testing.T, r *Result) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	es, err := r.Observations.Wait(ctx)
	if err != nil || len(es) != 0 {
		t.Fatalf("observations: %v %v", es, err)
	}
}

func TestSerialCompositionAndNativeApprovalInvalidation(t *testing.T) {
	c, ts := testClient(t, "fail-closed", "fail-closed")
	ts[0].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "modify", "target": "input", "operation": "merge", "value": map[string]any{"count": 2}}}
	}
	ts[1].reply = func(r map[string]any) []any {
		p := sdkObj(r["params"])
		if sdkObj(p["state"])["permission"] == "allow" {
			t.Error("native approval survived changed input")
		}
		if sdkObj(sdkObj(sdkObj(p["event"])["tool"])["input"])["count"] != float64(2) {
			t.Error("second backend missed accepted input")
		}
		return []any{map[string]any{"type": "ask"}}
	}
	var initial ahp.InterceptRequestParamsState
	_ = json.Unmarshal([]byte(`{"permission":"allow","candidate":null}`), &initial)
	input := testInput()
	before := sdkJSON(input)
	r, err := c.intercept(context.Background(), "tool.before", input, WithInitialState(initial))
	if err != nil {
		t.Fatal(err)
	}
	waitObservations(t, r)
	if len(r.Errors) != 0 || r.State.Permission != "ask" {
		t.Fatalf("result: %+v", r)
	}
	if string(before) != string(sdkJSON(input)) {
		t.Fatal("caller input mutated")
	}
	if ts[0].calls[0]["id"] != ts[1].calls[0]["id"] {
		t.Fatal("correlation changed")
	}
}
func TestTypedDecodeFailurePreservesProtocolAcceptance(t *testing.T) {
	c, ts := testClient(t, "fail-closed")
	ts[0].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "modify", "target": "input", "operation": "replace", "value": map[string]any{"count": "not-an-integer"}}, map[string]any{"type": "allow"}}
	}
	type Args struct {
		Count int `json:"count"`
	}
	r, err := decodeToolBefore[Args](c.intercept(context.Background(), "tool.before", testInput()))
	var decode *DecodeError
	if !errors.As(err, &decode) || r == nil || r.InputAvailable {
		t.Fatalf("decode contract: %+v %v", r, err)
	}
	if r.State.Permission != "allow" || len(r.Response.Effects) != 2 || len(r.Errors) != 0 {
		t.Fatalf("accepted effects lost: %+v", r)
	}
	if string(r.EffectiveInput) != `{"count":"not-an-integer"}` {
		t.Fatal(string(r.EffectiveInput))
	}
}
func TestShortCircuitObservesOnlyUncalledSubscriptions(t *testing.T) {
	c, ts := testClient(t, "fail-closed", "fail-open", "fail-closed")
	ts[0].reply = func(map[string]any) []any { return []any{map[string]any{"type": "deny", "reason": "no"}} }
	r, err := c.intercept(context.Background(), "tool.before", testInput())
	if err != nil {
		t.Fatal(err)
	}
	waitObservations(t, r)
	for i, tr := range ts {
		tr.mu.Lock()
		if len(tr.calls) != 1 {
			t.Errorf("backend %d: %d calls", i, len(tr.calls))
		} else {
			want := "hooks/observe"
			if i == 0 {
				want = "hooks/intercept"
			}
			if tr.calls[0]["method"] != want {
				t.Errorf("backend %d wrong method", i)
			}
		}
		tr.mu.Unlock()
	}
}
func TestAdmissionRejectsCapabilitiesExpansionBeforeIO(t *testing.T) {
	c, ts := testClient(t, "fail-open")
	caps := testCaps()
	caps["effects"] = append(sdkArray(caps["effects"]), "flow")
	caps["flow"] = map[string]any{"operations": []any{"stop"}}
	var typed ahp.Capabilities
	_ = json.Unmarshal(sdkJSON(caps), &typed)
	r, err := c.intercept(context.Background(), "tool.before", testInput(), WithCapabilities(typed))
	if err == nil || r != nil || len(ts[0].calls) != 0 {
		t.Fatal("expanded capabilities admitted")
	}
}
func TestFailClosedKeepsEarlierEffectsAndAuditsFailure(t *testing.T) {
	c, ts := testClient(t, "fail-open", "fail-closed")
	ts[0].reply = func(map[string]any) []any {
		return []any{map[string]any{"type": "modify", "target": "input", "operation": "merge", "value": map[string]any{"accepted": true}}}
	}
	ts[1].err = errors.New("unavailable")
	r, err := c.intercept(context.Background(), "tool.before", testInput())
	if err != nil {
		t.Fatal(err)
	}
	if r.State.Permission != "deny" || len(r.Errors) != 1 || !r.Errors[0].FailClosed || len(r.Response.Effects) != 1 {
		t.Fatalf("bad prefix: %+v", r)
	}
	var input map[string]any
	_ = json.Unmarshal(r.EffectiveInput, &input)
	if !reflect.DeepEqual(input, map[string]any{"count": float64(1), "accepted": true}) {
		t.Fatal(input)
	}
}
func TestCancelledBoundaryCannotBecomeFailOpenSuccess(t *testing.T) {
	c, ts := testClient(t, "fail-open")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := c.intercept(ctx, "tool.before", testInput())
	if !errors.Is(err, context.Canceled) || r == nil || !r.Interrupted {
		t.Fatalf("%+v %v", r, err)
	}
	waitObservations(t, r)
	for _, call := range ts[0].calls {
		if call["method"] == "hooks/intercept" {
			t.Fatal("cancelled request sent")
		}
	}
}

func TestCapabilityNarrowingCannotAddEmptyOptionBlock(t *testing.T) {
	if sdkNarrow(map[string]any{"effects": []any{"return"}}, map[string]any{"effects": []any{"return"}, "elicitation": map[string]any{"form": map[string]any{}}}) {
		t.Fatal("empty advertised blocks widened capabilities")
	}
}

func TestConfigurationIsSnapshottedAndCloseRejectsNewWork(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := c.intercept(context.Background(), "tool.before", testInput())
	var admission *AdmissionError
	if r != nil || !errors.As(err, &admission) {
		t.Fatalf("closed call: %+v %v", r, err)
	}
}

func TestEffectiveInputPreservesLargeApplicationIntegers(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	input := testInput()
	sdkObj(input["tool"])["input"] = map[string]any{"count": json.Number("18446744073709551615")}
	type Args struct {
		Count uint64 `json:"count"`
	}
	r, err := decodeToolBefore[Args](c.intercept(context.Background(), "tool.before", input))
	if err != nil || !r.InputAvailable || r.Input.Count != ^uint64(0) {
		t.Fatalf("number precision: %+v %v", r, err)
	}
}

func TestAbsentInitialStateRemainsAbsentOnFirstDelivery(t *testing.T) {
	c, ts := testClient(t, "fail-open", "fail-open")
	r, err := c.intercept(context.Background(), "tool.before", testInput())
	if err != nil {
		t.Fatal(err)
	}
	waitObservations(t, r)
	if _, present := sdkObj(ts[0].calls[0]["params"])["state"]; present {
		t.Fatal("invented optional initial wire state")
	}
	if _, present := sdkObj(ts[1].calls[0]["params"])["state"]; !present {
		t.Fatal("accepted prefix absent from later delivery")
	}
}
