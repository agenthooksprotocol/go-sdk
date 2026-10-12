package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

func typedEffect(t *testing.T, raw string) *ahp.ToolBeforeEffect {
	t.Helper()
	var effect ahp.ToolBeforeEffect
	if err := json.Unmarshal([]byte(raw), &effect); err != nil {
		t.Fatal(err)
	}
	return &effect
}

func TestTypedHTTPContextsRepliesAndObservation(t *testing.T) {
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(fixture(t, "intercept"), &wire); err != nil {
		t.Fatal(err)
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(wire["params"], &params); err != nil {
		t.Fatal(err)
	}
	params["state"] = json.RawMessage(`{"candidate":null,"permission":"none","opaque-state":{"nested":7}}`)
	params["extensions"] = json.RawMessage(`{"org.vendor":{"nested":true}}`)
	params["opaque-params"] = json.RawMessage(`{"exact":9007199254740993}`)
	wire["opaque-envelope"] = json.RawMessage(`{"array":[1,2]}`)
	var caps map[string]json.RawMessage
	_ = json.Unmarshal(params["capabilities"], &caps)
	caps["opaque-grant"] = json.RawMessage(`{"nested":true}`)
	params["capabilities"], _ = json.Marshal(caps)
	wire["params"], _ = json.Marshal(params)
	intercept, _ := json.Marshal(wire)
	if p := ahp.ParseInterceptRequest(intercept); !p.OK {
		t.Fatalf("parse: %+v", p)
	}
	if !canonical("intercept-request", intercept) {
		t.Fatalf("not canonical: %s", intercept)
	}
	interceptCalls, observeCalls := 0, 0
	h, err := NewHandler(Handlers{
		Intercept: InterceptHandlers{ToolBefore: func(ctx context.Context, c InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities]) (ToolBeforeReply, error) {
			interceptCalls++
			if c.Event.Tool.Name != "write_file" || !c.State.Present || !c.Extensions.Present || string(c.AdditionalProperties["opaque-params"]) != `{"exact":9007199254740993}` || string(c.EnvelopeExtras["opaque-envelope"]) != `{"array":[1,2]}` || string(c.Capabilities.AdditionalProperties["opaque-grant"]) != `{"nested":true}` {
				t.Fatalf("typed context lost data: %+v", c)
			}
			return ToolBeforeReply{Effects: []*ahp.ToolBeforeEffect{
				typedEffect(t, `{"type":"deny","reason":"first","extensions":{"org.evidence":{"number":9007199254740993}}}`),
				typedEffect(t, `{"type":"deny","reason":"second"}`),
			}, Extensions: c.Extensions, AdditionalProperties: map[string]json.RawMessage{"opaque-result": json.RawMessage(`{"nested":[true,null]}`), "protocolVersion": json.RawMessage(`"attacker"`)}, EnvelopeExtras: map[string]json.RawMessage{"opaque-envelope": json.RawMessage(`{"nested":true}`), "jsonrpc": json.RawMessage(`"bad"`), "id": json.RawMessage(`"bad"`), "result": json.RawMessage(`null`), "error": json.RawMessage(`{}`)}}, nil
		}},
		Observe: ObserveHandlers{ToolBefore: func(ctx context.Context, c ObserveContext[ahp.ToolBeforeEvent]) error {
			observeCalls++
			if c.Event.Tool.Name != "write_file" {
				t.Fatal("wrong observation")
			}
			return nil
		}},
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	response := request(h, intercept)
	if !ahp.ParseInterceptResponse(response.Body.Bytes()).OK || strings.Contains(response.Body.String(), `"error"`) {
		t.Fatalf("typed response: %s", response.Body)
	}
	text := response.Body.String()
	if !strings.Contains(text, `"opaque-envelope":{"nested":true}`) || strings.Contains(text, `"bad"`) || strings.Contains(text, `"attacker"`) {
		t.Fatalf("envelope ownership: %s", text)
	}
	if strings.Index(text, "first") >= strings.Index(text, "second") || !strings.Contains(text, `9007199254740993`) || !strings.Contains(text, `"opaque-result":{"nested":[true,null]}`) || !strings.Contains(text, `"extensions":{"org.vendor":{"nested":true}}`) {
		t.Fatalf("reply lost ordered opaque evidence: %s", text)
	}
	delete(wire, "id")
	wire["method"] = json.RawMessage(`"hooks/observe"`)
	observe, _ := json.Marshal(wire)
	response = request(h, observe)
	if response.Code != 204 || response.Body.Len() != 0 || interceptCalls != 1 || observeCalls != 1 {
		t.Fatalf("mixed dispatch: %d %d %d %s", interceptCalls, observeCalls, response.Code, response.Body)
	}
}

func TestTypedZeroReplyAndGrantValidation(t *testing.T) {
	for _, bad := range []bool{false, true} {
		h, err := NewHandler(Handlers{Intercept: InterceptHandlers{ToolBefore: func(context.Context, InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities]) (ToolBeforeReply, error) {
			if bad {
				return ToolBeforeReply{Effects: []*ahp.ToolBeforeEffect{typedEffect(t, `{"type":"message","text":"SECRET ungranted"}`)}}, nil
			}
			return ToolBeforeReply{}, nil
		}}}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		response := request(h, fixture(t, "intercept"))
		if bad {
			if !strings.Contains(response.Body.String(), "-32004") || strings.Contains(response.Body.String(), "SECRET") {
				t.Fatal(response.Body.String())
			}
		} else if !strings.Contains(response.Body.String(), `"effects":[]`) || !ahp.ParseInterceptResponse(response.Body.Bytes()).OK {
			t.Fatal(response.Body.String())
		}
	}
}

func TestTypedStdioUsesSameEngine(t *testing.T) {
	h, err := NewHandler(Handlers{Intercept: InterceptHandlers{ToolBefore: func(context.Context, InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities]) (ToolBeforeReply, error) {
		return ToolBeforeReply{}, nil
	}}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	compact := new(bytes.Buffer)
	if err := json.Compact(compact, fixture(t, "intercept")); err != nil {
		t.Fatal(err)
	}
	compact.WriteByte('\n')
	output := &typedWriteCloser{}
	if err := ServeStdio(context.Background(), io.NopCloser(compact), output, h); err != nil {
		t.Fatal(err)
	}
	if !ahp.ParseInterceptResponse(bytes.TrimSpace(output.Bytes())).OK || !strings.Contains(output.String(), `"id":"evt_http_001"`) || !strings.Contains(output.String(), `"effects":[]`) {
		t.Fatal(output.String())
	}
}

type typedWriteCloser struct{ bytes.Buffer }

func (*typedWriteCloser) Close() error { return nil }

func TestTypedToolArgumentsLossless(t *testing.T) {
	type args struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	called := false
	callback := WithToolBeforeArguments(testCodec[args]{}, func(ctx context.Context, c InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities], a args) (ToolBeforeReply, error) {
		called = true
		if a.Path != "README.md" {
			t.Fatal(a)
		}
		return ToolBeforeReply{}, nil
	})
	h, err := NewHandler(Handlers{Intercept: InterceptHandlers{ToolBefore: callback}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if response := request(h, fixture(t, "intercept")); strings.Contains(response.Body.String(), `"error"`) || !called {
		t.Fatal(response.Body.String())
	}
	called = false
	input := bytes.Replace(fixture(t, "intercept"), []byte(`"path": "README.md"`), []byte(`"path": "README.md", "future": {"exact":9007199254740993}`), 1)
	response := request(h, input)
	if called || !strings.Contains(response.Body.String(), "-32004") {
		t.Fatalf("lossy arguments accepted: %s", response.Body)
	}
	opaque := WithToolBeforeArguments(testCodec[map[string]json.RawMessage]{}, func(context.Context, InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities], map[string]json.RawMessage) (ToolBeforeReply, error) {
		called = true
		return ToolBeforeReply{}, nil
	})
	h, err = NewHandler(Handlers{Intercept: InterceptHandlers{ToolBefore: opaque}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if response := request(h, input); !called || strings.Contains(response.Body.String(), `"error"`) {
		t.Fatal(response.Body.String())
	}
}

func TestTypedSurfaceRejectsBroadCallbacks(t *testing.T) {
	source := `package rejected
import("context"; ahp "github.com/agenthooksprotocol/go-sdk"; "github.com/agenthooksprotocol/go-sdk/server")
var _ = server.Handlers{Intercept:func(context.Context,ahp.InterceptRequest)(ahp.InterceptResponseResult,error){panic("unreachable")}}
var _ = server.Handlers{Observe:func(context.Context,ahp.ObserveNotification)error{return nil}}
var _ = server.InterceptHandlers{ToolBefore:func(context.Context,server.InterceptContext[ahp.ToolAfterEvent,ahp.ToolAfterCapabilities])(server.ToolBeforeReply,error){panic("unreachable")}}
var _ = server.ToolBeforeReply{ProtocolVersion:nil}
var _ = server.ToolBeforeReply{Effects:[]*ahp.ToolAfterEffect{}}
`
	path := filepath.Join(t.TempDir(), "rejected.go")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("go", "build", path).CombinedOutput()
	if err == nil {
		t.Fatal("old broad server API compiled")
	}
	for _, want := range []string{"InterceptHandlers", "ObserveHandlers", "ToolAfterEvent", "unknown field ProtocolVersion", "[]*ahp.ToolAfterEffect"} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("missing compile rejection %q: %s", want, output)
		}
	}
}

// testCodec preserves the same lossless property without introducing client test cycles.
type testCodec[T any] struct{}

func (testCodec[T]) DecodeJSON(raw json.RawMessage) (T, error) {
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return value, err
	}
	var before, after any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	_ = d.Decode(&before)
	d = json.NewDecoder(bytes.NewReader(encoded))
	d.UseNumber()
	_ = d.Decode(&after)
	if !reflect.DeepEqual(before, after) {
		return value, errors.New("lossy codec")
	}
	return value, nil
}

func TestTypedMCPArgumentsSelectedBody(t *testing.T) {
	type args struct {
		Count int `json:"count"`
	}
	event := &ahp.ToolBeforeEvent{Tool: &ahp.ExecutionEventTool{Origin: ahp.ExecutionEventToolOriginMcp, Mcp: ahp.Some(&ahp.ExecutionEventMcp{ToolName: "read"}), Input: ahp.ExecutionEventToolInput{AdditionalProperties: map[string]json.RawMessage{"wrong-slot": json.RawMessage(`true`)}}}}
	c := InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities]{Event: event}
	called := false
	callback := func(ctx context.Context, c InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities], a args) (ToolBeforeReply, error) {
		called = true
		if a.Count != 7 {
			t.Fatal(a)
		}
		return ToolBeforeReply{}, nil
	}
	noBody := WithToolBeforeArguments(testCodec[args]{}, callback)
	if _, err := noBody(context.Background(), c); err == nil || called {
		t.Fatal("MCP decoded native input")
	}
	for _, body := range []string{
		`{"method":"tools/call","params":{"name":"read","arguments":{"count":7}},"opaque":{"nested":true}}`,
		`{"method":"tools/call","params":{"name":"other","arguments":{"count":7}}}`,
		`{"method":"tools/call","params":{"name":"read","arguments":{"count":7,"future":true}}}`,
	} {
		called = false
		bound := WithToolBeforeArguments(testCodec[args]{}, callback, func(context.Context, *ahp.ToolBeforeEvent) (json.RawMessage, error) {
			return json.RawMessage(body), nil
		})
		_, err := bound(context.Background(), c)
		valid := strings.Contains(body, `"opaque"`)
		if valid && (err != nil || !called) || !valid && (err == nil || called) {
			t.Fatalf("MCP body acceptance: %v %v", called, err)
		}
	}
}

// Transfer between typed callbacks and the private wire engine must not use
// serialization as an adapter. Only original incoming capability bytes decode;
// the authoritative outgoing envelope is serialized and validated by the engine.
func TestTypedTransferHelpersAvoidJSONRoundtrips(t *testing.T) {
	source, err := parser.ParseFile(token.NewFileSet(), "typed.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, decl := range source.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || (fn.Name.Name != "interceptContext" && fn.Name.Name != "wireReply") {
			continue
		}
		found[fn.Name.Name] = true
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if ok && pkg.Name == "json" && (selector.Sel.Name == "Marshal" || fn.Name.Name == "wireReply") {
				t.Errorf("%s must not serialize typed transfers", fn.Name.Name)
			}
			return true
		})
	}
	if !found["interceptContext"] || !found["wireReply"] {
		t.Fatal("transfer helper regression check lost its targets")
	}
}

func TestTypedCapabilitiesDecodeOriginalWireBytes(t *testing.T) {
	raw := json.RawMessage(`{"effects":["deny"],"opaque-grant":{"exact":9007199254740993}}`)
	ctx := context.WithValue(context.Background(), rawCapabilitiesKey{}, raw)
	// The broad parsed value deliberately differs. It must not become the source
	// of a typed-to-typed transfer or overwrite the original external evidence.
	request := ahp.InterceptRequest{}
	event := &ahp.ToolBeforeEvent{}
	c, err := interceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities](ctx, request, event)
	if err != nil {
		t.Fatal(err)
	}
	if c.Event != event || len(c.Capabilities.Effects) != 1 || c.Capabilities.Effects[0] != "deny" || string(c.Capabilities.AdditionalProperties["opaque-grant"]) != `{"exact":9007199254740993}` {
		t.Fatalf("original capability bytes lost: %+v", c)
	}
	if _, err := interceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities](context.Background(), request, event); err == nil {
		t.Fatal("missing incoming wire capabilities accepted")
	}
}
