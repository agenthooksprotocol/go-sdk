package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

type rpcErrorBody struct {
	ID    json.RawMessage `json:"id"`
	Error struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

func decodeRPCError(t *testing.T, body []byte) rpcErrorBody {
	t.Helper()
	var out rpcErrorBody
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("not a JSON-RPC error: %q", body)
	}
	return out
}

func TestInterceptWithoutHandlerIsUnsupportedEvent(t *testing.T) {
	typed, err := NewHandler(Handlers{Intercept: InterceptHandlers{ToolAfter: func(context.Context, InterceptContext[ahp.ToolAfterEvent, ahp.ToolAfterCapabilities]) (ToolAfterReply, error) {
		return ToolAfterReply{}, nil
	}}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := newWireHandler(wireHandlers{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]http.Handler{"typed": typed, "wire": wire} {
		w := request(h, fixture(t, "intercept"))
		got := decodeRPCError(t, w.Body.Bytes())
		if w.Code != 200 || got.Error.Code != -32002 || string(got.ID) != `"evt_http_001"` || got.Error.Data != nil {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
	}
}

func TestInterceptUnsupportedEventType(t *testing.T) {
	calls := 0
	h, err := newWireHandler(wireHandlers{Intercept: func(context.Context, ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
		calls++
		return noEffect(), nil
	}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, eventType := range []string{"vendor.custom", "session.end", "tool.progress"} {
		b := bytes.Replace(fixture(t, "intercept"), []byte(`"type": "tool.before"`), []byte(`"type": "`+eventType+`"`), 1)
		w := request(h, b)
		if got := decodeRPCError(t, w.Body.Bytes()); got.Error.Code != -32002 {
			t.Fatalf("%s: %s", eventType, w.Body)
		}
	}
	if calls != 0 {
		t.Fatal("unsupported event reached callback")
	}
}

func TestInterceptEventTypesMatchSchema(t *testing.T) {
	raw, err := os.ReadFile("../internal/canonical/schemas.json")
	if err != nil {
		t.Fatal(err)
	}
	var docs []struct {
		ID    string `json:"$id"`
		AllOf []struct {
			Properties struct {
				Params struct {
					Properties struct {
						Event struct {
							OneOf []struct {
								Ref string `json:"$ref"`
							} `json:"oneOf"`
						} `json:"event"`
					} `json:"properties"`
				} `json:"params"`
			} `json:"properties"`
		} `json:"allOf"`
	}
	if err := json.Unmarshal(raw, &docs); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, doc := range docs {
		if !strings.HasSuffix(doc.ID, "/intercept-request.schema.json") {
			continue
		}
		for _, part := range doc.AllOf {
			for _, variant := range part.Properties.Params.Properties.Event.OneOf {
				name := variant.Ref
				if i := strings.LastIndex(name, "/$defs/"); i >= 0 {
					name = name[i+len("/$defs/"):]
				} else {
					name = strings.ReplaceAll(strings.TrimSuffix(name, ".schema.json"), "-", ".")
				}
				want[name] = true
			}
		}
	}
	if len(want) == 0 || len(want) != len(interceptEventTypes) {
		t.Fatalf("schema %v, handler %v", want, interceptEventTypes)
	}
	for name := range want {
		if !interceptEventTypes[name] {
			t.Fatalf("missing intercept event type %q", name)
		}
	}
}

func TestMissingCapabilitiesHandlerIsMethodNotFound(t *testing.T) {
	h, err := NewHandler(Handlers{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	w := request(h, []byte(`{"jsonrpc":"2.0","id":7,"method":"hooks/capabilities","params":{"protocolVersion":"draft"}}`))
	if got := decodeRPCError(t, w.Body.Bytes()); got.Error.Code != -32601 || string(got.ID) != "7" {
		t.Fatal(w.Body.String())
	}
}

func TestUnsupportedVersionCarriesSupportedList(t *testing.T) {
	h, err := NewHandler(Handlers{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b := bytes.Replace(fixture(t, "intercept"), []byte(`"protocolVersion": "draft"`), []byte(`"protocolVersion": "1999-01-01"`), 1)
	got := decodeRPCError(t, request(h, b).Body.Bytes())
	var data struct {
		Supported []string `json:"supported"`
	}
	if got.Error.Code != -32001 || json.Unmarshal(got.Error.Data, &data) != nil || len(data.Supported) != 1 || data.Supported[0] != ahp.ProtocolVersionValue {
		t.Fatalf("%+v %s", got.Error, got.Error.Data)
	}
}

func TestMissingObserverIsSilentSuccess(t *testing.T) {
	var mu sync.Mutex
	var diagnostics []error
	opts := Options{Diagnostic: func(_ context.Context, err error) {
		mu.Lock()
		defer mu.Unlock()
		diagnostics = append(diagnostics, err)
	}}
	missing, err := NewHandler(Handlers{Observe: ObserveHandlers{ToolBefore: func(context.Context, ObserveContext[ahp.ToolBeforeEvent]) error { return nil }}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	nilObserve, err := newWireHandler(wireHandlers{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]http.Handler{"typed": missing, "wire": nilObserve} {
		w := request(h, fixture(t, "observe"))
		if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
			t.Fatalf("%s: %d %q", name, w.Code, w.Body)
		}
	}
	if len(diagnostics) != 2 || !errors.Is(diagnostics[0], ErrObserverUnavailable) || !errors.Is(diagnostics[1], ErrObserverUnavailable) {
		t.Fatal(diagnostics)
	}
	diagnostics = nil
	failing, err := NewHandler(Handlers{Observe: ObserveHandlers{ToolAfter: func(context.Context, ObserveContext[ahp.ToolAfterEvent]) error { return errors.New("SECRET") }}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	panicking, err := NewHandler(Handlers{Observe: ObserveHandlers{ToolAfter: func(context.Context, ObserveContext[ahp.ToolAfterEvent]) error { panic("SECRET") }}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]http.Handler{"error": failing, "panic": panicking} {
		w := request(h, fixture(t, "observe"))
		if w.Code != http.StatusInternalServerError || w.Body.Len() != 0 {
			t.Fatalf("%s: observer failure must be an empty non-2xx: %d %q", name, w.Code, w.Body)
		}
	}
	if len(diagnostics) != 0 {
		t.Fatal("observer failure reported as missing observer")
	}
}

func TestStdioDropsNotificationBodyAndContinues(t *testing.T) {
	notification := `{"jsonrpc":"2.0","method":"hooks/observe","params":{}}`
	request := `{"jsonrpc":"2.0","id":"r1","method":"custom","params":{}}`
	for name, body := range map[string]string{
		"envelope":  `{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"x"}}`,
		"garbage":   "<html>not json</html>",
		"too large": strings.Repeat("x", int(DefaultMaxFrameBytes)+1),
	} {
		t.Run(name, func(t *testing.T) {
			in := &readClose{Reader: strings.NewReader(notification + "\n" + request + "\n")}
			out := new(writeClose)
			var diagnostics []error
			err := ServeStdioWithOptions(context.Background(), in, out, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				if bytes.Contains(b, []byte(`"id"`)) {
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"r1","result":{}}`)
					return
				}
				_, _ = io.WriteString(w, body)
			}), StdioOptions{Diagnostic: func(_ context.Context, err error) { diagnostics = append(diagnostics, err) }})
			if err != nil {
				t.Fatal(err)
			}
			if out.String() != `{"jsonrpc":"2.0","id":"r1","result":{}}`+"\n" {
				t.Fatalf("output %q", out.String())
			}
			if len(diagnostics) != 1 || !errors.Is(diagnostics[0], ErrNotificationResponse) {
				t.Fatal(diagnostics)
			}
		})
	}
}
