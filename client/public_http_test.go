package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/effect"
	"github.com/agenthooksprotocol/go-sdk/event"
	"github.com/agenthooksprotocol/go-sdk/server"
	"github.com/agenthooksprotocol/go-sdk/transport"
)

func TestGenericBoundaryThroughPublicHTTPHandler(t *testing.T) {
	h, err := server.NewHandler(server.Handlers{Intercept: func(_ context.Context, r ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
		modification, err := effect.ModifyInputMerge(map[string]int{"count": 2})
		if err != nil {
			return ahp.InterceptResponseResult{}, err
		}
		version := ahp.ProtocolVersion("draft")
		return ahp.InterceptResponseResult{ProtocolVersion: &version, Effects: []*ahp.Effect{modification, effect.NewAllow()}}, nil
	}}, server.Options{})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(h)
	defer endpoint.Close()
	c, _ := testClient(t, "fail-closed")
	tr, err := newBackendTransport(&ahp.Backend{Transport: transport.NewHttp(endpoint.URL)}, endpoint.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.backends[0].transport = tr
	type Args struct {
		Count int `json:"count"`
	}
	result, err := c.ToolBefore(context.Background(), event.ToolBeforeInput[Args]{CallID: "call-public", Path: "execute", Name: "task", Origin: "native", Input: Args{Count: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if !result.InputAvailable || result.Input.Count != 2 || result.State.Permission != "allow" || len(result.Errors) != 0 {
		t.Fatalf("public result: %+v", result)
	}
	waitObservations(t, result.Result)
}

func TestGenericDecodeErrorThroughPublicHTTPHandler(t *testing.T) {
	h, err := server.NewHandler(server.Handlers{Intercept: func(_ context.Context, _ ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
		modification, err := effect.ModifyInputReplace(map[string]string{"count": "host-refuses"})
		if err != nil {
			return ahp.InterceptResponseResult{}, err
		}
		version := ahp.ProtocolVersion("draft")
		return ahp.InterceptResponseResult{ProtocolVersion: &version, Effects: []*ahp.Effect{modification}}, nil
	}}, server.Options{})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(h)
	defer endpoint.Close()
	c, _ := testClient(t, "fail-closed")
	tr, err := newBackendTransport(&ahp.Backend{Transport: transport.NewHttp(endpoint.URL)}, endpoint.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.backends[0].transport = tr
	type Args struct {
		Count int `json:"count"`
	}
	result, err := c.ToolBefore(context.Background(), event.ToolBeforeInput[Args]{CallID: "call-public", Path: "execute", Name: "task", Origin: "native", Input: Args{Count: 1}})
	var decode *DecodeError
	if !errors.As(err, &decode) || result == nil || result.InputAvailable || len(result.Errors) != 0 || len(result.Response.Effects) != 1 {
		t.Fatalf("public decode result: %+v %v", result, err)
	}
	raw, err := c.ToolBefore(context.Background(), event.ToolBeforeInput[json.RawMessage]{CallID: "call-dynamic", Path: "execute", Name: "task", Origin: "native", Input: json.RawMessage(`{"count":1}`)})
	if err != nil || !raw.InputAvailable || string(raw.Input) != `{"count":"host-refuses"}` {
		t.Fatalf("raw path: %+v %v", raw, err)
	}
}
