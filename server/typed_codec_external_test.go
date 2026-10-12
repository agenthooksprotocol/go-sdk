package server_test

import (
	"context"
	"encoding/json"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/client"
	"github.com/agenthooksprotocol/go-sdk/server"
	"testing"
)

func TestClientCodecBindsServerArguments(t *testing.T) {
	type args struct {
		Count int `json:"count"`
	}
	called := false
	bound := server.WithToolBeforeArguments(client.JSONCodec[args](nil), func(context.Context, server.InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities], args) (server.ToolBeforeReply, error) {
		called = true
		return server.ToolBeforeReply{}, nil
	})
	c := server.InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities]{Event: &ahp.ToolBeforeEvent{Tool: &ahp.ExecutionEventTool{Origin: ahp.ExecutionEventToolOriginNative, Input: ahp.ExecutionEventToolInput{AdditionalProperties: map[string]json.RawMessage{"count": json.RawMessage(`1`), "future": json.RawMessage(`{"exact":9007199254740993}`)}}}}}
	if _, err := bound(context.Background(), c); err == nil || called {
		t.Fatal("client codec accepted dropped extras")
	}
	delete(c.Event.Tool.Input.AdditionalProperties, "future")
	if _, err := bound(context.Background(), c); err != nil || !called {
		t.Fatalf("client codec binding: %v", err)
	}
}
