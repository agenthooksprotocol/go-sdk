package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/capability"
	"github.com/agenthooksprotocol/go-sdk/client"
	"github.com/agenthooksprotocol/go-sdk/effect"
	"github.com/agenthooksprotocol/go-sdk/event"
	"github.com/agenthooksprotocol/go-sdk/permission"
	"github.com/agenthooksprotocol/go-sdk/server"
	"github.com/agenthooksprotocol/go-sdk/state"
)

func ExampleHooks_ToolBefore() {
	// The receiver is an ordinary http.Handler mounted on an owned server.
	handler, err := server.NewHandler(server.Handlers{
		Intercept: server.InterceptHandlers{ToolBefore: func(context.Context, server.InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities]) (server.ToolBeforeReply, error) {
			replacement, err := effect.ModifyInputReplace(struct {
				Path string `json:"path"`
			}{Path: "safe.txt"})
			if err != nil {
				return server.ToolBeforeReply{}, err
			}
			typed, err := exampleToolBeforeEffect(replacement)
			if err != nil {
				return server.ToolBeforeReply{}, err
			}
			return server.ToolBeforeReply{Effects: []*ahp.ToolBeforeEffect{typed}}, nil
		}},
		Observe: server.ObserveHandlers{ToolBefore: func(context.Context, server.ObserveContext[ahp.ToolBeforeEvent]) error { return nil }},
	}, server.Options{})
	if err != nil {
		panic(err)
	}
	peer := httptest.NewServer(handler)
	defer peer.Close()

	// Registration is ordinary JSON, e.g. bytes from os.ReadFile. No SDK loader.
	data := []byte(fmt.Sprintf(`{"protocolVersion":"draft","hooks":[{
  "id":"com.example.guard","transport":{"type":"http","url":%q},
  "subscriptions":[
   {"events":["tool.before"],"mode":"intercept","timeoutMs":1000,"failurePolicy":"fail-closed","content":{"default":"metadata"}},
   {"events":["tool.before"],"mode":"observe","content":{"default":"metadata"}}
  ]}]}`, peer.URL))
	var registration ahp.Registration
	if err := json.Unmarshal(data, &registration); err != nil {
		panic(err)
	}

	narrowed := ahp.Capabilities{
		Effects: []ahp.CapabilitiesEffectsItem{{Known: ahp.Some(ahp.CapabilitiesEffectsItemKnown("modify"))}},
		Modify:  ahp.Some(ahp.CapabilitiesModify{Input: ahp.Some(ahp.CapabilitiesModifyInput{Replace: true, Merge: false})}),
	}
	hooks, err := client.New(registration, client.Options{
		Source: "urn:example:host",
		Events: capability.Host{
			ToolBefore: capability.ToolBefore{Deny: true, ModifyInput: capability.Replace(), Observe: true},
		},
		EventClient: peer.Client(),
		// Application input disclosure is an explicit host decision, not a grant
		// inferred from registration or the event capability map.
		Content: client.ContentOptions{ProjectOpaque: func(_ context.Context, _ client.ContentAuthorization, _ string, value any) (any, error) {
			return value, nil
		}},
	})
	if err != nil {
		panic(err)
	}
	defer hooks.Close()

	type Arguments struct {
		Path string `json:"path"`
	}
	ctx := context.Background()
	initial := state.Initial(permission.None)
	result, err := hooks.ToolBefore(ctx, event.ToolBeforeInput[Arguments]{
		CallID: "call-1", Path: "execute",
		Name: "read_file", Origin: ahp.ExecutionEventToolOriginNative,
		Input: Arguments{Path: "original.txt"},
	},
		client.WithInitialState(*initial),
		client.WithCapabilities(narrowed),
	)
	if err != nil {
		var decode *client.DecodeError
		if errors.As(err, &decode) && result != nil {
			// Protocol effects remain accepted. sdkJSON(result.Event.ToolBeforeEvent.Value.Tool.Input) is available;
			// do not execute result.Input when InputAvailable is false.
			return
		}
		panic(err)
	}
	if result.Interrupted || !result.InputAvailable || result.Permission == "deny" || len(result.Diagnostics) != 0 {
		return
	}
	// None is not approval; Ask requires host approval. Apply native permission
	// policy and application validation before actual execution. Printing is not execution.
	fmt.Println(result.Input.Path)
	// All observation delivery is already complete when ToolBefore returns.
	fmt.Println(len(result.Diagnostics))
	// Output:
	// safe.txt
	// 0
}

func ExampleHooks_stdioServer() {
	handler, err := server.NewHandler(server.Handlers{
		Intercept: server.InterceptHandlers{ToolBefore: func(context.Context, server.InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities]) (server.ToolBeforeReply, error) {
			return server.ToolBeforeReply{}, nil
		}},
	}, server.Options{})
	if err != nil {
		panic(err)
	}
	// A standalone process owns these streams. ServeStdio closes them on exit;
	// use a cancellable application context for coordinated shutdown.
	if err := server.ServeStdio(context.Background(), os.Stdin, os.Stdout, handler); err != nil {
		panic(err)
	}
}

// Decode the event-specific union without dropping caller-owned payloads or extras.
func exampleToolBeforeEffect(value *ahp.Effect) (*ahp.ToolBeforeEffect, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var typed ahp.ToolBeforeEffect
	if err := json.Unmarshal(raw, &typed); err != nil {
		return nil, err
	}
	return &typed, nil
}
