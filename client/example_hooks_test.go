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
		Intercept: func(context.Context, ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
			replacement, err := effect.ModifyInputReplace(struct {
				Path string `json:"path"`
			}{Path: "safe.txt"})
			if err != nil {
				return ahp.InterceptResponseResult{}, err
			}
			version := ahp.ProtocolVersion("draft")
			return ahp.InterceptResponseResult{ProtocolVersion: &version, Effects: []*ahp.Effect{
				replacement,
			}}, nil
		},
		Observe: func(context.Context, ahp.ObserveNotification) error { return nil },
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

	toolCapabilities, err := capability.Intercept(capability.Deny(), capability.ModifyInput(capability.Replace))
	if err != nil {
		panic(err)
	}
	narrowed, err := capability.Intercept(capability.ModifyInput(capability.Replace))
	if err != nil {
		panic(err)
	}
	hooks, err := client.New(registration, client.Options{
		Source: "urn:example:host",
		Events: map[string]client.EventCapabilities{
			"tool.before": toolCapabilities,
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
		client.WithCapabilities(*narrowed.Capabilities),
	)
	if err != nil {
		var decode *client.DecodeError
		if errors.As(err, &decode) && result != nil {
			// Protocol effects remain accepted. result.EffectiveInput is available;
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
		Intercept: func(context.Context, ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
			version := ahp.ProtocolVersion("draft")
			return ahp.InterceptResponseResult{ProtocolVersion: &version, Effects: []*ahp.Effect{}}, nil
		},
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
