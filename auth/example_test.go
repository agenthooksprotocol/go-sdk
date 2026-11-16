package auth_test

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

func ExampleRoute() {
	provider := auth.Route(auth.Routes{
		Bearer: auth.NewBearerProvider(auth.BearerOptions{
			ResolveSecret: func(ctx context.Context, ref string) (string, error) {
				// Replace with a context-aware host vault lookup.
				if ref != "vault/event" {
					return "", &auth.Error{Code: auth.CodeCredentialUnavailable}
				}
				return "example-token", nil
			},
		}),
		// OAuth: managed, // optional auth/oauth provider, or a host-owned provider
	})
	request := auth.Request{
		BackendID: "example", Destination: "https://backend.example/events", Purpose: auth.Event,
		Binding: json.RawMessage(`{"type":"bearer","tokenRef":"vault/event"}`),
	}
	credential, err := provider.Credential(context.Background(), request)
	if err != nil {
		panic(err)
	}
	// Pass provider through client.Options.AuthProvider; do not print the token.
	fmt.Println(credential.Type)
	// Output: bearer
}

func ExampleNormalizeTarget() {
	target, err := auth.NormalizeTarget(auth.Request{
		BackendID: "example", Destination: "https://backend.example/events", Purpose: auth.Event,
		Binding: json.RawMessage(`{"type":"oauth","issuer":"https://issuer.example","resource":"https://backend.example","clientId":"host-client","flow":"authorization_code_pkce"}`),
	})
	if err != nil {
		panic(err)
	}
	binding, _ := target.OAuth()
	fmt.Println(target.Kind(), binding.Flow)
	// Output: oauth authorization_code_pkce
}
