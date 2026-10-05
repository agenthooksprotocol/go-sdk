package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	ahp "github.com/agenthooksprotocol/go-sdk"
	hooks "github.com/agenthooksprotocol/go-sdk/client"
)

// fixtureTransport retains the adapter's authenticated HTTP/stdio connection;
// the public client owns envelope creation, delivery and protocol composition.
type fixtureTransport struct {
	exchange exchange
	received bool
}

func (t *fixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	var envelope Object
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	method := str(envelope["method"])
	reply, err := t.exchange(request.Context(), method, body)
	if err != nil {
		return nil, err
	}
	status := http.StatusOK
	if method == "hooks/observe" {
		status = http.StatusNoContent
	} else {
		t.received = true
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(reply)), Request: request}, nil
}

// PublicBoundaryOptions supplies host-owned content and pinned boundary context.
// Upload credentials remain separate from the event exchange.
type PublicBoundaryOptions struct {
	Content          hooks.ContentOptions
	ContentSelection Object
	Upload           Object
	UploadClient     *http.Client
	InterceptOptions []hooks.InterceptOption
	Accepted         func(*hooks.Result)
}

// PublicBoundary runs a fixture occurrence through the public client. The exchange
// retains host transport/auth and test-controller scheduling, not acceptance.
func PublicBoundary(ctx context.Context, request Object, exchange func(context.Context, string, []byte) ([]byte, error), settings ...PublicBoundaryOptions) (Object, bool, error) {
	params := obj(request["params"])
	ev := obj(params["event"])
	name := str(ev["type"])
	mode := "intercept"
	caps := params["capabilities"]
	if request["method"] == "hooks/observe" {
		mode = "observe"
		caps = Object{"effects": []any{}}
	}
	config := PublicBoundaryOptions{}
	if len(settings) > 0 {
		config = settings[0]
	}
	selection := config.ContentSelection
	if selection == nil {
		var err error
		selection, err = fixtureContentSelection(ev)
		if err != nil {
			return nil, false, err
		}
	}
	subscription := Object{"events": []any{name}, "mode": mode, "timeoutMs": 20000, "failurePolicy": "fail-closed", "content": selection, "includeNative": true}
	if mode == "observe" {
		delete(subscription, "timeoutMs")
		delete(subscription, "failurePolicy")
	}
	if config.Upload != nil {
		subscription["upload"] = config.Upload
	}
	registration := ahp.ParseRegistration(jsonBytes(Object{"protocolVersion": "draft", "hooks": []any{Object{"id": "org.agenthooks.interop", "transport": Object{"type": "http", "url": "http://127.0.0.1/hooks"}, "subscriptions": []any{subscription}}}}))
	if !registration.OK {
		return nil, false, fmt.Errorf("invalid fixture registration")
	}
	manifest := Object{"events": []any{Object{"event": name, "modes": []any{mode}, "capabilities": caps}}, "gaps": []any{}, "transports": []any{"http", "stdio"}, "authentication": []any{}, "toolPaths": []any{"execute"}, "contentCategories": []any{"text"}, "limits": Object{"maxContinuations": 4}, "managedPolicy": Object{"scopes": []any{"user"}, "disableable": true}, "correlationIdentityFields": []any{"event.id", "call.id"}}
	var typedManifest ahp.StaticCapabilityManifest
	if err := json.Unmarshal(jsonBytes(manifest), &typedManifest); err != nil {
		return nil, false, err
	}
	transport := &fixtureTransport{exchange: exchange}
	content := config.Content
	if content.ProjectOpaque == nil {
		content.ProjectOpaque = func(_ context.Context, _ hooks.ContentAuthorization, _ string, v any) (any, error) { return v, nil }
	}
	if content.AuthorizeContent == nil {
		content.AuthorizeContent = func(context.Context, hooks.ContentAuthorization) (bool, error) { return true, nil }
	}
	c, err := hooks.New(registration.Value, hooks.Options{Source: str(ev["source"]), Manifest: typedManifest, EventClient: &http.Client{Transport: transport}, UploadClient: config.UploadClient, Content: content})
	if err != nil {
		return nil, false, err
	}
	defer c.Close()
	var opts []hooks.InterceptOption
	if state, present := params["state"]; present {
		var initial ahp.InterceptRequestParamsState
		if err := json.Unmarshal(jsonBytes(state), &initial); err != nil {
			return nil, false, err
		}
		opts = append(opts, hooks.WithInitialState(initial))
	}
	opts = append(opts, config.InterceptOptions...)
	result, err := dispatchPublicBoundary(ctx, c, name, ev, opts)
	if err != nil {
		return nil, false, err
	}
	if result.Observations != nil {
		if failures, waitErr := result.Observations.Wait(ctx); waitErr != nil {
			return nil, false, waitErr
		} else if len(failures) > 0 {
			return nil, false, failures[0]
		}
	}
	if len(result.Errors) > 0 {
		return nil, transport.received, result.Errors[0]
	}
	if config.Accepted != nil {
		config.Accepted(result)
	}
	// Apply retains synthetic execution/native policy. Protocol delivery and atomic
	// acceptance above are the public SDK's, not this host evaluator's authority.
	var response Object
	if err := json.Unmarshal(jsonBytes(Object{"jsonrpc": "2.0", "id": request["id"], "result": result.Response}), &response); err != nil {
		return nil, false, err
	}
	return response, transport.received, nil
}

func jsonBytes(value any) []byte { data, _ := json.Marshal(value); return data }

func publicIntercept(ctx context.Context, request Object, exchange exchange) (Object, bool, error) {
	response, received, err := PublicBoundary(ctx, request, exchange)
	if err != nil {
		return nil, received, err
	}
	actual, err := Apply(request, response)
	return actual, false, err
}

// Fixtures have already selected disclosure per category. Reconstruct that local
// policy rather than upgrading a metadata-only descriptor into body disclosure.
func fixtureContentSelection(event Object) (Object, error) {
	conflict := false
	selection := Object{"default": "metadata"}
	var visit func(any)
	visit = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			if value["kind"] != nil && value["mediaType"] != nil && value["selection"] != nil {
				category := str(value["category"])
				if value["kind"] == "reasoning" {
					category = "reasoning"
				} else if category == "" {
					media := strings.ToLower(strings.Split(str(value["mediaType"]), ";")[0])
					switch {
					case strings.HasPrefix(media, "text/"), media == "application/json":
						category = "text"
					case strings.HasPrefix(media, "image/"):
						category = "images"
					case strings.HasPrefix(media, "audio/"):
						category = "audio"
					case strings.HasPrefix(media, "video/"):
						category = "video"
					default:
						category = "files"
					}
				}
				if prior, exists := selection[category]; exists && prior != value["selection"] {
					conflict = true
				}
				selection[category] = value["selection"]
			}
			for _, child := range value {
				visit(child)
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
		}
	}
	for _, field := range []string{"items", "instructions", "summary", "delta", "partialOutput", "message", "attention", "elicitation", "fileChanges"} {
		visit(event[field])
	}
	if conflict {
		return nil, fmt.Errorf("mixed per-item selection requires explicit host content policy")
	}
	return selection, nil
}
