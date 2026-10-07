package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	hooks "github.com/agenthooksprotocol/go-sdk/client"
	sdk "github.com/agenthooksprotocol/go-sdk/interop"
)

type senderSource struct {
	Descriptor O
	Bytes      string
}
type senderStep struct {
	Path, Bytes string
	Bypass      bool
	Headers     map[string]string
}
type senderPlan struct {
	Endpoint, Token, UploadToken string
	// StateFile is optional explicit host persistence; defaults to a private,
	// bounded endpoint/credential-scoped store shared by sender invocations.
	StateFile string
	// OriginalRequest explicitly supplies a real prior request when the caller
	// owns state elsewhere. Its original body must appear in ContentSources.
	OriginalRequest O
	ContentSources  []senderSource
	Steps           []senderStep
}

func senderSources(p senderPlan) (map[string][]byte, error) {
	sources := map[string][]byte{}
	var total int
	for _, source := range p.ContentSources {
		raw, err := base64.StdEncoding.Strict().DecodeString(source.Bytes)
		if err != nil {
			return nil, err
		}
		if len(raw) > 4<<20 {
			return nil, fmt.Errorf("source body exceeds limit")
		}
		ref := str(source.Descriptor["ref"])
		if ref == "" || source.Descriptor["sha256"] != hash(raw) {
			return nil, fmt.Errorf("invalid host source descriptor")
		}
		if size, ok := source.Descriptor["size"].(float64); !ok || size != float64(len(raw)) {
			return nil, fmt.Errorf("invalid host source size")
		}
		if prior, ok := sources[ref]; ok {
			if !bytes.Equal(prior, raw) {
				return nil, fmt.Errorf("mutable source reference")
			}
			continue
		}
		total += len(raw)
		if total > 16<<20 || len(sources) >= 1024 {
			return nil, fmt.Errorf("source catalogue exceeds bound")
		}
		sources[ref] = raw
	}
	return sources, nil
}

func pinRequest(request O, sources map[string][]byte) (pinnedRequest, error) {
	pin := pinnedRequest{Request: request, Bodies: map[string][]byte{}}
	item := obj(obj(obj(obj(request["params"])["event"])["elicitation"])["request"])
	ref := str(obj(item["body"])["ref"])
	if ref != "" {
		raw, ok := sources[ref]
		if !ok {
			return pin, fmt.Errorf("original request body unavailable")
		}
		pin.Bodies[ref] = bytes.Clone(raw)
	}
	return pin, nil
}

func resolver(sources map[string][]byte) hooks.ContentResolver {
	return func(_ context.Context, ref string) (io.ReadCloser, error) {
		raw, ok := sources[ref]
		if !ok {
			return nil, fmt.Errorf("missing host source bytes")
		}
		return io.NopCloser(bytes.NewReader(raw)), nil
	}
}

// Restore an opaque SDK snapshot from the actual original host occurrence and
// exact bytes. This local observation-only dispatch is not a replay to a receiver
// and cannot produce effects or pretend another request was accepted remotely.
func restoreSnapshot(ctx context.Context, pin pinnedRequest) (*hooks.ElicitationRequest, error) {
	note := O{"jsonrpc": "2.0", "method": "hooks/observe", "params": O{"protocolVersion": "draft", "event": obj(pin.Request["params"])["event"]}}
	var snapshot *hooks.ElicitationRequest
	_, _, err := sdk.PublicBoundary(ctx, note, func(context.Context, string, []byte) ([]byte, error) { return nil, nil }, sdk.PublicBoundaryOptions{
		Content: hooks.ContentOptions{Resolver: resolver(pin.Bodies)}, ContentSelection: O{"default": "metadata"},
		Accepted: func(result *hooks.Result) { snapshot = result.Snapshot },
	})
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, fmt.Errorf("public runtime did not retain original request snapshot")
	}
	return snapshot, nil
}

func sendOrdinary(ctx context.Context, p senderPlan, step senderStep, message O, client *http.Client) (O, error) {
	sources, err := senderSources(p)
	if err != nil {
		return nil, err
	}
	state, err := openHostState(ctx, p.Endpoint, p.Token, p.StateFile)
	if err != nil {
		return nil, err
	}
	defer state.Close()
	event := obj(obj(message["params"])["event"])
	stage := "request"
	options := sdk.PublicBoundaryOptions{Content: hooks.ContentOptions{Resolver: resolver(sources), AllowLoopbackHTTP: true}, Upload: O{"endpoint": p.Endpoint + "/upload", "timeoutMs": 10000, "maxBytes": 4 << 20}, UploadClient: &http.Client{Transport: elicitationUploadTransport{token: p.UploadToken}}}
	if event["type"] == "user.elicitation.result" {
		stage = "result"
		var pin pinnedRequest
		if p.OriginalRequest != nil {
			pin, err = pinRequest(p.OriginalRequest, sources)
		} else {
			pin, err = state.get(message)
		}
		if err != nil {
			return nil, err
		}
		snapshot, err := restoreSnapshot(ctx, pin)
		if err != nil {
			return nil, err
		}
		options.InterceptOptions = []hooks.InterceptOption{hooks.WithElicitationRequest(snapshot)}
	}
	status := 0
	var responseRaw []byte
	confirmations := []any{}
	_, _, err = sdk.PublicBoundary(ctx, message, func(ctx context.Context, _ string, raw []byte) ([]byte, error) {
		var projected O
		if err := json.Unmarshal(raw, &projected); err != nil {
			return nil, err
		}
		originalItem := obj(obj(event["elicitation"])[stage])
		projectedItem := obj(obj(obj(obj(projected["params"])["event"])["elicitation"])[stage])
		if ref := obj(projectedItem["body"]); ref != nil {
			confirmations = append(confirmations, O{"sourceRef": obj(originalItem["body"])["ref"], "descriptor": ref})
		}
		request, err := http.NewRequestWithContext(ctx, "POST", p.Endpoint+step.Path, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+p.Token)
		reply, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		defer reply.Body.Close()
		status = reply.StatusCode
		responseRaw, err = io.ReadAll(io.LimitReader(reply.Body, (4<<20)+1))
		if err != nil {
			return nil, err
		}
		if len(responseRaw) > 4<<20 {
			return nil, fmt.Errorf("response exceeds limit")
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("ordinary boundary HTTP %d", status)
		}
		return responseRaw, nil
	}, options)
	if err != nil {
		return nil, err
	}
	if stage == "request" {
		pin, err := pinRequest(message, sources)
		if err != nil {
			return nil, err
		}
		if err = state.put(pin); err != nil {
			return nil, err
		}
	} else if p.OriginalRequest == nil {
		if err = state.remove(message); err != nil {
			return nil, err
		}
	}
	return O{"status": status, "body": string(responseRaw), "contentUploads": confirmations}, nil
}

func runSender(ctx context.Context, p senderPlan, client *http.Client) ([]any, error) {
	results := []any{}
	for _, step := range p.Steps {
		body, err := base64.StdEncoding.Strict().DecodeString(step.Bytes)
		if err != nil {
			return nil, err
		}
		var message O
		if step.Path == "/hooks/intercept" && !step.Bypass {
			if err = json.Unmarshal(body, &message); err != nil {
				return nil, err
			}
			kind := obj(obj(message["params"])["event"])["type"]
			if kind != "user.elicitation.request" && kind != "user.elicitation.result" {
				return nil, fmt.Errorf("unsupported ordinary elicitation boundary")
			}
			result, err := sendOrdinary(ctx, p, step, message, client)
			if err != nil {
				return nil, err
			}
			results = append(results, result)
			continue
		}
		// Only explicitly marked adversarial intercepts, raw upload framing, and host
		// control operations use this byte driver. Ordinary result sends never do.
		request, err := http.NewRequestWithContext(ctx, "POST", p.Endpoint+step.Path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		token := p.Token
		if step.Path == "/upload" && p.UploadToken != "" {
			token = p.UploadToken
		}
		request.Header.Set("Authorization", "Bearer "+token)
		for name, value := range step.Headers {
			request.Header.Set(name, value)
		}
		reply, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		raw, err := io.ReadAll(io.LimitReader(reply.Body, (4<<20)+1))
		reply.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(raw) > 4<<20 {
			return nil, fmt.Errorf("response exceeds limit")
		}
		results = append(results, O{"status": reply.StatusCode, "body": string(raw)})
	}
	return results, nil
}
