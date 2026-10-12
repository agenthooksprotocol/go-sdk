package client

import (
	"context"
	"encoding/json"
	"io"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

// ContentResolver opens host-owned content. A ref is an opaque handle, not a URL
// that the SDK fetches. Each call must return a fresh reader for the same bytes.
// The SDK owns and closes the returned reader. Opening must honor ctx; Close
// must unblock a pending Read, because cancellation can close it concurrently.
type ContentResolver func(context.Context, string) (io.ReadCloser, error)

// ContentAuthorization identifies the local receiving backend and subscription.
// Item is a copy of the descriptor, not an authorization claim from the payload.
type ContentAuthorization struct {
	Operation      string // "read" for disclosure; "write" for new or changed inline text.
	BackendID      string
	SubscriptionID string
	Subscription   ahp.BackendSubscriptionsItem
	Item           ContentDescriptor
}

// ContentDescriptor is a pre-disclosure projection, not a selected wire item.
// It has no text, body, or gap. Selection is a request, not permission.
type ContentDescriptor struct {
	ID          string
	Kind        string
	MediaType   string
	Category    ahp.Optional[string]
	Selection   string
	Size        ahp.Optional[json.Number]
	Sha256      ahp.Optional[string]
	Synthesized ahp.Optional[bool]
	// AdditionalProperties retains unknown members as opaque JSON, without
	// interpreting nested descriptors, payloads, or authorization claims.
	AdditionalProperties map[string]json.RawMessage
}

func descriptorReserved(key string) bool {
	switch key {
	case "id", "kind", "mediaType", "category", "selection", "size", "sha256", "synthesized", "text", "body", "gap":
		return true
	}
	return false
}

// MarshalJSON prevents extension members from overriding known fields or
// adding disclosure payloads, including when callers modify the extension bag.
func (d ContentDescriptor) MarshalJSON() ([]byte, error) {
	fields := make(map[string]json.RawMessage, len(d.AdditionalProperties)+8)
	for key, raw := range d.AdditionalProperties {
		if !descriptorReserved(key) {
			fields[key] = raw
		}
	}
	known := map[string]any{"id": d.ID, "kind": d.Kind, "mediaType": d.MediaType, "selection": d.Selection}
	if d.Category.Present {
		known["category"] = d.Category.Value
	}
	if d.Size.Present {
		known["size"] = d.Size.Value
	}
	if d.Sha256.Present {
		known["sha256"] = d.Sha256.Value
	}
	if d.Synthesized.Present {
		known["synthesized"] = d.Synthesized.Value
	}
	for key, value := range known {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		fields[key] = raw
	}
	return json.Marshal(fields)
}

func contentDescriptor(item map[string]any, selection string) (ContentDescriptor, error) {
	d := ContentDescriptor{Selection: selection, AdditionalProperties: map[string]json.RawMessage{}}
	for key, value := range item {
		// Skip disclosure payloads before serialization, including owned sources.
		if key == "text" || key == "body" || key == "gap" || key == "selection" {
			continue
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return ContentDescriptor{}, err
		}
		switch key {
		case "id":
			err = json.Unmarshal(raw, &d.ID)
		case "kind":
			err = json.Unmarshal(raw, &d.Kind)
		case "mediaType":
			err = json.Unmarshal(raw, &d.MediaType)
		case "category":
			d.Category.Present = true
			err = json.Unmarshal(raw, &d.Category.Value)
		case "size":
			d.Size.Present = true
			err = json.Unmarshal(raw, &d.Size.Value)
		case "sha256":
			d.Sha256.Present = true
			err = json.Unmarshal(raw, &d.Sha256.Value)
		case "synthesized":
			d.Synthesized.Present = true
			err = json.Unmarshal(raw, &d.Synthesized.Value)
		default:
			d.AdditionalProperties[key] = raw
		}
		if err != nil {
			return ContentDescriptor{}, err
		}
	}
	return d, nil
}

func contentAuthorization(operation, backendID string, sub map[string]any) (ContentAuthorization, error) {
	registered, err := convertWire[ahp.BackendSubscriptionsItem](sub)
	if err != nil {
		return ContentAuthorization{}, err
	}
	scope := ContentAuthorization{Operation: operation, BackendID: backendID, Subscription: registered}
	scope.SubscriptionID, _ = sub["id"].(string)
	return scope, nil
}

// ContentOptions controls content disclosure independently from selection and
// event authentication. The zero value permits no body or opaque disclosure.
type ContentOptions struct {
	Resolver         ContentResolver
	AuthorizeContent func(context.Context, ContentAuthorization) (bool, error)
	// ProjectOpaque explicitly projects duplicate bytes in native/input/output/params/extensions and
	// other host-defined opaque fields. Native is considered only when includeNative
	// is true. A nil callback withholds opaque fields. It must return a safe view;
	// the SDK cannot discover embedded secrets in arbitrary application JSON.
	ProjectOpaque func(ctx context.Context, scope ContentAuthorization, path string, value any) (any, error)
	// AllowLoopbackHTTP permits HTTP only to literal loopback IPs or localhost.
	// Production upload endpoints require HTTPS and normal certificate validation.
	AllowLoopbackHTTP bool
}
