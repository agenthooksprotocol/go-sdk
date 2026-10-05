package client

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

// ElicitationRequest is an immutable snapshot of the original MCP request and
// its AHP requester identity. Obtain it from a request result and supply it when
// processing the corresponding elicitation result. A zero value cannot authorize
// an answer. Metadata-only snapshots establish correlation, not form validity.
// The snapshot does not establish transport authentication or URL permission.
type ElicitationRequest struct {
	id, source, session, server, mode string
	request                           string // Original validated bytes; strings cannot alias caller buffers.
}

// prepareElicitation runs before any effects or receiver-specific projection.
// bodies must contain integrity-verified original bytes indexed by body.ref.
// Envelope/schema validation and body authorization remain the caller's job.
func prepareElicitation(event map[string]any, original *ElicitationRequest, bodies map[string][]byte) (*ElicitationRequest, error) {
	kind, _ := event["type"].(string)
	if kind != "user.elicitation.request" && kind != "user.elicitation.result" {
		return nil, nil
	}
	if err := validateElicitationMetadata(event, original); err != nil {
		return nil, err
	}
	meta, _ := event["elicitation"].(map[string]any)
	server, _ := meta["server"].(string)
	mode, _ := meta["mode"].(string)
	if server == "" || (mode != "form" && mode != "url") {
		return nil, errors.New("invalid elicitation metadata")
	}
	if kind == "user.elicitation.result" {
		if err := correlateElicitation(event, original); err != nil {
			return nil, err
		}
		value, _, err := selectedElicitation(meta, "result", bodies)
		if err != nil {
			return nil, err
		}
		if value != nil {
			if err := validateElicitationAnswer(event, original, value); err != nil {
				return nil, err
			}
		}
		return original, nil
	}
	id, _ := event["id"].(string)
	source, _ := event["source"].(string)
	if id == "" || source == "" {
		return nil, errors.New("invalid elicitation requester identity")
	}
	value, raw, err := selectedElicitation(meta, "request", bodies)
	if err != nil {
		return nil, err
	}
	if value != nil {
		bodyMode := value["mode"]
		if bodyMode == nil {
			bodyMode = "form"
		}
		if bodyMode != mode {
			return nil, errors.New("elicitation request mode mismatch")
		}
	}
	snapshot := &ElicitationRequest{id: id, source: source, session: elicitationSession(event), server: server, mode: mode, request: string(raw)}
	if original != nil {
		if err := correlateElicitation(event, original); err != nil {
			return nil, err
		}
		// Never silently replace the original contract with a rewritten body.
		return original, nil
	}
	return snapshot, nil
}

func selectedElicitation(meta map[string]any, stage string, bodies map[string][]byte) (map[string]any, []byte, error) {
	item, _ := meta[stage].(map[string]any)
	if item == nil {
		return nil, nil, nil
	}
	rawItem, err := json.Marshal(item)
	if err != nil || canonical.Validate("content-item", rawItem) != nil || item["mediaType"] != "application/json" {
		return nil, nil, errors.New("invalid elicitation content descriptor")
	}
	if item["selection"] != "body" {
		return nil, nil, nil
	}
	body, _ := item["body"].(map[string]any)
	ref, _ := body["ref"].(string)
	raw, present := bodies[ref]
	if ref == "" || !present {
		return nil, nil, errors.New("selected elicitation body unavailable")
	}
	if err := canonical.Validate("mcp-elicitation#"+stage, raw); err != nil {
		return nil, nil, err
	}
	var value map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return nil, nil, errors.New("invalid elicitation JSON")
	}
	return value, raw, nil
}

// validateElicitationMetadata must run before any content resolver I/O. It checks
// correlation independently of selection or byte availability.
func validateElicitationMetadata(event map[string]any, original *ElicitationRequest) error {
	kind, _ := event["type"].(string)
	if kind != "user.elicitation.request" && kind != "user.elicitation.result" {
		return nil
	}
	meta, _ := event["elicitation"].(map[string]any)
	server, _ := meta["server"].(string)
	mode, _ := meta["mode"].(string)
	id, _ := event["id"].(string)
	source, _ := event["source"].(string)
	if id == "" || source == "" || server == "" || (mode != "form" && mode != "url") {
		return errors.New("invalid elicitation metadata")
	}
	if kind == "user.elicitation.result" {
		action, _ := meta["action"].(string)
		if action != "accept" && action != "decline" && action != "cancel" {
			return errors.New("invalid elicitation action")
		}
	}
	if kind == "user.elicitation.result" || original != nil {
		return correlateElicitation(event, original)
	}
	return nil
}

func elicitationSession(event map[string]any) string {
	session, _ := event["session"].(map[string]any)
	id, _ := session["id"].(string)
	return id
}

func correlateElicitation(event map[string]any, snapshot *ElicitationRequest) error {
	if snapshot == nil || snapshot.id == "" {
		return errors.New("original elicitation request required")
	}
	id := event["id"]
	if event["type"] == "user.elicitation.result" {
		id = event["parentEventId"]
	} else if event["type"] != "user.elicitation.request" {
		return errors.New("invalid elicitation boundary")
	}
	meta, _ := event["elicitation"].(map[string]any)
	if id != snapshot.id || event["source"] != snapshot.source || elicitationSession(event) != snapshot.session || meta["server"] != snapshot.server || meta["mode"] != snapshot.mode {
		return errors.New("elicitation requester correlation mismatch")
	}
	return nil
}

// validateElicitationAnswer accepts a complete MCP ElicitResult, including when
// supplied by a request-boundary return effect. Result-boundary replacements must
// retain the event's action and are checked against the original form contract.
func validateElicitationAnswer(event map[string]any, snapshot *ElicitationRequest, value any) error {
	if err := correlateElicitation(event, snapshot); err != nil {
		return err
	}
	if snapshot.request == "" {
		return errors.New("original elicitation request body required")
	}
	raw, err := json.Marshal(value)
	if err != nil || canonical.Validate("mcp-elicitation#result", raw) != nil {
		return errors.New("invalid MCP elicitation answer")
	}
	var answer map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&answer) != nil {
		return errors.New("invalid MCP elicitation answer")
	}
	meta, _ := event["elicitation"].(map[string]any)
	if event["type"] == "user.elicitation.result" && meta["action"] != answer["action"] {
		return errors.New("elicitation result action mismatch")
	}
	content, present := answer["content"]
	if present && (snapshot.mode != "form" || answer["action"] != "accept") {
		return errors.New("elicitation content only permitted for accepted forms")
	}
	if snapshot.mode == "form" && answer["action"] == "accept" {
		var request map[string]any
		d := json.NewDecoder(bytes.NewBufferString(snapshot.request))
		d.UseNumber()
		if d.Decode(&request) != nil {
			return errors.New("invalid original elicitation request")
		}
		if !present {
			content = map[string]any{}
		}
		return canonical.ValidateFormAnswer(request["requestedSchema"], content)
	}
	return nil
}
