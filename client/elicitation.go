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
	requestValid                      bool
	requestedSchema                   any // Parsed form contract, independent of attachment lifetime.
}

// prepareElicitation runs before any effects or receiver-specific projection.
// sources indexes attachment owners by canonical item path.
// Envelope/schema validation and body authorization remain the caller's job.
func prepareElicitation(event map[string]any, original *ElicitationRequest, sources map[string]*ContentSource) (*ElicitationRequest, error) {
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
		value, err := selectedElicitation(meta, "result", sources)
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
	value, err := selectedElicitation(meta, "request", sources)
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
	snapshot := &ElicitationRequest{id: id, source: source, session: elicitationSession(event), server: server, mode: mode, requestValid: value != nil}
	if value != nil {
		snapshot.requestedSchema = value["requestedSchema"]
	}
	if original != nil {
		if err := correlateElicitation(event, original); err != nil {
			return nil, err
		}
		// Never silently replace the original contract with a rewritten body.
		return original, nil
	}
	return snapshot, nil
}

func selectedElicitation(meta map[string]any, stage string, sources map[string]*ContentSource) (map[string]any, error) {
	item, _ := meta[stage].(map[string]any)
	if item == nil {
		return nil, nil
	}
	rawItem, err := json.Marshal(item)
	if err != nil || canonical.Validate("content-item", rawItem) != nil || item["kind"] != "text" {
		return nil, errors.New("invalid elicitation content descriptor")
	}
	text, present := item["text"].(string)
	raw := []byte(text)
	if !present {
		if item["selection"] == "body" {
			return nil, errors.New("selected elicitation body unavailable")
		}
		return nil, nil
	}
	if err := contentMatches(item, raw); err != nil {
		return nil, err
	}
	if err := canonical.Validate("mcp-elicitation#"+stage, raw); err != nil {
		return nil, err
	}
	var value map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return nil, errors.New("invalid elicitation JSON")
	}
	return value, nil
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
	if !snapshot.requestValid {
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
		if !present {
			content = map[string]any{}
		}
		return canonical.ValidateFormAnswer(snapshot.requestedSchema, content)
	}
	return nil
}
