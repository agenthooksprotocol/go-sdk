package client

import (
	"bytes"
	"encoding/json"
	"errors"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

// ManifestMetadata customizes non-event advertisement metadata. Events and
// capability grants come exclusively from Options.Events. Absent fields keep
// minimal defaults; explicit empty lists stay empty. Configuration is validated
// and detached at Hooks construction. Metadata is not execution permission.
type ManifestMetadata struct {
	Transports                ahp.Optional[[]ahp.StaticCapabilityManifestTransportsItem]
	Authentication            ahp.Optional[[]ahp.StaticCapabilityManifestAuthenticationItem]
	Gaps                      ahp.Optional[[]ahp.StaticCapabilityManifestGapsItem]
	ToolPaths                 ahp.Optional[[]string]
	ContentCategories         ahp.Optional[[]string]
	CorrelationIdentityFields ahp.Optional[[]string]
	Limits                    ahp.Optional[ahp.StaticCapabilityManifestLimits]
	ManagedPolicy             ahp.Optional[ahp.StaticCapabilityManifestManagedPolicy]
	AdditionalProperties      map[string]json.RawMessage
}

// validateManifestMetadata checks only fallible, caller-supplied non-event fields.
// The typed Host grants are transferred directly and never enter JSON admission.
func validateManifestMetadata(manifest map[string]any) error {
	metadata := make(map[string]any, len(manifest))
	for key, value := range manifest {
		if key != "events" {
			metadata[key] = value
		}
	}
	// The canonical envelope requires events; an empty placeholder excludes all
	// typed declarations while retaining canonical metadata constraints.
	metadata["events"] = []any{}
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "metadata", "result": map[string]any{"protocolVersion": "draft", "manifest": metadata}})
	if err != nil || canonical.Validate("capabilities-response", raw) != nil {
		return errors.New("invalid manifest metadata")
	}
	return nil
}

func metadataExtras(extras map[string]json.RawMessage, known ...string) (map[string]any, error) {
	out := map[string]any{}
	for key, value := range extras {
		for _, reserved := range known {
			if key == reserved {
				return nil, errors.New("metadata extras collide with a known field")
			}
		}
		out[key] = json.RawMessage(bytes.Clone(value))
	}
	return out, nil
}

func metadataStrings[T ~string](values []T) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func applyManifestMetadata(manifest map[string]any, metadata *ManifestMetadata) error {
	if metadata == nil {
		return nil
	}
	extras, err := metadataExtras(metadata.AdditionalProperties, "events", "transports", "authentication", "gaps", "toolPaths", "contentCategories", "correlationIdentityFields", "limits", "managedPolicy")
	if err != nil {
		return err
	}
	for key, value := range extras {
		manifest[key] = value
	}
	if metadata.Transports.Present {
		manifest["transports"] = metadataStrings(metadata.Transports.Value)
	}
	if metadata.Authentication.Present {
		manifest["authentication"] = metadataStrings(metadata.Authentication.Value)
	}
	if metadata.ToolPaths.Present {
		manifest["toolPaths"] = metadataStrings(metadata.ToolPaths.Value)
	}
	if metadata.ContentCategories.Present {
		manifest["contentCategories"] = metadataStrings(metadata.ContentCategories.Value)
	}
	if metadata.CorrelationIdentityFields.Present {
		manifest["correlationIdentityFields"] = metadataStrings(metadata.CorrelationIdentityFields.Value)
	}
	if metadata.Gaps.Present {
		gaps := make([]any, 0, len(metadata.Gaps.Value))
		for _, gap := range metadata.Gaps.Value {
			value, err := metadataExtras(gap.AdditionalProperties, "path", "reason")
			if err != nil {
				return err
			}
			value["path"], value["reason"] = gap.Path, gap.Reason
			gaps = append(gaps, value)
		}
		manifest["gaps"] = gaps
	}
	if metadata.Limits.Present {
		l := metadata.Limits.Value
		value, err := metadataExtras(l.AdditionalProperties, "maxContinuations", "maxTimeoutMs", "maxUploadBytes", "minTimeoutMs")
		if err != nil {
			return err
		}
		if l.MaxContinuations.Present {
			value["maxContinuations"] = l.MaxContinuations.Value
		}
		if l.MaxTimeoutMs.Present {
			value["maxTimeoutMs"] = l.MaxTimeoutMs.Value
		}
		if l.MaxUploadBytes.Present {
			value["maxUploadBytes"] = l.MaxUploadBytes.Value
		}
		if l.MinTimeoutMs.Present {
			value["minTimeoutMs"] = l.MinTimeoutMs.Value
		}
		manifest["limits"] = value
	}
	if metadata.ManagedPolicy.Present {
		p := metadata.ManagedPolicy.Value
		value, err := metadataExtras(p.AdditionalProperties, "scopes", "disableable")
		if err != nil {
			return err
		}
		value["scopes"], value["disableable"] = metadataStrings(p.Scopes), p.Disableable
		manifest["managedPolicy"] = value
	}
	return nil
}
