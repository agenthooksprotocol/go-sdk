package auth

import (
	"encoding/json"

	"github.com/agenthooksprotocol/go-sdk/internal/authutil"
)

// BindingKind distinguishes absent, bearer and OAuth bindings without changing
// the generated wire models. Unknown kinds fail closed.
type BindingKind string

const (
	BindingNone   BindingKind = ""
	BindingBearer BindingKind = "bearer"
	BindingOAuth  BindingKind = "oauth"
)

// BearerBinding identifies exactly one host-owned secret source.
type BearerBinding struct{ TokenEnv, TokenRef string }

// OAuthBinding is a validated preset, not authorization to contact its URLs.
// Hosts must still enforce trust, DNS/redirect policy and locally allowed scopes.
type OAuthBinding struct {
	Issuer          string   `json:"issuer"`
	Resource        string   `json:"resource"`
	ClientID        string   `json:"clientId"`
	Flow            string   `json:"flow"`
	Scopes          []string `json:"scopes"`
	ClientSecretRef string   `json:"clientSecretRef"`
}

// Target is immutable normalized registration context. Accessors return copies;
// Request retains extension fields. Destination and OAuth resource are distinct.
type Target struct {
	request Request
	kind    BindingKind
	bearer  BearerBinding
	oauth   OAuthBinding
}

func (t Target) Kind() BindingKind             { return t.kind }
func (t Target) BackendID() string             { return t.request.BackendID }
func (t Target) Destination() string           { return t.request.Destination }
func (t Target) Purpose() Operation            { return t.request.Purpose }
func (t Target) Request() Request              { return copyRequest(t.request) }
func (t Target) Bearer() (BearerBinding, bool) { return t.bearer, t.kind == BindingBearer }
func (t Target) OAuth() (OAuthBinding, bool) {
	b := t.oauth
	b.Scopes = append([]string(nil), b.Scopes...)
	return b, t.kind == BindingOAuth
}

func validTargetURL(raw string, local bool) bool { return authutil.ValidURL(raw, local) }

// NormalizeTarget validates handwritten binding variants, preserving all raw
// extension fields. Local HTTP is permitted only for literal loopback/localhost
// destinations, matching Do; OAuth issuer/resource always require HTTPS.
func NormalizeTarget(request Request) (Target, error) {
	invalid := &Error{Code: CodeInvalidConfiguration}
	if (request.Purpose != Event && request.Purpose != Upload) || !validTargetURL(request.Destination, true) {
		return Target{}, invalid
	}
	t := Target{request: copyRequest(request)}
	if len(request.Binding) == 0 {
		return t, nil
	}
	var envelope struct {
		Type BindingKind `json:"type"`
	}
	if json.Unmarshal(request.Binding, &envelope) != nil || envelope.Type == BindingNone {
		return Target{}, invalid
	}
	t.kind = envelope.Type
	switch t.kind {
	case BindingBearer:
		if json.Unmarshal(request.Binding, &t.bearer) != nil || (t.bearer.TokenEnv == "") == (t.bearer.TokenRef == "") {
			return Target{}, invalid
		}
	case BindingOAuth:
		if json.Unmarshal(request.Binding, &t.oauth) != nil {
			return Target{}, invalid
		}
		b := t.oauth
		if !validTargetURL(b.Issuer, false) || !validTargetURL(b.Resource, false) || b.ClientID == "" {
			return Target{}, invalid
		}
		if b.Flow != "authorization_code_pkce" && b.Flow != "client_credentials" {
			return Target{}, &Error{Code: CodeUnsupportedBinding}
		}
		for _, scope := range b.Scopes {
			if !authutil.ValidScope(scope) {
				return Target{}, invalid
			}
		}
	default:
		return Target{}, &Error{Code: CodeUnsupportedBinding}
	}
	return t, nil
}
