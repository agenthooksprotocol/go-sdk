package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"github.com/agenthooksprotocol/go-sdk/internal/authutil"
)

// This file is the scope decision procedure: decide chooses every scope
// outcome and refuse is the only constructor of an error carrying scopes;
// classify is the only place that turns an error into the host-facing
// *auth.Error. No other code decides scopes or attaches them to errors.

// operation is the entry point a decision is made for.
type operation int

const (
	// opCredential is Credential (delivery with a binding or a learned one).
	opCredential operation = iota
	// opPreemptive is PreemptiveCredential (up-front lookup).
	opPreemptive
	// opChallenge is Challenge (a 401 or 403 response).
	opChallenge
	// opPrepare is Prepare and PrepareWith: the only op that creates a login.
	opPrepare
)

// challengeKind classifies a challenged response.
type challengeKind int

const (
	noChallenge challengeKind = iota
	// unauthorized is a 401; its scope, if any, is a hint P.
	unauthorized
	// insufficient is a Bearer 403 insufficient_scope with a valid scope (Ch).
	insufficient
	// insufficientBare is a Bearer 403 insufficient_scope without scope.
	insufficientBare
	// forbidden is any other 403.
	forbidden
	// malformed is an unparseable or ambiguous challenge, or a malformed scope.
	malformed
)

type challenge struct {
	kind challengeKind
	// status is the challenged HTTP status (0 for none).
	status int
	scopes []string
	// header is the raw WWW-Authenticate value, for resource_metadata discovery.
	header string
}

// parseChallenge classifies a challenged status and its WWW-Authenticate
// header. A status of zero is no challenge. The scope grammar is strict:
// single spaces between RFC 6749 tokens, one scope parameter, one Bearer
// challenge.
func parseChallenge(status int, header string) challenge {
	if status == 0 {
		return challenge{}
	}
	parsed := challenge{status: status, header: header}
	challenges, ok := authutil.ParseWWWAuthenticate(header)
	if !ok {
		parsed.kind = malformed
		return parsed
	}
	var bearer *authutil.Challenge
	for i := range challenges {
		if strings.EqualFold(challenges[i].Scheme, "Bearer") {
			if bearer != nil {
				parsed.kind = malformed
				return parsed
			}
			bearer = &challenges[i]
		}
	}
	var scope string
	var hasScope bool
	if bearer != nil && bearer.Token68 != "" {
		// A Bearer challenge takes auth-params (RFC 6750), never token68:
		// "Bearer scope" is a bad auth-param.
		parsed.kind = malformed
		return parsed
	}
	if bearer != nil {
		scope, hasScope = bearer.Params["scope"]
		if hasScope && !authutil.ValidScopeList(scope) {
			parsed.kind = malformed
			return parsed
		}
	}
	if hasScope {
		parsed.scopes = merge(strings.Split(scope, " "))
	}
	switch {
	case status == 401:
		parsed.kind = unauthorized
	case status != 403 || bearer == nil || bearer.Params["error"] != "insufficient_scope":
		parsed.kind, parsed.scopes = forbidden, nil
	case hasScope:
		parsed.kind = insufficient
	default:
		parsed.kind = insufficientBare
	}
	return parsed
}

// presetScopes returns an explicit OAuth preset's scopes and whether the
// preset names any: an omitted scopes field is no constraint.
func presetScopes(r auth.Request) ([]string, bool) {
	var fields struct {
		Type   string           `json:"type"`
		Scopes *json.RawMessage `json:"scopes"`
	}
	if json.Unmarshal(r.Binding, &fields) != nil || fields.Type != "oauth" || fields.Scopes == nil || string(*fields.Scopes) == "null" {
		return nil, false
	}
	var scopes []string
	if json.Unmarshal(*fields.Scopes, &scopes) != nil {
		return nil, true
	}
	return append([]string{}, scopes...), true
}

// outcome is what an operation does next.
type outcome int

const (
	outcomeFail outcome = iota
	// outcomeUse serves the stored token.
	outcomeUse
	// outcomeRefresh refreshes the stored grant.
	outcomeRefresh
	// outcomeAcquire issues a client-credentials grant.
	outcomeAcquire
	// outcomeLogin creates a pending login (prepare only).
	outcomeLogin
)

// decisionInput is everything decide reads. config.Scopes is S,
// allowedScopes(config) is C and config.RequiredScopes is H; explicit is E.
// sent is the grant generation whose token was rejected ("" when none).
type decisionInput struct {
	op        operation
	config    ClientConfig
	preset    []string
	hasPreset bool
	explicit  []string
	challenge challenge
	grant     *Record
	sent      string
}

// decision is decide's single outcome.
type decision struct {
	outcome outcome
	err     error
	// required is R = H ∪ E ∪ Ch.
	required []string
	// hint is P′, the 401 hint within the ceiling, requested only by a
	// client-credentials acquisition in this operation.
	hint []string
	// retire asks the caller to retire the rejected (sent) generation.
	retire bool
	// early marks a failure decided without the grant (steps 1, 2 and 4).
	early bool
	// disagrees marks the step 5 refusal: the stored grant already records R.
	disagrees bool
	ceiling   []string
}

// decide runs the scope decision procedure; the first matching step wins.
func decide(in decisionInput) decision {
	c := in.config
	S, C, H, E := c.Scopes, allowedScopes(c), c.RequiredScopes, in.explicit
	ch := in.challenge
	grant := in.grant
	// 0. A 401 retires the sent generation first, whatever the outcome.
	retire := ch.status == 401 && in.sent != "" && grant != nil && grant.Generation == in.sent
	if retire {
		grant = cloneRecord(grant)
		grant.AccessToken = ""
	}
	fail := func(err error) decision {
		return decision{outcome: outcomeFail, err: err, early: true, retire: retire}
	}
	// 1. Configuration.
	for _, set := range [][]string{S, C, H, E, in.preset} {
		for _, scope := range set {
			if !authutil.ValidScope(scope) {
				return fail(refuse(auth.CodeInvalidConfiguration))
			}
		}
	}
	if !scopeSubset(S, C) || (in.hasPreset && !sameScopes(in.preset, S)) {
		return fail(refuse(auth.CodeInvalidConfiguration))
	}
	// 2. Challenge form.
	switch {
	case ch.kind == malformed, ch.kind == forbidden:
		return fail(refuse(auth.CodeAccessDenied))
	case ch.kind == insufficientBare && len(H) == 0 && len(E) == 0:
		return fail(refuse(auth.CodeAccessDenied))
	}
	R := merge(H, E...)
	if ch.kind == insufficient {
		R = merge(R, ch.scopes...)
	}
	d := decision{required: R, ceiling: merge(C), retire: retire}
	// 3. A 401 hint is for a client-credentials acquisition in this operation.
	if ch.kind == unauthorized && c.Flow == "client_credentials" {
		d.hint = intersect(ch.scopes, C)
	}
	// 4. Ceiling.
	if !scopeSubset(R, C) {
		d.outcome, d.err, d.early = outcomeFail, refuse(auth.CodeAccessDenied, R...), true
		return d
	}
	covers := grant != nil && scopeSubset(R, intersect(grant.Scopes, C))
	// 5. The server disagrees with our record.
	if covers && (ch.kind == insufficient || ch.kind == insufficientBare) {
		if in.sent == "" || grant.Generation == in.sent {
			d.outcome, d.err, d.disagrees = outcomeFail, refuse(auth.CodeAccessDenied, R...), true
			return d
		}
		if usable(grant) {
			d.outcome = outcomeUse
			return d
		}
	}
	// 6. Use.
	if covers && usable(grant) {
		d.outcome = outcomeUse
		return d
	}
	// 7. Refresh (PKCE), only when it can cover R: a refresh never broadens.
	if grant != nil && !usable(grant) && refreshable(grant, c) && scopeSubset(R, grant.Scopes) {
		d.outcome = outcomeRefresh
		return d
	}
	// 8. Client credentials.
	if c.Flow == "client_credentials" {
		d.outcome = outcomeAcquire
		return d
	}
	// 9. PKCE.
	if in.op == opPrepare {
		d.outcome = outcomeLogin
		return d
	}
	d.outcome, d.err = outcomeFail, refuse(auth.CodeInteractionRequired, R...)
	return d
}

// refreshable reports PKCE refresh material usable with the configured
// client. A client-credentials grant is always reissued, never refreshed.
func refreshable(grant *Record, c ClientConfig) bool {
	return c.Flow == pkceFlow && grant.RefreshToken != "" && (c.source != sourceDCR || grant.ClientID != "")
}

// acquisition is the scope set a client-credentials grant requests:
// previous ∪ ((S ∪ R ∪ P′) ∩ C).
func (d decision) acquisition(c ClientConfig, previous *Record) []string {
	var granted []string
	if previous != nil {
		granted = previous.Scopes
	}
	return merge(granted, intersect(merge(merge(c.Scopes, d.required...), d.hint...), d.ceiling)...)
}

// login is the scope set a login requests: previous ∪ ((S ∪ R) ∩ C).
func (d decision) login(c ClientConfig, previous *Record) []string {
	var granted []string
	if previous != nil {
		granted = previous.Scopes
	}
	return merge(granted, intersect(merge(c.Scopes, d.required...), d.ceiling)...)
}

// settle checks a refreshed or client-credentials grant against R: one
// narrower than R is refused with R (the grant is already persisted).
func (d decision) settle(next *Record) error {
	if next == nil || !scopeSubset(d.required, intersect(next.Scopes, d.ceiling)) {
		return refuse(auth.CodeAccessDenied, d.required...)
	}
	return nil
}

// completed checks a completed login's grant, within the current ceiling,
// against the R stored on the login.
func completed(next *Record, required, ceiling []string) error {
	if !scopeSubset(required, intersect(next.Scopes, ceiling)) {
		return refuse(auth.CodeAccessDenied, required...)
	}
	return nil
}

// scoped is an SDK scope outcome: the only error that carries scopes.
type scoped struct {
	code   auth.Code
	scopes []string
}

func (e *scoped) Error() string { return "auth: " + string(e.code) }

// Is keeps the auth sentinels working before classification.
func (e *scoped) Is(target error) bool { return (&auth.Error{Code: e.code}).Is(target) }

// refuse builds a scope outcome; only decide and completed call it.
func refuse(code auth.Code, scopes ...string) error {
	return &scoped{code: code, scopes: merge(nil, scopes...)}
}

// classify is the only place that sets a host-facing error's code, scopes
// and login state. Scopes survive only from a scope outcome; every other
// error (host callbacks, stores, network, token endpoint) keeps only an
// allowlisted code, else fallback. ended is set only for Complete. A
// cancelled caller sees fallback joined with its context error.
func classify(ctx context.Context, err error, fallback auth.Code, ended *bool) error {
	result := &auth.Error{Code: fallback}
	var outcome *scoped
	if ctx.Err() == nil {
		if errors.As(err, &outcome) {
			result = &auth.Error{Code: outcome.code, Scopes: append([]string(nil), outcome.scopes...)}
		} else if classified := auth.Classify(err); classified != nil {
			result = &auth.Error{Code: classified.Code}
		}
	}
	if ended != nil {
		value := *ended
		result.LoginEnded = &value
	}
	if cause := ctx.Err(); cause != nil {
		return errors.Join(result, cause)
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, cause) {
			return errors.Join(result, cause)
		}
	}
	return result
}
