package auth

import (
	"bytes"
	"context"
)

// ProviderFuncs adapts host callbacks to Provider. A missing CredentialFunc is
// unsupported. Missing ChallengeFunc and PreemptiveCredentialFunc callbacks
// decline recovery and cached credentials, respectively. A missing
// PreparationsFunc reports no host prepares (see PreparationTracker).
type ProviderFuncs struct {
	CredentialFunc           func(context.Context, Request) (Credential, error)
	PreemptiveCredentialFunc func(context.Context, Request) (*Credential, error)
	ChallengeFunc            func(context.Context, Request, Challenge) (*Credential, error)
	PreparationsFunc         func(Request) uint64
}

func (p ProviderFuncs) Preparations(r Request) uint64 {
	if p.PreparationsFunc == nil {
		return 0
	}
	return p.PreparationsFunc(copyRequest(r))
}

func (p ProviderFuncs) Credential(ctx context.Context, r Request) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, redactError(ErrCredential, err)
	}
	if p.CredentialFunc == nil {
		return Credential{}, &Error{Code: CodeUnsupportedBinding}
	}
	return p.CredentialFunc(ctx, copyRequest(r))
}
func (p ProviderFuncs) PreemptiveCredential(ctx context.Context, r Request) (*Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, redactError(ErrCredential, err)
	}
	if p.PreemptiveCredentialFunc == nil {
		return nil, nil
	}
	return p.PreemptiveCredentialFunc(ctx, copyRequest(r))
}

func (p ProviderFuncs) Challenge(ctx context.Context, r Request, c Challenge) (*Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, redactError(ErrCredential, err)
	}
	if p.ChallengeFunc == nil {
		return nil, nil
	}
	c.Header = c.Header.Clone()
	return p.ChallengeFunc(ctx, copyRequest(r), c)
}

// BearerOptions supplies reference resolution without changing the environment-
// only default. No resolver or OAuth provider is installed globally.
type BearerOptions struct{ ResolveSecret SecretResolver }
type bearerProvider struct{ options BearerOptions }

func NewBearerProvider(options BearerOptions) Provider { return bearerProvider{options} }
func (p bearerProvider) Credential(ctx context.Context, r Request) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, redactError(ErrCredential, err)
	}
	target, err := NormalizeTarget(r)
	if err != nil {
		return Credential{}, err
	}
	binding, ok := target.Bearer()
	if !ok {
		return Credential{}, &Error{Code: CodeUnsupportedBinding}
	}
	token, err := ResolveSecret(ctx, binding.TokenEnv, binding.TokenRef, p.options.ResolveSecret)
	if err != nil {
		return Credential{}, redactError(&Error{Code: CodeCredentialUnavailable}, err)
	}
	if !validBearer(token) {
		return Credential{}, &Error{Code: CodeCredentialUnavailable}
	}
	return Credential{Type: "bearer", Token: token}, nil
}
func (bearerProvider) Challenge(context.Context, Request, Challenge) (*Credential, error) {
	return nil, nil
}

// Routes composes providers by binding, never by success/failure fallback.
// Bearer defaults to EnvironmentProvider. OAuth also receives cached lookup
// and actual challenges for unbound targets; it must enforce host trust policy.
type Routes struct{ Bearer, OAuth Provider }
type router struct{ routes Routes }
type routedAttempt struct {
	request  Request
	owner    *router
	provider Provider
	attempt  any
}

// Route is opt-in. Existing custom providers passed to client.Options are not
// wrapped or reinterpreted. Attempts retain the issuing provider across retries.
func Route(routes Routes) Provider {
	if routes.Bearer == nil {
		routes.Bearer = EnvironmentProvider{}
	}
	return &router{routes: routes}
}
func (p *router) selectProvider(r Request) (Provider, error) {
	target, err := NormalizeTarget(r)
	if err != nil {
		return nil, err
	}
	if target.Kind() == BindingBearer {
		return p.routes.Bearer, nil
	}
	if p.routes.OAuth == nil {
		return nil, &Error{Code: CodeUnsupportedBinding}
	}
	return p.routes.OAuth, nil
}

// Preparations forwards PreparationTracker to the provider Credential would
// select for r; a provider that does not track prepares reports zero.
func (p *router) Preparations(r Request) uint64 {
	provider, err := p.selectProvider(r)
	if err != nil {
		return 0
	}
	if tracker, ok := provider.(PreparationTracker); ok {
		return tracker.Preparations(copyRequest(r))
	}
	return 0
}

func (p *router) wrap(provider Provider, r Request, c Credential) Credential {
	c.Attempt = &routedAttempt{owner: p, provider: provider, attempt: c.Attempt, request: copyRequest(r)}
	return c
}
func (p *router) Credential(ctx context.Context, r Request) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, redactError(ErrCredential, err)
	}
	provider, err := p.selectProvider(r)
	if err != nil {
		return Credential{}, err
	}
	c, err := provider.Credential(ctx, copyRequest(r))
	if err != nil {
		return Credential{}, redactProviderError(err)
	}
	if err := ctx.Err(); err != nil {
		return Credential{}, redactError(ErrCredential, err)
	}
	if c.Type != "bearer" || !validBearer(c.Token) {
		return Credential{}, &Error{Code: CodeCredentialUnavailable}
	}
	return p.wrap(provider, r, c), nil
}
func (p *router) PreemptiveCredential(ctx context.Context, r Request) (*Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, redactError(ErrCredential, err)
	}
	if len(r.Binding) != 0 {
		return nil, &Error{Code: CodeInvalidConfiguration}
	}
	if _, err := NormalizeTarget(r); err != nil {
		return nil, err
	}
	provider := p.routes.OAuth
	lookup, ok := provider.(PreemptiveProvider)
	if !ok {
		return nil, nil
	}
	cached, err := lookup.PreemptiveCredential(ctx, copyRequest(r))
	if err != nil {
		return nil, redactProviderError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, redactError(ErrCredential, err)
	}
	if cached == nil {
		return nil, nil
	}
	if cached.Type != "bearer" || !validBearer(cached.Token) {
		return nil, &Error{Code: CodeCredentialUnavailable}
	}
	wrapped := p.wrap(provider, r, *cached)
	return &wrapped, nil
}

func (p *router) Challenge(ctx context.Context, r Request, c Challenge) (*Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, redactError(ErrCredential, err)
	}
	var provider Provider
	if attempt, ok := c.Attempt.(*routedAttempt); ok && attempt.owner == p {
		if attempt.request.BackendID != r.BackendID || attempt.request.Destination != r.Destination || attempt.request.Purpose != r.Purpose || !bytes.Equal(attempt.request.Binding, r.Binding) {
			return nil, &Error{Code: CodeInvalidConfiguration}
		}
		provider, c.Attempt = attempt.provider, attempt.attempt
	} else {
		// Only an initially anonymous request has no issuing attempt. Never route
		// an unknown attempt to a different provider or credential identity.
		if c.Attempt != nil || len(r.Binding) != 0 {
			return nil, &Error{Code: CodeInvalidConfiguration}
		}
		var err error
		provider, err = p.selectProvider(r)
		if err != nil {
			return nil, err
		}
	}
	c.Header = c.Header.Clone()
	replacement, err := provider.Challenge(ctx, copyRequest(r), c)
	if err != nil {
		return nil, redactProviderError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, redactError(ErrCredential, err)
	}
	if replacement == nil {
		return nil, nil
	}
	if replacement.Type != "bearer" || !validBearer(replacement.Token) {
		return nil, &Error{Code: CodeCredentialUnavailable}
	}
	wrapped := p.wrap(provider, r, *replacement)
	return &wrapped, nil
}
