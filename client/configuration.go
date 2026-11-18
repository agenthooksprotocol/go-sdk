package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

// ErrConfigurationSkipped reports that a backend without explicit subscriptions
// was skipped. It contains no endpoint, credentials, or backend response data.
// Every *ConfigurationSkipError matches it with errors.Is.
var ErrConfigurationSkipped = errors.New("backend configuration unavailable or inapplicable")

// ErrConfigurationLocalSecretReference wraps ErrConfigurationSkipped for discovered
// upload auth naming a local secret reference. It contains no reference name.
// A *ConfigurationSkipError with ConfigurationLocalSecret matches it.
var ErrConfigurationLocalSecretReference = fmt.Errorf("%w: discovered upload names a local secret reference", ErrConfigurationSkipped)

// ConfigurationSkipCode classifies why server-driven configuration skipped a
// backend. Its string values are the protocol's diagnostic codes.
type ConfigurationSkipCode string

const (
	// ConfigurationUnavailable: transport failure, timeout, non-success HTTP
	// status, a JSON-RPC error other than method-not-found, or an endpoint
	// authentication failure. It is re-attempted at a later event admission.
	ConfigurationUnavailable ConfigurationSkipCode = "configuration_unavailable"
	// ConfigurationInvalid: method-not-found, or an uncorrelated, malformed or
	// version-incompatible response (or a transport this client cannot open).
	ConfigurationInvalid ConfigurationSkipCode = "configuration_invalid"
	// ConfigurationNoApplicableSubscriptions: a valid advertisement with no
	// supported subscriptions.
	ConfigurationNoApplicableSubscriptions ConfigurationSkipCode = "no_applicable_subscriptions"
	// ConfigurationLocalSecret: a discovered subscription names a local secret
	// reference.
	ConfigurationLocalSecret ConfigurationSkipCode = "configuration_local_secret"
)

// ConfigurationSkipError is the host-visible diagnostic reported to
// Options.TransportDiagnostic when discovery skips a backend, at New or at a
// failed re-attempt. AuthError and Recovery are set only when an endpoint
// authentication error caused the skip; they are the safe auth code and its
// paired recovery. It never carries credentials, tokens, response bodies or
// event content. Cancellation is returned, never reported as a skip.
type ConfigurationSkipError struct {
	BackendID string
	Code      ConfigurationSkipCode
	AuthError auth.Code
	Recovery  auth.Recovery
}

func (e *ConfigurationSkipError) Error() string {
	message := "backend " + e.BackendID + " configuration skipped: " + string(e.Code)
	if e.AuthError != "" {
		message += " (auth " + string(e.AuthError) + ", recovery " + string(e.Recovery) + ")"
	}
	return message
}

// Is matches ErrConfigurationSkipped, and ErrConfigurationLocalSecretReference
// for ConfigurationLocalSecret.
func (e *ConfigurationSkipError) Is(target error) bool {
	return target == ErrConfigurationSkipped || (target == ErrConfigurationLocalSecretReference && e.Code == ConfigurationLocalSecret)
}

// Unwrap returns the redacted *auth.Error that caused the skip, if any.
func (e *ConfigurationSkipError) Unwrap() error {
	if e.AuthError == "" {
		return nil
	}
	return &auth.Error{Code: e.AuthError}
}

// MarshalJSON encodes {backendId, code, authError?, recovery?}.
func (e ConfigurationSkipError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		BackendID string                `json:"backendId"`
		Code      ConfigurationSkipCode `json:"code"`
		AuthError auth.Code             `json:"authError,omitempty"`
		Recovery  auth.Recovery         `json:"recovery,omitempty"`
	}{e.BackendID, e.Code, e.AuthError, e.Recovery})
}

// skipped returns a diagnostic without a backend identifier; the caller sets it.
func skipped(code ConfigurationSkipCode) error { return &ConfigurationSkipError{Code: code} }

// unavailable classifies an exchange failure, keeping only a redacted auth code.
func unavailable(err error) error {
	skip := &ConfigurationSkipError{Code: ConfigurationUnavailable}
	if classified := auth.Classify(err); classified != nil {
		skip.AuthError, skip.Recovery = classified.Code, classified.Recovery()
	}
	return skip
}

func (c *Hooks) configurationSkipped(id string, reason *ConfigurationSkipError) {
	reason.BackendID = id
	if c.opts.TransportDiagnostic != nil {
		c.opts.TransportDiagnostic(id, reason)
	}
}

// skippedBackend is a backend skipped with ConfigurationUnavailable. It holds
// no open transport; a re-attempt opens a fresh one.
type skippedBackend struct {
	order    int
	id       string
	backend  *ahp.Backend
	endpoint *auth.Request
	// prepared is the host prepare count observed before the last attempt.
	prepared uint64
	// retryAt is when backoff makes the backend eligible; zero means never.
	retryAt time.Time
	delay   time.Duration
}

// openTransport opens one backend's event transport with the host options.
func (c *Hooks) openTransport(id string, backend *ahp.Backend) (backendTransport, error) {
	tr, err := newAuthenticatedBackendTransport(backend, c.opts.EventClient, c.opts.AuthProvider)
	if err != nil {
		return nil, err
	}
	if httpTransport, ok := tr.(*httpBackend); ok {
		httpTransport.headerResolver = c.opts.HeaderResolver
		httpTransport.backendID = id
	}
	if stdio, ok := tr.(*stdioBackend); ok {
		stdio.inheritEnvironment = c.opts.InheritEnvironment
		if c.opts.TransportDiagnostic != nil {
			backendID, report := id, c.opts.TransportDiagnostic
			stdio.diagnostic = func(err error) { report(backendID, err) }
		}
	}
	return tr, nil
}

// endpointRequest is the event endpoint a host prepares, or nil for stdio.
func endpointRequest(tr backendTransport) *auth.Request {
	if h, ok := tr.(*httpBackend); ok && h.authRequest != nil {
		request := *h.authRequest
		request.Binding = append(json.RawMessage(nil), request.Binding...)
		return &request
	}
	return nil
}

// preparations reads the host provider's successful prepare count for s.
func (c *Hooks) preparations(s *skippedBackend) uint64 {
	tracker, ok := c.opts.AuthProvider.(auth.PreparationTracker)
	if !ok || s.endpoint == nil {
		return 0
	}
	request := *s.endpoint
	request.Binding = append(json.RawMessage(nil), request.Binding...)
	return tracker.Preparations(request)
}

// skip reports a failed discovery and schedules s, reporting whether it stays
// eligible for re-attempt. Only ConfigurationUnavailable is re-attempted; backoff
// applies only without an auth error or when its recovery is retry.
func (c *Hooks) skip(s *skippedBackend, err error) bool {
	var reason *ConfigurationSkipError
	if !errors.As(err, &reason) {
		reason = &ConfigurationSkipError{Code: ConfigurationInvalid}
	}
	c.configurationSkipped(s.id, reason)
	if reason.Code != ConfigurationUnavailable {
		return false
	}
	s.retryAt = time.Time{}
	if reason.AuthError == "" || reason.Recovery == auth.RecoveryRetry {
		s.retryAt = c.now().Add(s.delay)
	}
	s.delay = min(2*s.delay, c.opts.ConfigurationRetryMaxDelay)
	return true
}

// routes returns the current admitted routes.
func (c *Hooks) routes() []registeredBackend {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backends
}

// admit is the single shared admission for an event. It re-attempts every
// skipped backend that a host prepare or an elapsed backoff made eligible, then
// installs all newly discovered routes at once. A caller arriving while another
// re-attempt runs uses the previous routes rather than waiting. The returned
// snapshot is the event's complete, immutable route set, so an event admitted
// before a retry succeeds is never delivered to the retried backend.
func (c *Hooks) admit(ctx context.Context) []registeredBackend {
	if !c.retry.TryLock() {
		return c.routes()
	}
	defer c.retry.Unlock()
	var admitted []registeredBackend
	remaining := c.skipped[:0]
	for _, s := range c.skipped {
		if b, keep := c.reattempt(ctx, s); b != nil {
			admitted = append(admitted, *b)
		} else if keep {
			remaining = append(remaining, s)
		}
	}
	clear(c.skipped[len(remaining):])
	c.skipped = remaining
	if len(admitted) == 0 {
		return c.routes()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		for _, b := range admitted {
			_ = b.transport.Close()
		}
		return c.backends
	}
	next := make([]registeredBackend, 0, len(c.backends)+len(admitted))
	next = append(next, c.backends...)
	for _, b := range admitted {
		at := len(next)
		for i, existing := range next {
			if existing.order > b.order {
				at = i
				break
			}
		}
		next = append(next[:at], append([]registeredBackend{b}, next[at:]...)...)
	}
	c.backends = next
	return next
}

// reattempt runs discovery for s if it is eligible. It returns the admitted
// backend on success, else whether s stays skipped. Cancellation of the event
// leaves s unchanged and emits no diagnostic; its deadline counts as a timeout.
func (c *Hooks) reattempt(ctx context.Context, s *skippedBackend) (*registeredBackend, bool) {
	prepared := c.preparations(s)
	delay := s.delay
	if prepared != s.prepared {
		// A successful prepare makes the backend eligible at once and resets backoff.
		delay = c.opts.ConfigurationRetryDelay
	} else if s.retryAt.IsZero() || c.now().Before(s.retryAt) {
		return nil, true
	}
	if ctx.Err() != nil {
		return nil, true
	}
	tr, err := c.openTransport(s.id, s.backend)
	if err != nil {
		c.configurationSkipped(s.id, &ConfigurationSkipError{Code: ConfigurationInvalid})
		return nil, false
	}
	subscriptions, err := c.discoverConfiguration(ctx, tr)
	if errors.Is(ctx.Err(), context.Canceled) {
		_ = tr.Close()
		return nil, true
	}
	if err != nil {
		_ = tr.Close()
		if ctx.Err() != nil {
			// The event's deadline bounded this attempt like a discovery
			// timeout; it backs off rather than repeating at every admission.
			err = skipped(ConfigurationUnavailable)
		}
		s.prepared, s.delay = prepared, delay
		return nil, c.skip(s, err)
	}
	return &registeredBackend{id: s.id, order: s.order, transport: tr, subscriptions: subscriptions}, false
}

// discoverConfiguration retrieves and resolves one backend's configuration
// within ConfigurationTimeout. It returns parent's error on cancellation, else
// a *ConfigurationSkipError for a skip.
func (c *Hooks) discoverConfiguration(parent context.Context, transport backendTransport) ([]map[string]any, error) {
	ctx, cancel := context.WithTimeout(parent, c.opts.ConfigurationTimeout)
	defer cancel()
	// Each transport is bound to exactly one backend. The request has no event,
	// content, or session and uses the ordinary endpoint credential boundary.
	id := "ahp-configuration"
	request := sdkJSON(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "hooks/configuration",
		"params": map[string]any{"protocolVersion": ahp.ProtocolVersionValue},
	})
	response, err := transport.Exchange(ctx, request, false)
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	if errors.Is(err, errMalformedResponse) {
		return nil, skipped(ConfigurationInvalid)
	}
	if err != nil || ctx.Err() != nil {
		return nil, unavailable(err)
	}
	var envelope map[string]any
	decoder := json.NewDecoder(bytes.NewReader(response))
	decoder.UseNumber()
	if decoder.Decode(&envelope) != nil || envelope["id"] != id || envelope["jsonrpc"] != "2.0" {
		return nil, skipped(ConfigurationInvalid)
	}
	if rpcError, exists := envelope["error"]; exists {
		code, ok := sdkObj(rpcError)["code"].(json.Number)
		if _, integer := code.Int64(); !ok || integer != nil || code == "-32601" {
			return nil, skipped(ConfigurationInvalid)
		}
		return nil, skipped(ConfigurationUnavailable)
	}
	if canonical.Validate("configuration-response", response) != nil {
		return nil, skipped(ConfigurationInvalid)
	}
	result := sdkObj(envelope["result"])
	if result["protocolVersion"] != ahp.ProtocolVersionValue {
		return nil, skipped(ConfigurationInvalid)
	}
	configuration := sdkObj(result["configuration"])
	// Checked before selectors are resolved: a reference on any subscription skips
	// the whole backend, including one this client would otherwise drop as unmatched.
	for _, raw := range sdkArray(configuration["subscriptions"]) {
		if uploadNamesLocalSecret(sdkObj(raw)) {
			return nil, skipped(ConfigurationLocalSecret)
		}
	}
	var resolved []map[string]any
	for _, raw := range sdkArray(configuration["subscriptions"]) {
		sub := sdkObj(raw)
		var events []any
		for _, rawEvent := range sdkArray(c.manifest["events"]) {
			entry := sdkObj(rawEvent)
			name, _ := entry["event"].(string)
			if !sdkHas(entry["modes"], sub["mode"]) {
				continue
			}
			for _, selector := range sdkArray(sub["events"]) {
				if sdkMatch(selector, name) {
					events = append(events, name)
					break
				}
			}
		}
		if len(events) == 0 {
			continue
		}
		sub["events"] = events
		// Settings are not rewritten to fit local limits or policy scope. An
		// unsupported non-selector setting skips the backend as a whole.
		if validateSubscription(c.manifest, sub) != nil {
			return nil, skipped(ConfigurationInvalid)
		}
		resolved = append(resolved, sub)
	}
	if len(resolved) == 0 {
		return nil, skipped(ConfigurationNoApplicableSubscriptions)
	}
	return resolved, nil
}

// uploadNamesLocalSecret reports whether a subscription's upload auth would make
// the client read a value the backend has never held. The value is not inspected.
func uploadNamesLocalSecret(sub map[string]any) bool {
	binding := sdkObj(sdkObj(sub["upload"])["auth"])
	for _, key := range []string{"tokenEnv", "tokenRef", "clientSecretRef"} {
		if _, present := binding[key]; present {
			return true
		}
	}
	return false
}
