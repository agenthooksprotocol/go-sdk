// Package client delivers AHP boundaries and composes accepted protocol effects.
// It never executes an application operation or validates an application's schema.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
	"github.com/agenthooksprotocol/go-sdk/capability"
	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/diagnostic"
	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
)

// Options describes host-owned identity, supported protocol operations and I/O.
// The two HTTP clients are deliberately independent credential scopes.
type Options struct {
	Source string
	// Events explicitly advertises boundary modes and capabilities.
	// Metadata customizes only non-event advertisement fields.
	Events   capability.Host
	Metadata *ManifestMetadata
	// AuthProvider is harness-owned; Hooks never closes it.
	AuthProvider    auth.Provider
	EventClient     *http.Client
	UploadClient    *http.Client
	MaxContentBytes int64
	// MaxConcurrentUploads limits active transfers across invocations; zero uses 8.
	MaxConcurrentUploads   int
	MaxPendingObservations int
	ObservationTimeout     time.Duration
	Content                ContentOptions
	// InheritEnvironment starts stdio backends with the full host environment
	// instead of the minimal base (PATH, HOME, locale, temp directories and
	// similar). Registration env entries still apply on top. This SDK option is
	// not part of the protocol; it exists for hosts migrating backends that rely
	// on inherited variables. Prefer explicit registration env entries.
	InheritEnvironment bool
}

// Hooks is the registration-driven host for AHP boundary delivery.
// It composes protocol decisions, but never executes native operations.
type Hooks struct {
	opts         Options
	manifest     map[string]any
	backends     []registeredBackend
	mu           sync.Mutex
	closed       bool
	closeDone    chan struct{}
	closeErr     error
	active       sync.WaitGroup
	cancel       context.CancelFunc
	life         context.Context
	observations chan struct{}
	uploads      chan struct{}
}

type registeredBackend struct {
	id            string
	subscriptions []map[string]any
	transport     backendTransport
}

// DeliveryError is local audit information, not an explicit backend denial.
type DeliveryError struct {
	BackendID    string
	Subscription int
	Stage        string
	Code         diagnostic.Code
	Err          error
	FailClosed   bool
}

func (e DeliveryError) Error() string {
	return fmt.Sprintf("backend %s subscription %d %s: %v", e.BackendID, e.Subscription, e.Stage, e.Err)
}
func (e DeliveryError) Unwrap() error { return e.Err }

type Result struct {
	contentMu        sync.Mutex
	contentClosed    bool
	attachments      map[string]*content.Source
	attachmentItems  map[string]map[string]any
	attachmentBudget *contentSourceBudget
	attachmentLimit  int64
	// Snapshot retains the original MCP semantic contract, not body bytes.
	Snapshot *ElicitationRequest
	// Event is the authoritative SDK-owned settled event, including opaque extras.
	Event     *ahp.Event
	eventWire json.RawMessage
	// AcceptedResponses retains complete receiver envelopes in atomic acceptance
	// order, including envelope/result extras. The list is empty when no receiver
	// response is accepted; there is no separate aggregate/last-response snapshot.
	AcceptedResponses []ahp.ContextualResponse
	// Candidate distinguishes no candidate from an opaque candidate whose
	// value is JSON null. Schema-owned values are decoded using event context.
	Candidate ahp.Nullable[Candidate]
	state     ahp.InterceptRequestParamsState
	// Flow is the settled canonical control flow.
	Flow ahp.Optional[ahp.InterceptRequestParamsStateFlow]
	// StateExtras preserves unknown state properties without granting authority.
	StateExtras map[string]json.RawMessage
	// Instructions and Injections retain the complete accumulated settlement,
	// including native initial state and omission versus an explicitly empty list.
	Instructions ahp.Optional[[]string]
	Injections   ahp.Optional[[]*ahp.InjectEffect]
	// Permission is the settled canonical permission, not proof of execution.
	// None and Ask are not grants; Interrupted always gates execution.
	Permission ahp.InterceptRequestParamsStatePermission
	// Diagnostics includes interception and completed observation delivery failures.
	Diagnostics []DeliveryError
	response    ahp.InterceptResponseResult
	errors      []DeliveryError
	Interrupted bool
}

// New validates and snapshots configuration before opening any transport.
func New(reg ahp.Registration, opts Options) (*Hooks, error) {
	c, err := newClient(reg, opts)
	if err != nil {
		return nil, &AdmissionError{Kind: "config", Err: err}
	}
	return c, nil
}

func newClient(reg ahp.Registration, opts Options) (*Hooks, error) {
	if strings.TrimSpace(opts.Source) == "" {
		return nil, errors.New("source is required")
	}
	if opts.MaxConcurrentUploads < 0 || opts.MaxContentBytes < 0 || opts.MaxPendingObservations < 0 || opts.ObservationTimeout < 0 {
		return nil, errors.New("negative client limit")
	}
	if opts.MaxConcurrentUploads == 0 {
		opts.MaxConcurrentUploads = 8
	}
	if opts.MaxContentBytes == 0 {
		opts.MaxContentBytes = 4 << 20
	}
	if opts.MaxPendingObservations == 0 {
		opts.MaxPendingObservations = 64
	}
	if opts.ObservationTimeout == 0 {
		opts.ObservationTimeout = 5 * time.Second
	}
	rb, err := json.Marshal(reg)
	if err != nil {
		return nil, err
	}
	if err := canonical.Validate("registration", rb); err != nil {
		return nil, err
	}
	parsed := ahp.ParseRegistration(rb)
	if !parsed.OK {
		return nil, errors.New("invalid registration")
	}
	manifest, err := manifestForOptions(parsed.Value, opts)
	if err != nil {
		return nil, err
	}
	if err := validateManifestMetadata(manifest); err != nil {
		return nil, err
	}
	// Retain only the detached normalized advertisement, not the caller's map.
	opts.Events = capability.Host{}
	opts.Metadata = nil
	c := &Hooks{opts: opts, manifest: manifest, observations: make(chan struct{}, opts.MaxPendingObservations), closeDone: make(chan struct{}), uploads: make(chan struct{}, opts.MaxConcurrentUploads)}
	c.life, c.cancel = context.WithCancel(context.Background())
	ids := map[string]bool{}
	for _, backend := range parsed.Value.Hooks {
		bm, _ := sdkMap(backend)
		id, _ := bm["id"].(string)
		if ids[id] {
			c.Close()
			return nil, errors.New("duplicate backend ID")
		}
		ids[id] = true
		tm := sdkObj(bm["transport"])
		if !sdkHas(manifest["transports"], tm["type"]) {
			c.Close()
			return nil, errors.New("transport is not advertised")
		}
		if auth := sdkObj(bm["authentication"]); auth != nil && !sdkHas(manifest["authentication"], auth["type"]) {
			c.Close()
			return nil, errors.New("authentication is not advertised")
		}
		b := registeredBackend{id: id}
		for _, v := range sdkArray(bm["subscriptions"]) {
			sub := sdkObj(v)
			if err := validateSubscription(manifest, sub); err != nil {
				c.Close()
				return nil, err
			}
			b.subscriptions = append(b.subscriptions, sub)
		}
		tr, err := newAuthenticatedBackendTransport(backend, opts.EventClient, opts.AuthProvider)
		if err != nil {
			c.Close()
			return nil, err
		}
		if stdio, ok := tr.(*stdioBackend); ok {
			stdio.inheritEnvironment = opts.InheritEnvironment
		}
		b.transport = tr
		c.backends = append(c.backends, b)
	}
	return c, nil
}

// Close cancels outstanding calls and observations and releases owned processes.
// Injected HTTP clients remain caller-owned. Close is safe to call repeatedly.
func (c *Hooks) Close() error {
	c.mu.Lock()
	if c.closed {
		done := c.closeDone
		c.mu.Unlock()
		<-done
		return c.closeErr
	}
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	var errs []error
	for _, b := range c.backends {
		if err := b.transport.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	c.active.Wait()
	c.closeErr = errors.Join(errs...)
	close(c.closeDone)
	return c.closeErr
}

func validateSubscription(manifest, sub map[string]any) error {
	policy := sdkObj(manifest["managedPolicy"])
	scope := sub["scope"]
	if scope == nil {
		scope = "user"
	}
	if !sdkHas(policy["scopes"], scope) || ((scope == "managed" || sub["disableable"] == false) && policy["disableable"] != false) {
		return errors.New("unsupported policy scope")
	}
	limits := sdkObj(manifest["limits"])
	if n, ok := sdkNumber(sub["timeoutMs"]); ok {
		if min, ok := sdkNumber(limits["minTimeoutMs"]); ok && n < min {
			return errors.New("timeout below manifest limit")
		}
		if max, ok := sdkNumber(limits["maxTimeoutMs"]); ok && n > max {
			return errors.New("timeout above manifest limit")
		}
		if n > float64((1<<63-1)/int64(time.Millisecond)) {
			return errors.New("timeout overflows duration")
		}
	}
	for _, selector := range sdkArray(sub["events"]) {
		found := false
		for _, raw := range sdkArray(manifest["events"]) {
			entry := sdkObj(raw)
			name, _ := entry["event"].(string)
			if sdkMatch(selector, name) && sdkHas(entry["modes"], sub["mode"]) {
				found = true
			}
		}
		if !found {
			return errors.New("subscription selects no advertised event/mode")
		}
	}
	return nil
}

func sdkMatch(selector any, name string) bool {
	s, _ := selector.(string)
	return s == name || s == "*" || (strings.HasSuffix(s, ".*") && strings.HasPrefix(name, strings.TrimSuffix(s, "*")))
}
func sdkObj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func sdkArray(v any) []any        { a, _ := v.([]any); return a }
func sdkHas(v, needle any) bool {
	for _, x := range sdkArray(v) {
		if reflect.DeepEqual(x, needle) {
			return true
		}
	}
	return false
}
func sdkJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func sdkMap(v any) (map[string]any, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	var m map[string]any
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	e = decoder.Decode(&m)
	return m, e
}
func sdkID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func sdkNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, e := n.Float64()
		return f, e == nil
	case float64:
		return n, true
	default:
		return 0, false
	}
}
func sdkNumberNarrow(base, next json.Number) bool {
	b, bok := new(big.Rat).SetString(string(base))
	n, nok := new(big.Rat).SetString(string(next))
	return bok && nok && n.Cmp(b) <= 0
}
