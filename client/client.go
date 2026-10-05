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
	// Use Events for ordinary configuration or Manifest for advanced metadata, not both.
	Events                 map[string]EventCapabilities
	Manifest               ahp.StaticCapabilityManifest
	EventClient            *http.Client
	EventTransportResolver EventTransportResolver
	UploadClient           *http.Client
	MaxContentBytes        int64
	MaxPendingObservations int
	ObservationTimeout     time.Duration
	Content                ContentOptions
}

// Hooks is the registration-driven host for AHP boundary delivery.
// It composes protocol decisions, but never executes native operations.
type Hooks struct {
	opts         Options
	manifest     map[string]any
	backends     []registeredBackend
	mu           sync.Mutex
	closed       bool
	active       sync.WaitGroup
	cancel       context.CancelFunc
	life         context.Context
	observations chan struct{}
}

// Client is retained for source compatibility.
// Deprecated: use Hooks.
type Client = Hooks

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
	Err          error
	FailClosed   bool
}

func (e DeliveryError) Error() string {
	return fmt.Sprintf("backend %s subscription %d %s: %v", e.BackendID, e.Subscription, e.Stage, e.Err)
}
func (e DeliveryError) Unwrap() error { return e.Err }

type Result struct {
	content map[string][]byte
	// Snapshot retains the original MCP request, never an effective result.
	Snapshot        *ElicitationRequest
	EffectiveValues map[string]json.RawMessage
	prepared        *preparedBoundary
	Event           json.RawMessage
	EffectiveInput  json.RawMessage
	State           ahp.InterceptRequestParamsState
	Response        ahp.InterceptResponseResult
	Errors          []DeliveryError
	Observations    *Observations
	Interrupted     bool
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
	if opts.MaxContentBytes < 0 || opts.MaxPendingObservations < 0 || opts.ObservationTimeout < 0 {
		return nil, errors.New("negative client limit")
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
	mb, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "manifest", "result": map[string]any{"protocolVersion": "draft", "manifest": manifest}})
	if canonical.Validate("capabilities-response", mb) != nil || !ahp.ParseCapabilitiesResponse(mb).OK {
		return nil, errors.New("invalid manifest")
	}
	if err = json.Unmarshal(sdkJSON(manifest), &opts.Manifest); err != nil {
		return nil, err
	}
	// Retain only the detached normalized advertisement, not the caller's map.
	opts.Events = nil
	c := &Hooks{opts: opts, manifest: manifest, observations: make(chan struct{}, opts.MaxPendingObservations)}
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
		tr, err := newBackendTransport(backend, opts.EventClient, opts.EventTransportResolver)
		if err != nil {
			c.Close()
			return nil, err
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
		c.mu.Unlock()
		return nil
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
	return errors.Join(errs...)
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
