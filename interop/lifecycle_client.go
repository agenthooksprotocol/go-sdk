package interop

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

type lifecycleResult struct {
	response Object
	err      error
}
type lifecycleAttempt struct {
	request Object
	done    chan lifecycleResult
}
type lifecycleBoundary struct {
	staged              Object
	protocolError       error
	accepted, cancelled bool
}
type lifecyclePipe struct {
	ordinary  chan struct{} // one ordinary outstanding stdio intercept per connection
	mu        sync.Mutex
	writer    io.Writer
	pending   map[string][]chan lifecycleResult
	discarded map[string]int
	changed   chan struct{}
	err       error
}

func (p *lifecyclePipe) send(m Object, ch chan lifecycleResult) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	if ch != nil {
		id := lifecycleID(m)
		p.pending[id] = append(p.pending[id], ch)
	}
	return json.NewEncoder(p.writer).Encode(m)
}
func (p *lifecyclePipe) read(r io.Reader) {
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 4096), 16<<20)
	for scan.Scan() {
		var m Object
		if e := json.Unmarshal(scan.Bytes(), &m); e != nil {
			p.fail(e)
			return
		}
		p.mu.Lock()
		id := lifecycleID(m)
		q := p.pending[id]
		if len(q) > 0 {
			q[0] <- lifecycleResult{response: m}
			p.pending[id] = q[1:]
		} else if m["id"] != "unsolicited-observer" {
			p.discarded[id]++
			close(p.changed)
			p.changed = make(chan struct{})
		}
		p.mu.Unlock()
	}
	e := scan.Err()
	if e == nil {
		e = io.EOF
	}
	p.fail(e)
}
func (p *lifecyclePipe) fail(e error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = e
	close(p.changed)
	p.changed = make(chan struct{})
	for id, q := range p.pending {
		for _, ch := range q {
			ch <- lifecycleResult{err: e}
		}
		delete(p.pending, id)
	}
}
func LifecycleClient(ctx context.Context, c LifecycleConfig) error {
	if c.Suite != "" && c.Suite != "lifecycle" && c.Suite != "catalogue" {
		return fmt.Errorf("unknown suite")
	}
	if !c.Auth.validMode() {
		return fmt.Errorf("unsupported auth mode")
	}
	if c.Transport == "stdio" && c.Auth.mode() != "none" {
		return fmt.Errorf("HTTP auth is inapplicable to trusted stdio")
	}
	v, e := newLifecycleValidator(c.SchemaDir)
	if e != nil {
		return e
	}
	fixtures, e := lifecycleFixtures(c.ScenarioFile)
	if e != nil {
		return e
	}
	eventHTTP, eventToken, e := c.Auth.client(ctx)
	if e != nil {
		return e
	}
	defer eventHTTP.CloseIdleConnections()
	var pipe *lifecyclePipe
	if c.Transport == "stdio" {
		if len(c.ServerCommand) == 0 {
			return fmt.Errorf("missing server command")
		}
		cmd := exec.Command(c.ServerCommand[0], append(c.ServerCommand[1:], "--config", c.ServerConfig)...)
		cmd.Dir = c.ServerCwd
		cmd.Stderr = os.Stderr
		setProcessGroup(cmd)
		in, e := cmd.StdinPipe()
		if e != nil {
			return e
		}
		out, e := cmd.StdoutPipe()
		if e != nil {
			return e
		}
		if e = cmd.Start(); e != nil {
			return e
		}
		defer func() { in.Close(); killProcessGroup(cmd); _ = cmd.Wait() }()
		if c.ChildPidFile != "" {
			if e = writeAtomic(c.ChildPidFile, Object{"pid": cmd.Process.Pid}); e != nil {
				return e
			}
		}
		pipe = &lifecyclePipe{writer: in, pending: map[string][]chan lifecycleResult{}, discarded: map[string]int{}, changed: make(chan struct{})}
		go pipe.read(out)
		var sc LifecycleConfig
		if e = Load(c.ServerConfig, &sc); e != nil {
			return e
		}
		ready := time.NewTicker(10 * time.Millisecond)
		defer ready.Stop()
		deadline := time.NewTimer(30 * time.Second)
		defer deadline.Stop()
		for c.ControlEndpoint == "" {
			var r Object
			if Load(sc.ReadinessFile, &r) == nil {
				c.ControlEndpoint = str(r["controlEndpoint"])
				if c.Upload.Endpoint == "" {
					c.Upload.Endpoint = str(r["uploadEndpoint"])
				}
				if c.ControlEndpoint != "" {
					break
				}
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-deadline.C:
				return fmt.Errorf("server readiness timeout")
			case <-ready.C:
			}
		}
	} else if c.Transport != "http" {
		return fmt.Errorf("unknown transport")
	}
	if c.Suite == "catalogue" {
		return catalogueClient(ctx, c, v, fixtures, pipe, eventHTTP, eventToken)
	}
	confirmed := map[string]string{}
	aliases := map[string]string{}
	results := []any{}
	observed := map[string]int{}
	for _, sc := range fixtures {
		if sc.Chain != nil {
			result, observationDiagnostics, err := runObservationChain(sc, func(request Object) (<-chan lifecycleResult, error) {
				done := make(chan lifecycleResult, 1)
				go func() {
					response, err := lifecyclePublicCall(ctx, request, pipe, eventHTTP, eventToken, c.Endpoint)
					done <- lifecycleResult{response: response, err: err}
				}()
				return done, nil
			}, func(path string, value Object) error {
				_, err := lifecycleControl(ctx, c.ControlEndpoint, path, value)
				return err
			}, func(note Object) error {
				_, err := lifecyclePublicCall(ctx, note, pipe, eventHTTP, eventToken, c.Endpoint)
				return err
			}, v.validate)
			if err != nil {
				return err
			}
			row := Object{"id": sc.ID, "actual": result}
			if len(observationDiagnostics) > 0 {
				row["observationDiagnostics"] = observationDiagnostics
			}
			results = append(results, row)
			continue
		}

		actual := Object{"published": []any{}, "cancelled": []any{}, "ignored": []any{}, "states": Object{}, "observations": []any{}, "uploadStatuses": []any{}}
		observationDiagnostics := []any{}
		boundaries := map[string]*lifecycleBoundary{}
		attempts := map[string]*lifecycleAttempt{}
		appendActual := func(k string, x any) { actual[k] = append(array(actual[k]), x) }
		mark := func(kind string, id any) error {
			_, e := lifecycleControl(ctx, c.ControlEndpoint, "/mark", Object{"scenario": sc.ID, "kind": kind, "id": id})
			return e
		}
		for _, step := range sc.Steps {
			op := str(step["op"])
			key := str(step["key"])
			request := sc.Requests[key]
			id := lifecycleID(request)
			b := boundaries[id]
			if request != nil && b == nil {
				b = &lifecycleBoundary{}
				boundaries[id] = b
			}
			switch op {
			case "send":
				if request == nil {
					return fmt.Errorf("unknown request %s", key)
				}
				request = obj(clone(request))
				params := obj(request["params"])
				sub := str(step["subscription"])
				if sub == "" && len(c.Uploads) == 1 {
					for scope := range c.Uploads {
						sub = scope
					}
				}
				// Shared fixtures omit the body subscription on intercept sends.
				// Only the single default policy supplies that implicit scope; never
				// search confirmed references across explicitly configured scopes.
				if sub == "" && len(c.Uploads) == 0 && c.Upload.Endpoint != "" {
					sub = "body"
				}
				_, allowed := c.Uploads[sub]
				projected, err := ProjectContent(obj(params["event"]), c.ContentSelections[sub], allowed)
				if err != nil {
					return err
				}
				resolveUploadAliases(projected, sub, aliases)
				params["event"] = projected
				if e = checkContent(obj(obj(request["params"])["event"]), sub, confirmed); e != nil {
					return e
				}
				if e = v.validate("intercept-request", request); e != nil {
					return e
				}
				slot := str(step["slot"])
				if attempts[slot] != nil {
					return fmt.Errorf("duplicate slot %s", slot)
				}
				a := &lifecycleAttempt{request: request, done: make(chan lifecycleResult, 1)}
				attempts[slot] = a
				options := lifecycleContentOptions(c, sub, confirmed, obj(params["event"]))
				go func() {
					response, err := lifecyclePublicCall(ctx, a.request, pipe, eventHTTP, eventToken, c.Endpoint, options)
					a.done <- lifecycleResult{response: response, err: err}
				}()
			case "wait", "release":
				if request == nil {
					return fmt.Errorf("unknown request")
				}
				m := Object{"id": request["id"]}
				if n, ok := step["count"]; ok {
					m["count"] = n
				}
				if _, e = lifecycleControl(ctx, c.ControlEndpoint, "/"+op, m); e != nil {
					return e
				}
			case "receive":
				slot := str(step["slot"])
				a := attempts[slot]
				if a == nil {
					return fmt.Errorf("unknown slot")
				}
				var reply lifecycleResult
				select {
				case reply = <-a.done:
				case <-ctx.Done():
					return ctx.Err()
				}

				bid := lifecycleID(a.request)
				boundary := boundaries[bid]
				if (reply.response != nil && lifecycleID(reply.response) != bid) || boundary.cancelled || boundary.accepted || boundary.staged != nil {
					appendActual("ignored", slot)
				} else {
					boundary.staged = reply.response
					boundary.protocolError = reply.err
					if boundary.staged == nil {
						boundary.staged = Object{"id": a.request["id"]}
					}
					if e = mark("acquired", a.request["id"]); e != nil {
						return e
					}
				}
			case "cancel":
				if b == nil {
					return fmt.Errorf("unknown request")
				}
				if !b.cancelled {
					b.cancelled = true
					b.staged = nil
					appendActual("cancelled", request["id"])
					if e = mark("cancelled", request["id"]); e != nil {
						return e
					}
				}
			case "nativeSettle":
				if b == nil || b.cancelled || b.accepted {
					return fmt.Errorf("invalid native settlement")
				}
				state := Object{"decision": "allow", "input": clone(obj(obj(obj(request["params"])["event"])["tool"])["input"])}
				b.accepted = true
				obj(actual["states"])[str(request["id"])] = state
			case "accept", "failOpen":
				if b == nil {
					return fmt.Errorf("unknown request")
				}
				if b.cancelled || b.accepted {
					continue
				}
				response := b.staged
				if op == "failOpen" {
					response = lifecycleReply(request["id"])
				}
				if response == nil {
					continue
				}
				if op != "failOpen" && b.protocolError != nil {
					return fmt.Errorf("scenario %s: %w", sc.ID, b.protocolError)
				}
				state, e := Apply(request, response)
				if e != nil {
					return e
				}
				b.accepted = true
				b.staged = nil
				obj(actual["states"])[str(request["id"])] = state
				appendActual("published", request["id"])
				if e = mark("accepted", request["id"]); e != nil {
					return e
				}
			case "emit":
				if pipe == nil {
					return fmt.Errorf("emit requires stdio")
				}
				response := obj(step["response"])
				if e = v.validate("intercept-response", response); e != nil {
					return e
				}
				emitID := lifecycleID(response)
				pipe.mu.Lock()
				count := pipe.discarded[emitID] + 1
				pipe.mu.Unlock()
				if _, e = lifecycleControl(ctx, c.ControlEndpoint, "/emit", Object{"response": response}); e != nil {
					return e
				}
				if e = pipe.waitDiscarded(ctx, emitID, count); e != nil {
					return e
				}
				appendActual("ignored", fmt.Sprint("unsolicited:", response["id"]))
				if e = mark("discarded", response["id"]); e != nil {
					return e
				}
			case "upload":
				sub := str(step["subscription"])
				binding, ok := c.Uploads[sub]
				if !ok && c.Upload.Endpoint != "" {
					binding = c.Upload
					ok = true
				}
				if override, present := step["upload"]; present {
					// Overrides replace credentials, never inherit them. The discovered
					// endpoint remains the fallback for process-trusted stdio fixtures.
					endpoint := binding.Endpoint
					raw, err := json.Marshal(override)
					if err != nil {
						return err
					}
					binding = UploadBinding{}
					if err = json.Unmarshal(raw, &binding); err != nil {
						return err
					}
					if binding.Endpoint == "" {
						binding.Endpoint = endpoint
					}
					ok = binding.Endpoint != ""
				}
				if !ok {
					return fmt.Errorf("no upload binding for subscription %s", sub)
				}
				encoded, present := step["bodyBase64"].(string)
				if !present {
					return fmt.Errorf("upload fixture requires bodyBase64")
				}
				body, err := base64.StdEncoding.Strict().DecodeString(encoded)
				if err != nil {
					return err
				}
				// A failed retry must not reuse an earlier fixture alias as a ready ref.
				delete(aliases, contentKey(sub, str(step["ref"])))
				descriptor, status, err := uploadFixture(ctx, binding, sub, str(step["ref"]), body, step)
				if err == nil {
					confirmed[contentKey(sub, str(descriptor["ref"]))] = string(body)
					aliases[contentKey(sub, str(step["ref"]))] = str(descriptor["ref"])
				}
				if status == 0 || (status == 201 && err != nil) {
					return err
				}
				appendActual("uploadStatuses", status)
			case "observe":
				if b == nil || (!b.accepted && !b.cancelled) {
					return fmt.Errorf("observe before settlement")
				}
				event := obj(clone(obj(request["params"])["event"]))
				tool := obj(event["tool"])
				if b.accepted && tool != nil {
					tool["input"] = clone(obj(obj(actual["states"])[str(request["id"])])["input"])
				}
				if items, ok := step["items"]; ok {
					event["items"] = clone(items)
				}
				sub := str(step["subscription"])
				_, allowed := c.Uploads[sub]
				event, e = ProjectContent(event, c.ContentSelections[sub], allowed)
				if e != nil {
					return e
				}
				resolveUploadAliases(event, sub, aliases)
				notification := Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": event}}
				if e = checkContent(event, sub, confirmed); e != nil {
					return e
				}
				if e = v.validate("observe", notification); e != nil {
					return e
				}
				if _, e = lifecyclePublicCall(ctx, notification, pipe, eventHTTP, eventToken, c.Endpoint, lifecycleContentOptions(c, sub, confirmed, event)); e != nil {
					var acknowledgement *lifecycleObservationAcknowledgementError
					if !errors.As(e, &acknowledgement) {
						return e
					}
					// The public client rejected this acknowledgement. Settlement
					// is already final; report delivery evidence separately.
					observationDiagnostics = append(observationDiagnostics, Object{"eventId": event["id"], "subscription": sub, "kind": "invalid-observation-acknowledgement", "status": acknowledgement.Status, "response": clone(acknowledgement.Response)})
				}
				eventID := str(event["id"])
				observed[eventID]++
				if _, e = lifecycleControl(ctx, c.ControlEndpoint, "/wait-observed", Object{"eventId": event["id"], "count": observed[eventID]}); e != nil {
					return e
				}
				appendActual("observations", Object{"eventId": event["id"], "subscription": sub, "input": clone(tool["input"])})
			default:
				return fmt.Errorf("unknown lifecycle operation %s", op)
			}
		}
		result := Object{"id": sc.ID, "actual": actual}
		if len(observationDiagnostics) > 0 {
			result["observationDiagnostics"] = observationDiagnostics
		}
		results = append(results, result)
	}
	receipts, e := lifecycleControl(ctx, c.ControlEndpoint, "/receipts", nil)
	if e != nil {
		return e
	}
	return writeAtomic(c.ReportFile, Object{"language": "go", "results": results, "receipts": receipts})
}

// Discard rendezvous is test control only; unmatched frames never resolve a slot.
func (p *lifecyclePipe) waitDiscarded(ctx context.Context, id string, count int) error {
	watchdog := time.NewTimer(30 * time.Second)
	defer watchdog.Stop()
	for {
		p.mu.Lock()
		n := p.discarded[id]
		err := p.err
		changed := p.changed
		p.mu.Unlock()
		if n >= count {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-watchdog.C:
			return fmt.Errorf("unsolicited frame drain timeout")
		}
	}
}

// Fixture references are local aliases only. Preserve size/hash so a corrupt
// fixture descriptor is still rejected before publication.
func resolveUploadAliases(value any, scope string, aliases map[string]string) {
	switch x := value.(type) {
	case map[string]any:
		if ref, ok := x["ref"].(string); ok && x["size"] != nil && x["sha256"] != nil {
			if allocated, ok := aliases[contentKey(scope, ref)]; ok {
				x["ref"] = allocated
			}
		}
		for _, child := range x {
			resolveUploadAliases(child, scope, aliases)
		}
	case []any:
		for _, child := range x {
			resolveUploadAliases(child, scope, aliases)
		}
	}
}
