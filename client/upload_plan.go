package client

import (
	"context"
	"errors"
	"math"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/agenthooksprotocol/go-sdk/internal/ownedcontent"
)

type uploadReceiver struct {
	backendID    string
	subscription int
}
type uploadPlanContextKey struct{}
type uploadReceiverContextKey struct{}
type uploadPreparationContextKey struct{}

// Invocation-local metadata only: attachment owners remain the sole byte store.
// Backend/subscription identity, not endpoint equality, defines receipt scope.
type uploadPlan struct {
	receivers map[uploadReceiver]*receiverUploads
}
type receiverUploads struct {
	mu   sync.Mutex
	refs map[*ContentSource]string
	err  error
}

func (r *receiverUploads) fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = err
	}
}
func (p *uploadPlan) failure(receiver uploadReceiver) error {
	r := p.receivers[receiver]
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}
func plannedUpload(ctx context.Context, owner *ContentSource) (string, bool, error) {
	plan, _ := ctx.Value(uploadPlanContextKey{}).(*uploadPlan)
	if plan == nil {
		return "", false, nil
	}
	receiver, ok := ctx.Value(uploadReceiverContextKey{}).(uploadReceiver)
	if !ok {
		return "", true, errors.New("missing upload receiver scope")
	}
	r := plan.receivers[receiver]
	if r == nil {
		return "", true, errors.New("missing planned upload receiver")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return "", true, r.err
	}
	ref, ok := r.refs[owner]
	if !ok {
		return "", true, errors.New("attachment has no authorized planned receipt")
	}
	return ref, true, nil
}

type plannedTransfer struct {
	receiver uploadReceiver
	sub      map[string]any
	owner    *ContentSource
	items    []map[string]any
}

// planUploads settles all authorized immutable transfers before serial policy
// calls. Failures are retained per subscription, never applied at this barrier.
func (c *Hooks) planUploads(ctx context.Context, event map[string]any, p *preparedBoundary) *uploadPlan {
	plan := &uploadPlan{receivers: map[uploadReceiver]*receiverUploads{}}
	paths := make([]string, 0, len(p.sources))
	for path := range p.sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	tasks := []plannedTransfer{}
	for _, backend := range c.backends {
		for index, sub := range backend.subscriptions {
			if !subscriptionMatches(sub, compositionString(event["type"])) {
				continue
			}
			key := uploadReceiver{backend.id, index}
			r := &receiverUploads{refs: map[*ContentSource]string{}}
			plan.receivers[key] = r
			selection := sdkObj(sub["content"])
			if !contentMode(compositionString(selection["default"])) {
				r.fail(errors.New("invalid content selection"))
				continue
			}
			valid := true
			for _, mode := range selection {
				if !contentMode(compositionString(mode)) {
					valid = false
				}
			}
			if !valid {
				r.fail(errors.New("invalid content selection"))
				continue
			}
			groups := map[*ContentSource]int{}
			selected := []plannedTransfer{}
			for _, path := range paths {
				owner := p.sources[path]
				item := preparedAt(event, path)
				if owner == nil || item == nil {
					continue
				}
				if event["type"] == "file.changed" && fileChangeReferencePath(path) {
					item = map[string]any{"id": path, "kind": "file", "category": "files", "mediaType": "application/octet-stream", "synthesized": true}
				} else if item["kind"] != "attachment" {
					continue
				}
				mode := compositionString(selection["default"])
				if override, ok := selection[contentCategory(item)].(string); ok {
					mode = override
				}
				if mode != "body" {
					continue
				}
				scope := ContentAuthorization{Operation: "read", BackendID: backend.id, Subscription: contentClone(sub).(map[string]any), Item: contentDescriptor(item, "body")}
				scope.SubscriptionID, _ = sub["id"].(string)
				if c.opts.Content.AuthorizeContent == nil {
					continue
				}
				allowed, err := c.opts.Content.AuthorizeContent(ctx, scope)
				if err != nil {
					r.fail(err)
					break
				}
				if !allowed {
					continue
				}
				detached := contentClone(item).(map[string]any)
				detached["body"] = owner
				if i, ok := groups[owner]; ok {
					selected[i].items = append(selected[i].items, detached)
				} else {
					groups[owner] = len(selected)
					selected = append(selected, plannedTransfer{receiver: key, sub: sub, owner: owner, items: []map[string]any{detached}})
				}
			}
			if r.err != nil {
				continue
			}
			if len(selected) > 0 {
				if err := c.validatePlannedUpload(sdkObj(sub["upload"])); err != nil {
					r.fail(err)
					continue
				}
				tasks = append(tasks, selected...)
			}
		}
	}
	// Source demand has an invocation-scoped shared deadline: a short receiver
	// cannot cancel bytes still needed by another requesting destination. Individual
	// receiver preparation deadlines are applied independently after materialization.
	type demand struct {
		tasks   []plannedTransfer
		limit   int64
		owner   *ContentSource
		timeout time.Duration
		started time.Time
		err     error
	}
	demands := map[*ContentSource]*demand{}
	ordered := []*demand{}
	for _, task := range tasks {
		ms, _ := contentInt(sdkObj(task.sub["upload"])["timeoutMs"])
		timeout := time.Duration(ms) * time.Millisecond
		limit, _ := contentInt(sdkObj(task.sub["upload"])["maxBytes"])
		if limit > p.limit {
			limit = p.limit
		}
		d := demands[task.owner]
		if d == nil {
			d = &demand{owner: task.owner}
			demands[task.owner] = d
			ordered = append(ordered, d)
		}
		d.tasks = append(d.tasks, task)
		if limit > d.limit {
			d.limit = limit
		}
		if timeout > d.timeout {
			d.timeout = timeout
		}
	}
	cap := c.opts.MaxConcurrentUploads
	if cap == 0 {
		cap = 8
	}
	work := make(chan plannedTransfer)
	var wg sync.WaitGroup
	for i := 0; i < cap; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range work {
				r := plan.receivers[task.receiver]
				if err := ctx.Err(); err != nil {
					r.fail(err)
					continue
				}
				d := demands[task.owner]
				if d.err != nil {
					r.fail(d.err)
					continue
				}
				ms, _ := contentInt(sdkObj(task.sub["upload"])["timeoutMs"])
				deadlineCtx, cancel := context.WithDeadline(ctx, d.started.Add(time.Duration(ms)*time.Millisecond))
				transferCtx := context.WithValue(deadlineCtx, uploadPreparationContextKey{}, true)
				scope := ContentAuthorization{Operation: "read", BackendID: task.receiver.backendID, Subscription: contentClone(task.sub).(map[string]any)}
				validate := func(raw []byte) error {
					for _, item := range task.items {
						if err := contentMatches(item, raw); err != nil {
							return err
						}
					}
					return nil
				}
				prepared, err := c.projectContentItem(transferCtx, task.items[0], sdkObj(task.sub["content"]), task.sub, scope, validate)
				cancel()
				if err != nil {
					r.fail(err)
					continue
				}
				ref := compositionString(sdkObj(prepared["body"])["ref"])
				if ref == "" {
					r.fail(errors.New("upload was not confirmed"))
					continue
				}
				r.mu.Lock()
				r.refs[task.owner] = ref
				r.mu.Unlock()
			}
		}()
	}
	readers := make(chan *demand)
	var reads sync.WaitGroup
	// Materialization follows aggregate byte-budget admission order. Transfers
	// run concurrently as soon as each owner is ready; unrelated read admission
	// does not consume a later owner's receiver deadline.
	workers := 1
	if len(ordered) == 0 {
		workers = 0
	}
	for i := 0; i < workers; i++ {
		reads.Add(1)
		go func() {
			defer reads.Done()
			for d := range readers {
				d.started = time.Now()
				readCtx, cancel := context.WithTimeout(ctx, d.timeout)
				budget, _ := ctx.Value(contentSourceBudgetKey{}).(*contentSourceBudget)
				if budget != nil {
					_, d.err = budget.snapshot(readCtx, d.owner, d.limit, p.limit)
				} else {
					_, d.err = ownedcontent.Borrow(d.owner, readCtx, d.limit)
				}
				cancel()
				for _, task := range d.tasks {
					work <- task
				}
			}
		}()
	}
	for _, d := range ordered {
		readers <- d
	}
	close(readers)
	reads.Wait()
	close(work)
	wg.Wait()
	return plan
}

func contentDescriptor(item map[string]any, selection string) map[string]any {
	out := map[string]any{}
	for _, key := range []string{"id", "kind", "mediaType", "category", "size", "sha256", "synthesized"} {
		if v, ok := item[key]; ok {
			out[key] = contentClone(v)
		}
	}
	out["selection"] = selection
	return out
}

// Reject invalid destination configuration before materializing any source.
func (c *Hooks) validatePlannedUpload(upload map[string]any) error {
	endpoint, ok := upload["endpoint"].(string)
	if !ok || strings.ContainsAny(endpoint, "\r\n") {
		return errors.New("invalid upload endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid upload endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	loopback := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback && c.opts.Content.AllowLoopbackHTTP) {
		return errors.New("upload requires HTTPS")
	}
	timeout, ok := contentInt(upload["timeoutMs"])
	if !ok || timeout < 1 || timeout > math.MaxInt64/int64(time.Millisecond) {
		return errors.New("invalid upload timeout")
	}
	limit, ok := contentInt(upload["maxBytes"])
	if !ok || limit < 0 {
		return errors.New("invalid upload byte limit")
	}
	return nil
}
