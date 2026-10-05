package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"strings"
	"unicode/utf8"
)

// preparedBoundary is occurrence-owned. Staging clones its indexes; backing byte
// slices are immutable and never exposed to callers or application resolvers.
type preparedBoundary struct {
	bodies   map[string][]byte
	slots    map[string][]string
	limit    int64
	snapshot *ElicitationRequest
	bindings map[string]ModificationTarget
	absent   map[string]bool
}
type preparedContextKey struct{}

func (p *preparedBoundary) clone() *preparedBoundary {
	q := &preparedBoundary{bodies: map[string][]byte{}, slots: map[string][]string{}, limit: p.limit, snapshot: p.snapshot, bindings: map[string]ModificationTarget{}, absent: map[string]bool{}}
	for k, v := range p.absent {
		q.absent[k] = v
	}
	for k, v := range p.bindings {
		q.bindings[k] = v
	}
	for k, v := range p.slots {
		q.slots[k] = append([]string(nil), v...)
	}
	for k, v := range p.bodies {
		q.bodies[k] = v
	}
	return q
}
func preparedAt(event map[string]any, path string) map[string]any {
	var v any = event
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		switch x := v.(type) {
		case map[string]any:
			v = x[part]
		case []any:
			var n int
			if _, e := fmt.Sscan(part, &n); e != nil || n < 0 || n >= len(x) {
				return nil
			}
			v = x[n]
		default:
			return nil
		}
	}
	return sdkObj(v)
}
func preparedItemPaths(event map[string]any, target string) ([]string, error) {
	kind := compositionString(event["type"])
	switch target {
	case "input", "workspace":
		return nil, nil
	case "instructions", "summary":
		return []string{"/" + target}, nil
	case "content":
		if kind == "user.elicitation.result" {
			return []string{"/elicitation/result"}, nil
		}
	}
	return nil, errors.New("ambiguous native target requires WithModificationTarget")
}
func (c *Client) prepareBoundary(ctx context.Context, event, caps map[string]any, cfg interceptConfig) (*preparedBoundary, error) {
	p := &preparedBoundary{bodies: map[string][]byte{}, slots: map[string][]string{}, limit: c.opts.MaxContentBytes, bindings: map[string]ModificationTarget{}, absent: map[string]bool{}}
	if p.limit == 0 {
		p.limit = 4 << 20
	}
	if p.limit == math.MaxInt64 {
		p.limit--
	}
	if p.limit < 0 {
		return nil, errors.New("invalid prepared byte limit")
	}
	for target, binding := range cfg.targets {
		grant := sdkObj(sdkObj(caps["modify"])[target])
		if grant["replace"] != true && grant["merge"] != true {
			return nil, errors.New("target binding has no modification grant")
		}
		if _, err := preparedBindingPaths(event, target, binding); err != nil {
			return nil, err
		}
	}
	for target, raw := range sdkObj(caps["modify"]) {
		grant := sdkObj(raw)
		if grant["replace"] != true && grant["merge"] != true {
			continue
		}
		if target != compositionTargets[compositionString(event["type"])] {
			continue
		}
		binding, explicit := cfg.targets[target]
		paths, err := preparedItemPaths(event, target)
		if target != "input" && target != "workspace" && target != "instructions" && target != "summary" && !(target == "content" && event["type"] == "user.elicitation.result") {
			if !explicit {
				return nil, errors.New("ambiguous native target requires WithModificationTarget")
			}
			paths, err = preparedBindingPaths(event, target, binding)
			encoded, encodeErr := json.Marshal(binding)
			if encodeErr != nil {
				return nil, errors.New("invalid target binding")
			}
			var detached ModificationTarget
			if json.Unmarshal(encoded, &detached) != nil {
				return nil, errors.New("invalid target binding")
			}
			p.bindings[target] = detached
		} else if explicit {
			return nil, errors.New("fixed target does not accept a custom binding")
		}
		if err != nil {
			return nil, err
		}
		p.slots[target] = paths
		for _, path := range paths {
			item := preparedAt(event, path)
			if item == nil && path == "/instructions" && cfg.instructions != nil {
				item, _ = sdkMap(cfg.instructions)
				event["instructions"] = item
				cfg.instructionsAbsent = true
			}
			if item == nil {
				return nil, errors.New("modification target descriptor is absent")
			}
			if path == "/instructions" && cfg.instructionsAbsent && item["selection"] == "metadata" && item["body"] == nil {
				if !preparedMedia(item) {
					return nil, errors.New("instruction template requires text or JSON media type")
				}
				p.absent[path] = true
				continue
			}
			if err := p.resolve(ctx, c, item); err != nil {
				return nil, err
			}
		}
	}
	kind := compositionString(event["type"])
	if kind == "user.elicitation.request" || kind == "user.elicitation.result" {
		field := "request"
		if kind == "user.elicitation.result" {
			field = "result"
		}
		item := sdkObj(sdkObj(event["elicitation"])[field])
		if item["selection"] == "body" {
			if err := p.resolve(ctx, c, item); err != nil {
				return nil, err
			}
		}
		snapshot, err := prepareElicitation(event, cfg.elicitation, p.bodies)
		if err != nil {
			return nil, err
		}
		p.snapshot = snapshot
		if compositionContains(caps["effects"], "return") && (snapshot == nil || snapshot.request == "") {
			return nil, errors.New("elicitation answers require an original request body")
		}
	}

	return p, nil
}
func (p *preparedBoundary) resolve(ctx context.Context, c *Client, item map[string]any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !preparedMedia(item) {
		return errors.New("modifiable body requires a text or JSON descriptor")
	}
	body := sdkObj(item["body"])
	ref := compositionString(body["ref"])
	if ref == "" {
		return errors.New("modification requires an available content body")
	}
	raw, ok := p.bodies[ref]
	if !ok {
		if c.opts.Content.Resolver == nil {
			return errors.New("modification requires a content resolver")
		}
		reader, err := c.opts.Content.Resolver(ctx, ref)
		if err != nil {
			return err
		}
		if reader == nil {
			return errors.New("content resolver returned no reader")
		}
		raw, err = readOwnedContent(ctx, reader, p.limit)
		if err != nil {
			return err
		}

		if int64(len(raw)) > p.limit {
			return errors.New("prepared content exceeds byte limit")
		}
	}
	if err := contentMatches(body, raw); err != nil {
		return err
	}
	if err := contentMatches(item, raw); err != nil {
		return err
	}
	if _, err := preparedDecode(item, raw); err != nil {
		return err
	}
	if !ok {
		p.bodies[ref] = bytes.Clone(raw)
	}
	return p.bound()
}
func (p *preparedBoundary) bound() error {
	var total int64
	for _, raw := range p.bodies {
		if int64(len(raw)) > p.limit-total {
			return errors.New("prepared content exceeds occurrence byte limit")
		}
		total += int64(len(raw))
	}
	return nil
}
func preparedMedia(item map[string]any) bool {
	media, _, err := mime.ParseMediaType(compositionString(item["mediaType"]))
	return err == nil && (strings.HasPrefix(media, "text/") || media == "application/json" || strings.HasSuffix(media, "+json"))
}
func preparedDecode(item map[string]any, raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("modifiable content must be UTF-8")
	}
	media, _, err := mime.ParseMediaType(compositionString(item["mediaType"]))
	if err != nil {
		return nil, errors.New("invalid content media type")
	}
	if media == "application/json" || strings.HasSuffix(media, "+json") {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var value any
		if dec.Decode(&value) != nil || dec.Decode(new(any)) != io.EOF {
			return nil, errors.New("invalid JSON content")
		}
		return value, nil
	}
	if strings.HasPrefix(media, "text/") {
		return string(raw), nil
	}
	return nil, errors.New("modifiable body requires a text or JSON descriptor")
}
func (p *preparedBoundary) values(event map[string]any) (map[string]any, error) {
	values := map[string]any{}
	for target, paths := range p.slots {
		if target == "input" {
			continue
		}
		if target == "workspace" {
			values[target] = contentClone(sdkObj(event["workspace"])["change"])
			continue
		}
		if binding, ok := p.bindings[target]; ok && binding.Path == "/params" {
			values[target] = contentClone(event["params"])
			continue
		}
		vs := []any{}
		for _, path := range paths {
			item := preparedAt(event, path)
			if p.absent[path] {
				vs = append(vs, nil)
				continue
			}
			v, err := preparedDecode(item, p.bodies[compositionString(sdkObj(item["body"])["ref"])])
			if err != nil {
				return nil, err
			}
			if target == "content" && event["type"] == "user.elicitation.result" {
				v = sdkObj(v)["content"]
			}
			vs = append(vs, v)
		}
		binding, bound := p.bindings[target]
		if bound && preparedCollection(binding.Path) {
			values[target] = vs
		} else if len(vs) == 1 {
			values[target] = vs[0]
		} else {
			values[target] = vs
		}
	}
	return values, nil
}
func (p *preparedBoundary) apply(event map[string]any, target string, value any) error {
	if target == "workspace" {
		sdkObj(event["workspace"])["change"] = value
		return nil
	}
	binding, bound := p.bindings[target]
	if bound && binding.Path == "/params" {
		if sdkObj(value) == nil {
			return errors.New("model params modification requires object")
		}
		event["params"] = value
		return nil
	}
	paths := p.slots[target]
	if bound && preparedCollection(binding.Path) {
		return p.applyCollection(event, target, binding, value)
	}
	if len(paths) == 0 {
		return errors.New("unprepared modification target")
	}
	values := []any{value}
	if len(paths) != 1 {
		return errors.New("invalid scalar target binding")
	}
	for i, path := range paths {
		item := preparedAt(event, path)
		if !preparedMedia(item) {
			return errors.New("modified body requires a text or JSON descriptor")
		}
		oldRef := compositionString(sdkObj(item["body"])["ref"])
		old := p.bodies[oldRef]
		prev, err := preparedDecode(item, old)
		if err != nil && oldRef != "" {
			return err
		}
		if oldRef != "" && compositionEqual(prev, values[i]) {
			continue
		}
		var raw []byte
		media, _, _ := mime.ParseMediaType(compositionString(item["mediaType"]))
		if strings.HasPrefix(media, "text/") {
			text, ok := values[i].(string)
			if !ok {
				return errors.New("text modification requires a string")
			}
			raw = []byte(text)
		} else {
			raw, err = json.Marshal(values[i])
			if err != nil {
				return err
			}
		}
		if !utf8.Valid(raw) || int64(len(raw)) > p.limit {
			return errors.New("modified body exceeds content constraints")
		}
		id, err := sdkID()
		if err != nil {
			return err
		}
		ref := "ahp-internal:" + id
		hash := fmt.Sprintf("%x", sha256.Sum256(raw))
		item["body"] = map[string]any{"ref": ref, "size": len(raw), "sha256": hash}
		if _, ok := item["size"]; ok {
			item["size"] = len(raw)
		}
		if _, ok := item["sha256"]; ok {
			item["sha256"] = hash
		}
		delete(p.absent, path)
		item["selection"] = "body"
		delete(item, "gap")
		p.bodies[ref] = bytes.Clone(raw)
	}
	p.prune(event)
	return p.bound()
}
