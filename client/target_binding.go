package client

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

func preparedCollection(path string) bool {
	return path == "/items" || path == "/message/text" || path == "/message/payload"
}

func preparedBindingPaths(event map[string]any, target string, binding ModificationTarget) ([]string, error) {
	kind := compositionString(event["type"])
	if target != compositionTargets[kind] {
		return nil, errors.New("target binding does not match boundary")
	}
	base := "/items"
	switch kind {
	case "user.message.inbound":
		base = "/message/text"
	case "user.message.outbound":
		base = "/message/payload"
	}
	if kind == "model.request.before" && binding.Path == "/params" {
		if len(binding.Templates) > 0 {
			return nil, errors.New("params binding does not accept item templates")
		}
		return nil, nil
	}
	if binding.Path != base {
		if !strings.HasPrefix(binding.Path, base+"/") {
			return nil, errors.New("target binding is outside canonical content container")
		}
		index := strings.TrimPrefix(binding.Path, base+"/")
		n, err := strconv.Atoi(index)
		if err != nil || n < 0 || strconv.Itoa(n) != index || preparedAt(event, binding.Path) == nil {
			return nil, errors.New("target binding requires an existing canonical item")
		}
		if len(binding.Templates) > 0 {
			return nil, errors.New("scalar binding does not accept collection templates")
		}
		return []string{binding.Path}, nil
	}
	for _, template := range binding.Templates {
		raw, err := sdkMap(template)
		if err != nil || canonical.Validate("content-item", sdkJSON(raw)) != nil || !preparedMedia(raw) {
			return nil, errors.New("invalid host content template")
		}
	}
	var items []any
	if base == "/items" {
		items = sdkArray(event["items"])
	} else {
		items = sdkArray(sdkObj(event["message"])[strings.TrimPrefix(base, "/message/")])
	}
	paths := make([]string, len(items))
	for i := range items {
		paths[i] = fmt.Sprintf("%s/%d", base, i)
	}
	return paths, nil
}

func (p *preparedBoundary) applyCollection(event map[string]any, target string, binding ModificationTarget, value any) error {
	values, ok := value.([]any)
	if !ok {
		return errors.New("collection modification requires an array of body values")
	}
	oldPaths := p.slots[target]
	items := make([]any, len(values))
	paths := make([]string, len(values))
	for i := range values {
		var item map[string]any
		if i < len(oldPaths) {
			item = preparedAt(event, oldPaths[i])
		} else {
			if i >= len(binding.Templates) {
				return errors.New("added content requires a host-owned descriptor template")
			}
			var err error
			item, err = sdkMap(binding.Templates[i])
			if err != nil {
				return err
			}
			// A template is identity/metadata, not a claim that its old ref contains new bytes.
			delete(item, "body")
			delete(item, "gap")
			delete(item, "size")
			delete(item, "sha256")
		}
		items[i] = item
		paths[i] = fmt.Sprintf("%s/%d", binding.Path, i)
	}
	if binding.Path == "/items" {
		event["items"] = items
	} else {
		sdkObj(event["message"])[strings.TrimPrefix(binding.Path, "/message/")] = items
	}
	// A private scalar view reuses the same descriptor-byte machinery without
	// changing the explicit collection shape for this or later backend responses.
	for i, v := range values {
		scalar := p.clone()
		delete(scalar.bindings, target)
		scalar.slots[target] = []string{paths[i]}
		if err := scalar.apply(event, target, v); err != nil {
			return err
		}
		p.bodies = scalar.bodies
	}
	p.slots[target] = paths
	p.prune(event)
	return p.bound()
}

func (p *preparedBoundary) prune(event map[string]any) {
	live := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if ref, ok := x["ref"].(string); ok {
				live[ref] = true
			}
			for _, v := range x {
				walk(v)
			}
		case []any:
			for _, v := range x {
				walk(v)
			}
		}
	}
	walk(event)
	for ref := range p.bodies {
		if !live[ref] {
			delete(p.bodies, ref)
		}
	}
}
