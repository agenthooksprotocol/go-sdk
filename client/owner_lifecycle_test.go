package client

import (
	"context"
	"github.com/agenthooksprotocol/go-sdk/internal/ownedcontent"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

func preparedLifecycleFixture(t *testing.T) (map[string]any, *preparedBoundary, *ContentSource) {
	t.Helper()
	part := preparedOwnerAttachment("binary")
	part["selection"] = "body"
	part["body"] = map[string]any{"ref": "urn:original"}
	event := preparedOwnerEvent(preparedOwnerMessage("one", part, preparedOwnerText("text", "original")))
	c := &Client{opts: Options{Content: ContentOptions{Resolver: func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("original")), nil
	}}}}
	p, err := c.prepareBoundary(context.Background(), event, preparedOwnerCaps("response"), interceptConfig{})
	if err != nil {
		t.Fatal(err)
	}
	owner := p.sources["/items/0/parts/0"]
	if owner == nil || !p.owned[owner] {
		t.Fatal("missing managed attachment")
	}
	raw, err := ownedcontent.Borrow(owner, context.Background(), p.limit)
	if err != nil || string(raw) != "original" {
		t.Fatal(string(raw), err)
	}
	t.Cleanup(func() { _ = owner.Retire() })
	return event, p, owner
}
func TestReleaseUnusedRejectsSpeculativeOwners(t *testing.T) {
	event, p, original := preparedLifecycleFixture(t)
	part := preparedAt(event, "/items/0/parts/0")
	staged := []any{preparedOwnerMessage("one", preparedOwnerText("text", "speculative"), part)}
	invalid := []any{preparedOwnerMessage("one", preparedOwnerAttachment("new-binary"))}
	result, err := preparedOwnerCompose(t, event, "response", p, staged, invalid)
	if err == nil || result != nil {
		t.Fatal("invalid staged edit accepted")
	}
	p.releaseUnused(nil)
	if len(p.owned) != 1 || !p.owned[original] || p.sources["/items/0/parts/0"] != original || string(preparedTestBytes(p, "/items/0/parts/0")) != "original" {
		t.Fatal("failed transaction lost effective owner")
	}
	if len(p.sources) != 1 || preparedAt(event, "/items/0/parts/1")["text"] != "original" {
		t.Fatal("failed transaction published inline edit or speculative owner")
	}
}
func TestReleaseUnusedPreservesEffectiveClone(t *testing.T) {
	event, p, original := preparedLifecycleFixture(t)
	part := preparedAt(event, "/items/0/parts/0")
	accepted, err := preparedOwnerCompose(t, event, "response", p, []any{preparedOwnerMessage("one", preparedOwnerText("text", "effective"), part)})
	if err != nil {
		t.Fatal(err)
	}
	effective := accepted.prepared
	effective.releaseUnused(nil)
	if len(p.owned) != 1 || !p.owned[original] || effective.sources["/items/0/parts/1"] != original || string(preparedTestBytes(effective, "/items/0/parts/1")) != "original" {
		t.Fatal("cleanup retired retained owner")
	}
	if preparedAt(compositionObject(accepted.Event), "/items/0/parts/0")["text"] != "effective" {
		t.Fatal("inline edit lost")
	}
	effective.releaseUnused(nil)
	if len(effective.owned) != 1 {
		t.Fatal("repeated cleanup changed live ledger")
	}
	removed, err := preparedOwnerCompose(t, compositionObject(accepted.Event), "response", effective, []any{preparedOwnerMessage("one", preparedOwnerText("text", "effective"))})
	if err != nil {
		t.Fatal(err)
	}
	removed.prepared.releaseUnused(nil)
	if _, ok := ownedcontent.Available(original); ok {
		t.Fatal("removed binary owner remains readable")
	}
	if len(removed.prepared.owned) != 0 || len(removed.prepared.sources) != 0 {
		t.Fatal("removed owner remains indexed")
	}
}
func TestReleaseUnusedCleansLazyOwnersWithoutOpening(t *testing.T) {
	var opens, cleanups atomic.Int32
	stale := ownedcontent.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
		opens.Add(1)
		return io.NopCloser(strings.NewReader("unused")), nil
	}, func() error { cleanups.Add(1); return nil })
	external := ownedcontent.NewAttachment([]byte("external"))
	live := ownedcontent.NewAttachment([]byte("live"))
	p := &preparedBoundary{sources: map[string]*ContentSource{"/items/0/parts/0": live}, owned: map[*ContentSource]bool{stale: true, live: true}}
	// An original user source in a discarded index is not in the owned ledger.
	discarded := p.clone()
	discarded.sources["/items/1/parts/0"] = external
	p.releaseUnused(nil)
	p.releaseUnused(nil)
	if opens.Load() != 0 || cleanups.Load() != 1 {
		t.Fatal("unused lazy owner cleanup", opens.Load(), cleanups.Load())
	}
	if _, err := ownedcontent.Borrow(stale, context.Background(), 1024); err == nil {
		t.Fatal("retired lazy owner reopened")
	}
	if raw, ok := ownedcontent.Available(external); !ok || string(raw) != "external" {
		t.Fatal("untracked user source retired")
	}
	if raw, ok := ownedcontent.Available(live); !ok || string(raw) != "live" {
		t.Fatal("live source retired")
	}
	_ = external.Retire()
	_ = live.Retire()
}

func TestReleaseUnusedReclaimsSerialEditBudget(t *testing.T) {
	event, p, owner := preparedLifecycleFixture(t)
	budget := &contentSourceBudget{seen: map[*ContentSource]bool{}}
	for i := 0; i < 8; i++ {
		if _, err := budget.snapshot(context.Background(), owner, 8, 8); err != nil {
			t.Fatal("inline versions exhausted immutable budget", i, err)
		}
		part := preparedAt(event, "/items/0/parts/0")
		accepted, err := preparedOwnerCompose(t, event, "response", p, []any{preparedOwnerMessage("one", part, preparedOwnerText("text", "version"+string(rune('1'+i))))})
		if err != nil {
			t.Fatal(err)
		}
		p = accepted.prepared
		event = compositionObject(accepted.Event)
		p.releaseUnused(budget)
		if budget.used != 8 || len(budget.seen) != 1 || len(p.owned) != 1 || len(p.sources) != 1 || p.sources["/items/0/parts/0"] != owner {
			t.Fatal("inline versions accumulated owners or changed attachment accounting", budget.used)
		}
	}
	removed, err := preparedOwnerCompose(t, event, "response", p, []any{})
	if err != nil {
		t.Fatal(err)
	}
	removed.prepared.releaseUnused(budget)
	if budget.used != 0 || len(budget.seen) != 0 || len(removed.prepared.owned) != 0 {
		t.Fatal("removed attachment remained accounted", budget.used)
	}
	if _, ok := ownedcontent.Available(owner); ok {
		t.Fatal("removed owner remained materialized")
	}
}
