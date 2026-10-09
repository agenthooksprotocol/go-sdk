package client

import (
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/internal/ownedcontent"
)

func TestReleaseUnusedRejectsSpeculativeOwners(t *testing.T) {
	item, bodies := targetTestItem("one", "text/plain", "original")
	event := targetTestEvent(t, []any{item})
	p := targetTestPrepare(t, event, "output", bodies, ModificationTarget{Path: "/items/0"})
	original := p.sources["/items/0"]
	result, err := composePrepared(targetTestRequest(t, event, "output"), compositionTestResponse(t, `[{"type":"modify","target":"output","operation":"replace","value":"speculative"},{"type":"modify","target":"output","operation":"replace","value":{}}]`), p)
	if err == nil || result != nil {
		t.Fatal("invalid staged edit accepted")
	}
	var speculative *ContentSource
	for source := range p.owned {
		if source != original {
			speculative = source
		}
	}
	if speculative == nil {
		t.Fatal("test did not stage an attachment owner")
	}
	p.releaseUnused(nil)
	if _, ok := ownedcontent.Available(speculative); ok {
		t.Fatal("rejected owner remains readable")
	}
	if len(p.owned) != 1 || !p.owned[original] || string(preparedTestBytes(p, "/items/0")) != "original" {
		t.Fatal("cleanup retired the effective owner")
	}
	_ = original.Retire()
}

func TestReleaseUnusedPreservesEffectiveClone(t *testing.T) {
	item, bodies := targetTestItem("one", "text/plain", "original")
	event := targetTestEvent(t, []any{item})
	p := targetTestPrepare(t, event, "output", bodies, ModificationTarget{Path: "/items/0"})
	original := p.sources["/items/0"]
	accepted := targetTestCompose(t, event, "output", p, `[{"type":"modify","target":"output","operation":"replace","value":"effective"}]`)
	effective := accepted.prepared
	effective.releaseUnused(nil)
	if _, ok := ownedcontent.Available(original); ok {
		t.Fatal("superseded owner remains readable")
	}
	owner := effective.sources["/items/0"]
	if len(p.owned) != 1 || !p.owned[owner] || string(preparedTestBytes(effective, "/items/0")) != "effective" {
		t.Fatal("cleanup retired the accepted clone owner")
	}
	effective.releaseUnused(nil)
	if len(effective.owned) != 1 {
		t.Fatal("repeated cleanup changed live ledger")
	}
	_ = owner.Retire()
}

func TestReleaseUnusedCleansLazyOwnersWithoutOpening(t *testing.T) {
	var opens, cleanups atomic.Int32
	stale := ownedcontent.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
		opens.Add(1)
		return io.NopCloser(strings.NewReader("unused")), nil
	}, func() error { cleanups.Add(1); return nil })
	external := ownedcontent.NewAttachment([]byte("external"))
	live := ownedcontent.NewAttachment([]byte("live"))
	p := &preparedBoundary{sources: map[string]*ContentSource{"/items/0": live}, owned: map[*ContentSource]bool{stale: true, live: true}}
	// An original user source in a discarded index is not in the owned ledger.
	discarded := p.clone()
	discarded.sources["/items/1"] = external
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
	item, bodies := targetTestItem("one", "text/plain", "version0")
	event := targetTestEvent(t, []any{item})
	p := targetTestPrepare(t, event, "output", bodies, ModificationTarget{Path: "/items/0"})
	budget := &contentSourceBudget{seen: map[*ContentSource]bool{}}
	for i := 0; i < 8; i++ {
		owner := p.sources["/items/0"]
		if _, err := budget.snapshot(context.Background(), owner, 8, 8); err != nil {
			t.Fatal("retired versions exhausted live budget", i, err)
		}
		if budget.used != 8 {
			t.Fatal("unexpected live accounting", budget.used)
		}
		accepted := targetTestCompose(t, event, "output", p, `[{"type":"modify","target":"output","operation":"replace","value":"version`+string(rune('1'+i))+`"}]`)
		p = accepted.prepared
		event = compositionObject(accepted.Event)
		p.releaseUnused(budget)
		if budget.used != 0 || len(budget.seen) != 0 {
			t.Fatal("obsolete version remained accounted", budget.used)
		}
		if len(p.owned) != 1 {
			t.Fatal("obsolete versions accumulated", len(p.owned))
		}
		if _, ok := ownedcontent.Available(owner); ok {
			t.Fatal("obsolete version remained materialized")
		}
	}
	for owner := range p.owned {
		_ = owner.Retire()
	}
}
