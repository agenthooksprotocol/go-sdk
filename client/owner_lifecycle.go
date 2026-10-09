package client

// releaseUnused retires speculative and superseded owners after the caller has
// chosen the authoritative prepared boundary. No discarded staging clone may be
// used afterward. Call only between composition decisions, not during fan-out.
// Caller-supplied sources outside the owned ledger remain caller lifecycle work.
func (p *preparedBoundary) releaseUnused(budget *contentSourceBudget) {
	if p == nil {
		return
	}
	live := make(map[*ContentSource]bool, len(p.sources))
	for _, source := range p.sources {
		live[source] = true
	}
	for source := range p.owned {
		if live[source] {
			continue
		}
		// Forget before retirement so accounting can inspect materialized size.
		if budget != nil {
			budget.forget(source)
		}
		_ = source.Retire()
		delete(p.owned, source)
	}
}
