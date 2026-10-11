package client

// Subscribes reports static subscription interest in a configured event.
// It includes intercept and observation deliveries, using the same selectors
// as dispatch. Payload filters are not evaluated: a matching subscription may
// return true even when a particular input would not pass its filters.
//
// This synchronous lookup does not prepare input, authenticate, upload, or
// contact backends. It is neither permission nor a guarantee of delivery.
func (h *Hooks) Subscribes(event string) bool {
	if h == nil {
		return false
	}
	for _, raw := range sdkArray(h.manifest["events"]) {
		entry := sdkObj(raw)
		if entry["event"] != event {
			continue
		}
		if !sdkHas(entry["modes"], "intercept") && !sdkHas(entry["modes"], "observe") {
			return false
		}
		for _, backend := range h.backends {
			for _, sub := range backend.subscriptions {
				// Dispatch can downgrade intercept subscriptions to observations after
				// settlement. Do not exclude such interest using the subscription mode.
				if subscriptionMatches(sub, event) {
					return true
				}
			}
		}
		return false
	}
	return false
}
