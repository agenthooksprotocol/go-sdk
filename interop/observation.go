package interop

// DispatchObservations delivers an already-settled boundary to explicit observers
// and remaining uncalled matching intercept subscriptions. prepare must apply the
// subscription's existing permissions/selections and confirm selected uploads.
// Each worker is best effort: no wait, response effects, or decision reopening.
func DispatchObservations(event Object, subscriptions []Object, called map[string]bool, prepare func(Object, Object) (Object, error), notify func(Object) error) {
	snapshot := obj(clone(event))
	for _, sub := range subscriptions {
		if sub["mode"] != "observe" && !(sub["mode"] == "intercept" && !called[str(sub["id"])]) {
			continue
		}
		subscription := obj(clone(sub))
		go func() {
			projected, err := prepare(obj(clone(snapshot)), subscription)
			if err != nil {
				return
			}
			for _, key := range []string{"id", "source", "type"} {
				if projected[key] != snapshot[key] {
					return
				}
			}
			_ = notify(Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": projected}})
		}()
	}
}
