package server

// This package deliberately supplies no listener, registry, storage service, or
// authentication middleware. Mount NewHandler on an application's HTTP mux and
// configure TLS, authorization, deadlines and admission with ordinary net/http
// facilities. Discovery is the hooks/capabilities POST method, not a GET route.
//
// Request and callback-result validation combines root ahp codecs with the
// generator-produced offline internal/canonical bundle. Contextual checks enforce
// request/event correlation, advertised effects/operations, object merge rules
// and continuation allowance. For unresolved descriptor-backed targets, merge
// checks cover the patch object, not inaccessible body bytes; complete resolved-
// base and elicitation-answer acceptance belongs to the host client. No callback
// output applies host policy, proves an
// operation executed, or validates arbitrary application input against a host
// schema. Applications also resolve referenced content within authorized storage
// scope; this stateless handler cannot verify bytes it has not been given.
//
// Notifications never receive RPC replies. Observation callback errors produce
// an empty HTTP failure; callback panics and ordinary interception errors expose
// only fixed, redacted protocol errors. Applications can wrap their callbacks to
// record safe diagnostics; the SDK does not log payloads or error text.
//
// ServeStdio is a sequential HTTP-handler adapter, not another protocol engine.
// It owns explicit streams, imposes finite frame ceilings, honors write
// backpressure, and requires Close to unblock concurrent I/O. Cancellation cannot
// forcibly stop uncooperative callback code. Synthetic requests carry no verified
// identity, so HTTP authentication middleware must not assume a remote peer.
//
// ParseUpload owns a body only on success. Copy into staging storage, check the
// read and close results, and require Verified before publishing an immutable
// reference in the independently authorized upload scope. Commit that storage
// before WriteUploadResponse. Descriptor construction is not a storage commit.
