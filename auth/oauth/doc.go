// Package oauth provides optional managed PKCE and client-credentials
// authentication for AHP registration transports. It reuses golang.org/x/oauth2
// grant mechanics with protected-resource discovery and resource-bound refresh.
// Hosts supply trusted network policy, identity/token validation and coordinated
// storage, and explicitly control consent through Prepare, Complete and Cancel.
// The package starts no browser, listener, worker or default credential store.
package oauth
