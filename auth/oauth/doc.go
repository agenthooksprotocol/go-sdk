// Package oauth reserves the optional managed OAuth integration boundary.
//
// Managed acquisition is deliberately not implemented: golang.org/x/oauth2
// supplies grant mechanics, but not the mandatory AHP/MCP discovery, trust,
// resource-validation, or coordinated persistence policy. See README.md for the
// security gate and executable dependency compatibility evidence. This package
// does not implement auth.Provider and starts no network or background work.
package oauth
