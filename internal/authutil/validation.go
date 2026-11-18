// Package authutil contains shared SDK authentication grammar checks, not trust policy.
package authutil

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

var bearerPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)
var scopePattern = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$`)

// ValidBearer checks the bearer/token68 character grammar, including padding.
func ValidBearer(token string) bool { return bearerPattern.MatchString(token) }

// ValidScope checks one RFC 6749 scope token, not a space-separated list.
func ValidScope(scope string) bool { return ValidScopeList(scope) && !strings.Contains(scope, " ") }

// ValidScopeList checks a nonempty RFC 6749 scope list.
func ValidScopeList(scopes string) bool { return scopePattern.MatchString(scopes) }

// ValidURL preserves exact identifiers and allows HTTP only at literal local hosts
// when explicitly enabled. Calling code must separately enforce host trust policy.
func ValidURL(raw string, allowLocalHTTP bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.Contains(raw, "#") {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return allowLocalHTTP && u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback()))
}

// NormalizeEndpoint returns a comparison key for an endpoint URL: scheme and
// host are lowercased, a default port is dropped and an empty path becomes
// "/". Path and query are compared exactly. An unparsable URL is returned as is.
func NormalizeEndpoint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	key := scheme + "://" + host + path
	if u.RawQuery != "" || u.ForceQuery {
		key += "?" + u.RawQuery
	}
	return key
}

// KnownCode reports whether code is one of the nine safe auth error codes.
func KnownCode(code string) bool {
	switch code {
	case "invalid_configuration", "unsupported_binding", "credential_unavailable",
		"interaction_required", "access_denied", "refresh_rejected", "discovery_failed",
		"untrusted_destination", "provider_failed":
		return true
	}
	return false
}
