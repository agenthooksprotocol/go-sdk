package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/agenthooksprotocol/go-sdk/auth"
	"github.com/agenthooksprotocol/go-sdk/internal/authutil"
)

type metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	GrantTypes            []string `json:"grant_types_supported"`
	ChallengeMethods      []string `json:"code_challenge_methods_supported"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	ResponseIssuer        bool     `json:"authorization_response_iss_parameter_supported"`
}

type protectedResource struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	BearerMethods        []string `json:"bearer_methods_supported"`
}

const discoveryLimit = 1 << 20

var errDiscovery = errors.New("oauth discovery failed")

func (p *Provider) resolve(ctx context.Context, request auth.Request, challenge string) (ClientConfig, metadata, error) {
	target, err := auth.NormalizeTarget(request)
	if err != nil {
		return ClientConfig{}, metadata{}, err
	}
	if target.Kind() == auth.BindingBearer || !discoveryHTTPS(request.Destination) {
		return ClientConfig{}, metadata{}, fail(auth.CodeUnsupportedBinding)
	}
	preset, explicit := target.OAuth()
	var resource protectedResource
	if explicit {
		// An explicit OAuth preset already selects resource and issuer. Never
		// let a challenge replace that identity with an advertised one.
		resource = protectedResource{Resource: preset.Resource, AuthorizationServers: []string{preset.Issuer}}
	} else {
		hint, err := resourceMetadataHint(challenge)
		if err != nil {
			return ClientConfig{}, metadata{}, fail(auth.CodeDiscoveryFailed)
		}
		candidates := []string{hint}
		if hint == "" {
			candidates = discoveryLocations(request.Destination, "oauth-protected-resource", false)
		}
		found := false
		for index, location := range candidates {
			var candidate protectedResource
			ok, err := fetchDiscovery(ctx, &p.client, func(ctx context.Context, raw string) error { return p.check(ctx, raw, Metadata) }, location, &candidate)
			if err != nil {
				return ClientConfig{}, metadata{}, safe(ctx, err, auth.CodeDiscoveryFailed)
			}
			if !ok {
				continue
			}
			expected := request.Destination
			if hint == "" && index > 0 {
				endpoint, _ := url.Parse(request.Destination)
				expected = endpoint.Scheme + "://" + endpoint.Host
			}
			// RFC 9728 section 3.3 requires IDENTICAL source identifiers,
			// independently of coverage and the host's trust decision.
			if candidate.Resource != expected {
				return ClientConfig{}, metadata{}, fail(auth.CodeDiscoveryFailed)
			}
			resource = candidate
			found = true
			break
		}
		if !found {
			return ClientConfig{}, metadata{}, fail(auth.CodeDiscoveryFailed)
		}
	}
	if !resourceCovers(resource.Resource, request.Destination) || len(resource.AuthorizationServers) == 0 {
		return ClientConfig{}, metadata{}, fail(auth.CodeDiscoveryFailed)
	}
	if resource.BearerMethods != nil && !contains(resource.BearerMethods, "header") {
		return ClientConfig{}, metadata{}, fail(auth.CodeUnsupportedBinding)
	}
	for _, issuer := range resource.AuthorizationServers {
		if !discoveryIssuer(issuer) {
			return ClientConfig{}, metadata{}, fail(auth.CodeDiscoveryFailed)
		}
	}
	issuers := append([]string(nil), resource.AuthorizationServers...)
	if explicit {
		issuers = []string{preset.Issuer}
	}
	config, err := p.options.SelectClient(ctx, cloneRequest(request), append([]string(nil), issuers...), resource.Resource)
	if err != nil {
		return ClientConfig{}, metadata{}, safe(ctx, err, auth.CodeUntrustedDestination)
	}
	config = cloneConfig(config)
	if !validConfig(config) || config.Resource != resource.Resource || !contains(issuers, config.Issuer) {
		return ClientConfig{}, metadata{}, fail(auth.CodeInvalidConfiguration)
	}
	if explicit && (config.Issuer != preset.Issuer || config.ClientID != preset.ClientID || config.Flow != preset.Flow || !sameScopes(config.Scopes, preset.Scopes)) {
		return ClientConfig{}, metadata{}, fail(auth.CodeInvalidConfiguration)
	}
	required, err := bearerParameter(challenge, "scope")
	if err != nil {
		return ClientConfig{}, metadata{}, fail(auth.CodeDiscoveryFailed)
	}
	if required != "" && !authutil.ValidScopeList(required) {
		return ClientConfig{}, metadata{}, fail(auth.CodeAccessDenied)
	}
	for _, scope := range strings.Fields(required) {
		if !contains(allowedScopes(config), scope) {
			return ClientConfig{}, metadata{}, fail(auth.CodeAccessDenied)
		}
	}
	config.RequiredScopes = sortedUnique(append(config.RequiredScopes, strings.Fields(required)...))
	return p.resolveMetadata(ctx, config)
}

// resolveMetadata refreshes issuer capabilities without revisiting trusted PRM.
func (p *Provider) resolveMetadata(ctx context.Context, config ClientConfig) (ClientConfig, metadata, error) {
	policy := func(ctx context.Context, raw string) error { return p.check(ctx, raw, Metadata) }
	locations := discoveryLocations(config.Issuer, "oauth-authorization-server", false)[:1]
	locations = appendUniqueDiscovery(locations, discoveryLocations(config.Issuer, "openid-configuration", false)[0])
	locations = appendUniqueDiscovery(locations, discoveryLocations(config.Issuer, "openid-configuration", true)[0])
	for _, location := range locations {
		var m metadata
		ok, err := fetchDiscovery(ctx, &p.client, policy, location, &m)
		if err != nil {
			return ClientConfig{}, metadata{}, fail(auth.CodeDiscoveryFailed)
		}
		if !ok {
			continue
		}
		if m.Issuer != config.Issuer || !discoveryHTTPS(m.TokenEndpoint) {
			return ClientConfig{}, metadata{}, fail(auth.CodeDiscoveryFailed)
		}
		if config.Flow == "authorization_code_pkce" && (!discoveryHTTPS(m.AuthorizationEndpoint) || !contains(m.ChallengeMethods, "S256")) {
			return ClientConfig{}, metadata{}, fail(auth.CodeUnsupportedBinding)
		}
		// Client credentials must be explicitly advertised for unattended use.
		if config.Flow == "client_credentials" && !contains(m.GrantTypes, "client_credentials") {
			return ClientConfig{}, metadata{}, fail(auth.CodeUnsupportedBinding)
		}
		methods := m.TokenAuthMethods
		if methods == nil {
			methods = []string{"client_secret_basic"}
		}
		method := config.TokenAuthMethod
		if method == "" {
			if config.ClientSecret == "" {
				method = "none"
			} else if contains(methods, "client_secret_post") {
				method = "client_secret_post"
			} else {
				method = "client_secret_basic"
			}
		}
		if !contains(methods, method) || (method != "none" && method != "client_secret_post" && method != "client_secret_basic") || (method == "none" && config.ClientSecret != "") || (method != "none" && config.ClientSecret == "") {
			return ClientConfig{}, metadata{}, fail(auth.CodeUnsupportedBinding)
		}
		config.TokenAuthMethod = method
		if err := p.check(ctx, m.TokenEndpoint, TokenEndpoint); err != nil {
			return ClientConfig{}, metadata{}, err
		}
		if m.AuthorizationEndpoint != "" {
			if err := p.check(ctx, m.AuthorizationEndpoint, Authorization); err != nil {
				return ClientConfig{}, metadata{}, err
			}
		}
		return config, m, nil
	}
	return ClientConfig{}, metadata{}, fail(auth.CodeDiscoveryFailed)
}

func resourceCovers(resource, endpoint string) bool {
	if !discoveryHTTPS(resource) || !discoveryHTTPS(endpoint) {
		return false
	}
	base, _ := url.Parse(resource)
	target, _ := url.Parse(endpoint)
	if base.Scheme != target.Scheme || base.Host != target.Host {
		return false
	}
	if base.RawQuery != "" || base.ForceQuery {
		return resource == endpoint
	}
	path := strings.TrimSuffix(base.EscapedPath(), "/")
	return target.EscapedPath() == path || strings.HasPrefix(target.EscapedPath(), path+"/")
}

func discoveryHTTPS(raw string) bool { return authutil.ValidURL(raw, false) }

func discoveryIssuer(raw string) bool {
	if !discoveryHTTPS(raw) {
		return false
	}
	u, _ := url.Parse(raw)
	return u.RawQuery == "" && !u.ForceQuery
}

func appendUniqueDiscovery(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

// Preserve the source identifier, including escaped paths and query, for RFC 9728.
func discoveryLocations(raw, name string, appendPath bool) []string {
	u, _ := url.Parse(raw)
	base := u.Scheme + "://" + u.Host
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}
	// RFC 8414 AS lookup removes a terminating issuer slash; RFC 9728
	// protected-resource lookup preserves the resource source identifier.
	if name != "oauth-protected-resource" {
		path = strings.TrimRight(path, "/")
	}
	query := ""
	if u.RawQuery != "" || u.ForceQuery {
		query = "?" + u.RawQuery
	}
	first := base + "/.well-known/" + name + path + query
	if appendPath {
		first = base + strings.TrimSuffix(path, "/") + "/.well-known/" + name + query
	}
	return appendUniqueDiscovery([]string{first}, base+"/.well-known/"+name)
}

// Missing documents permit the next standardized location. Redirects, policy
// rejection, and invalid documents fail closed rather than masking errors.
func fetchDiscovery(ctx context.Context, client *http.Client, policy func(context.Context, string) error, location string, result any) (bool, error) {
	if ctx.Err() != nil || !discoveryHTTPS(location) {
		return false, errDiscovery
	}
	if err := policy(ctx, location); err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return false, errDiscovery
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, errDiscovery
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, errDiscovery
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, discoveryLimit+1))
	if err != nil || len(body) > discoveryLimit || json.Unmarshal(body, result) != nil {
		return false, errDiscovery
	}
	return true, nil
}

// Parse auth-params rather than splitting on commas: quoted realms may contain
// commas, escaped quotes, or text resembling another authentication scheme.
func resourceMetadataHint(header string) (string, error) {
	return bearerParameter(header, "resource_metadata")
}
func bearerParameter(header, parameter string) (string, error) {
	challenges, ok := authutil.ParseWWWAuthenticate(header)
	if !ok {
		return "", errDiscovery
	}
	value, seen := "", false
	for _, challenge := range challenges {
		if !strings.EqualFold(challenge.Scheme, "Bearer") {
			continue
		}
		candidate, present := challenge.Params[parameter]
		if !present {
			continue
		}
		if seen || (parameter == "resource_metadata" && !discoveryHTTPS(candidate)) || (parameter == "scope" && candidate == "") {
			return "", errDiscovery
		}
		value, seen = candidate, true
	}
	return value, nil
}
