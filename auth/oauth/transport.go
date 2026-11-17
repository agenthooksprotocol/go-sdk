package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

// tokenTransport keeps oauth2's maintained token parsing, PKCE and grant logic
// while adding RFC 8707 to EVERY grant, including its generic refresh request.
// It accepts only the resolved token endpoint. The underlying host transport
// must enforce DNS/connect policy and must not follow redirects internally.
type tokenTransport struct {
	provider           *Provider
	endpoint, resource string
	base               http.RoundTripper
}

func (p *Provider) tokenClient(_ context.Context, c ClientConfig, m metadata) *http.Client {
	client := p.client
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = &tokenTransport{p, m.TokenEndpoint, c.Resource, base}
	return &client
}
func (t *tokenTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	ctx := request.Context()
	if request.Method != http.MethodPost || request.URL.String() != t.endpoint || request.Body == nil {
		return nil, fail(auth.CodeUntrustedDestination)
	}
	if err := t.provider.check(ctx, t.endpoint, TokenEndpoint); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, discoveryLimit+1))
	request.Body.Close()
	if err != nil || len(body) > discoveryLimit {
		return nil, fail(auth.CodeProviderFailed)
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fail(auth.CodeProviderFailed)
	}
	if resources, ok := form["resource"]; ok && (len(resources) != 1 || resources[0] != t.resource) {
		return nil, fail(auth.CodeUntrustedDestination)
	}
	form.Set("resource", t.resource)
	encoded := form.Encode()
	copy := request.Clone(ctx)
	copy.Header = request.Header.Clone()
	copy.Body = io.NopCloser(strings.NewReader(encoded))
	copy.ContentLength = int64(len(encoded))
	copy.Header.Set("Content-Length", strconv.Itoa(len(encoded)))
	copy.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(encoded)), nil }
	// oauth2 owns this response and applies its bounded token decoder. Never
	// return underlying network error text, which may contain credentials/URLs.
	response, err := t.base.RoundTrip(copy)
	if err != nil {
		if ctx.Err() == nil && unsent(err) {
			return nil, errEndpoint
		}
		return nil, safe(ctx, err, auth.CodeProviderFailed)
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		response.Body.Close()
		return nil, fail(auth.CodeUntrustedDestination)
	}
	if response.StatusCode == http.StatusOK {
		return sanitizeExpiry(response)
	}
	return response, nil
}

// invalidExpiry replaces a malformed expires_in, which x/oauth2 would reject
// before the SDK could persist a rotated refresh token. grant still refuses
// the response as provider_failed.
const invalidExpiry = "ahp_invalid_expires_in"

// sanitizeExpiry buffers a JSON token response and swaps a malformed
// expires_in (anything but a positive integer or ASCII digit string) for the
// invalidExpiry marker, so the rest of the response still decodes.
func sanitizeExpiry(response *http.Response) (*http.Response, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, discoveryLimit+1))
	response.Body.Close()
	if err != nil || len(body) > discoveryLimit {
		return nil, fail(auth.CodeProviderFailed)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) == nil {
		if raw, ok := fields["expires_in"]; ok && !positiveExpiry(raw) {
			delete(fields, "expires_in")
			fields[invalidExpiry] = json.RawMessage("true")
			body, _ = json.Marshal(fields)
		}
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Del("Content-Length")
	return response, nil
}

func positiveExpiry(raw json.RawMessage) bool {
	var digits string
	if json.Unmarshal(raw, &digits) != nil {
		digits = string(raw)
	}
	return digits != "" && strings.Trim(digits, "0123456789") == "" && strings.Trim(digits, "0") != "" && len(digits) <= 18
}
