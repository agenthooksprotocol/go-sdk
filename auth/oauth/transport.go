package oauth

import (
	"context"
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
	return response, nil
}
