package oauth

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"mime"
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
	// refresh captures a 2xx response's refresh_token, so it survives a
	// response x/oauth2 rejects before the SDK sees it.
	refresh *string
}

func (p *Provider) tokenClient(c ClientConfig, m metadata, refresh *string) *http.Client {
	client := p.client
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = &tokenTransport{p, m.TokenEndpoint, c.Resource, base, refresh}
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
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return sanitize(response, t.refresh)
	}
	return response, nil
}

// invalidExpiry replaces a malformed expires_in, which x/oauth2 would reject
// before the SDK could persist a rotated refresh token. grant still refuses
// the response as provider_failed.
const invalidExpiry = "ahp_invalid_expires_in"

// sanitize buffers a JSON (or re-encoded form) token response, captures its refresh_token and
// normalizes expires_in: a positive integer or digit string is clamped to what
// x/oauth2 accepts; any other present value, including null, becomes the
// invalidExpiry marker so the rest of the response still decodes.
func sanitize(response *http.Response, refresh *string) (*http.Response, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, discoveryLimit+1))
	response.Body.Close()
	if err != nil || len(body) > discoveryLimit {
		return nil, fail(auth.CodeProviderFailed)
	}
	var fields map[string]json.RawMessage
	// x/oauth2 also accepts form-encoded token responses, but its form token
	// reports an absent field as "" and parses numeric-looking values, so a
	// form body is re-encoded as the equivalent JSON object of strings: an
	// absent field stays absent and a present one keeps its exact text.
	media, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if form, err := url.ParseQuery(string(body)); err == nil && (media == "application/x-www-form-urlencoded" || media == "text/plain") {
		fields = make(map[string]json.RawMessage, len(form))
		for key, values := range form {
			fields[key], _ = json.Marshal(values[0])
		}
		body, _ = json.Marshal(fields)
		response.Header.Set("Content-Type", "application/json")
	}
	if json.Unmarshal(body, &fields) != nil {
		if form, err := url.ParseQuery(string(body)); err == nil && refresh != nil {
			*refresh = form.Get("refresh_token")
		}
	} else {
		if refresh != nil {
			json.Unmarshal(fields["refresh_token"], refresh)
		}
		if raw, ok := fields["expires_in"]; ok {
			if seconds, valid := positiveExpiry(raw); valid {
				fields["expires_in"] = json.RawMessage(strconv.FormatInt(seconds, 10))
			} else {
				delete(fields, "expires_in")
				fields[invalidExpiry] = json.RawMessage("true")
			}
			body, _ = json.Marshal(fields)
		}
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Del("Content-Length")
	return response, nil
}

// positiveExpiry parses a positive JSON integer or ASCII digit string,
// clamping very long lifetimes to the largest x/oauth2 represents.
func positiveExpiry(raw json.RawMessage) (int64, bool) {
	var digits string
	if json.Unmarshal(raw, &digits) != nil {
		digits = string(raw)
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return 0, false
	}
	if len(digits) > 10 {
		return math.MaxInt32, true
	}
	seconds, _ := strconv.ParseInt(digits, 10, 64)
	return min(seconds, math.MaxInt32), true
}
