package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
)

// HeaderRequest scopes a harness-owned secret lookup to one backend event or upload destination.
// ValueRef is opaque and must not be included in diagnostics.
type HeaderRequest struct {
	BackendID   string
	Destination string
	Purpose     auth.Operation
	ValueRef    string
}

// HeaderResolver resolves valueRef sources. Implementations must honor ctx and
// must not log returned values or references. Environment sources use os.LookupEnv.
type HeaderResolver func(ctx context.Context, request HeaderRequest) (string, error)

var errHeaderConfig = errors.New("invalid HTTP registration headers")
var errHeaderResolution = errors.New("HTTP registration header resolution failed")
var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
var headerEnv = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type headerSource struct{ literal, env, ref string }

// Go's HTTP field values allow HTAB, visible ASCII, and obs-text bytes.
func validHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if (s[i] < 32 && s[i] != '\t') || s[i] == 127 {
			return false
		}
	}
	return true
}

func registrationHeaders(cfg *ahp.HttpTransport) (map[string]headerSource, error) {
	// Project through JSON so both retained extension fields and generated schema
	// fields use exactly the same registration path.
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return nil, errHeaderConfig
	}
	var transport map[string]json.RawMessage
	if json.Unmarshal(encoded, &transport) != nil {
		return nil, errHeaderConfig
	}
	raw, present := transport["headers"]
	if !present {
		return nil, nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errHeaderConfig
	}
	result := make(map[string]headerSource)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, errHeaderConfig
		}
		name, ok := token.(string)
		key := strings.ToLower(name)
		if !ok || !headerName.MatchString(name) {
			return nil, errHeaderConfig
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return nil, errHeaderConfig
		}
		var source headerSource
		if len(raw) > 0 && raw[0] == '"' {
			if json.Unmarshal(raw, &source.literal) != nil || !validHeaderValue(source.literal) {
				return nil, errHeaderConfig
			}
		} else {
			// Exactly one recognized source; unknown extensions do not select a source.
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil || fields == nil {
				return nil, errHeaderConfig
			}
			env, hasEnv := fields["valueEnv"]
			ref, hasRef := fields["valueRef"]
			if hasEnv == hasRef {
				return nil, errHeaderConfig
			}
			if hasEnv && (json.Unmarshal(env, &source.env) != nil || !headerEnv.MatchString(source.env)) {
				return nil, errHeaderConfig
			}
			if hasRef && (json.Unmarshal(ref, &source.ref) != nil || source.ref == "") {
				return nil, errHeaderConfig
			}
		}
		result[key] = source
	}
	if _, err := d.Token(); err != nil {
		return nil, errHeaderConfig
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errHeaderConfig
	}
	return result, nil
}

func (t *httpBackend) resolveHeaders(ctx context.Context) (http.Header, error) {
	return resolveHeaders(ctx, t.headers, t.headerResolver, HeaderRequest{BackendID: t.backendID, Destination: t.url, Purpose: auth.Event})
}

func resolveHeaders(ctx context.Context, sources map[string]headerSource, resolver HeaderResolver, scope HeaderRequest) (http.Header, error) {
	headers := make(http.Header, len(sources))
	for name, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value := source.literal
		if source.env != "" || source.ref != "" {
			var lookup auth.SecretResolver
			if resolver != nil {
				lookup = func(ctx context.Context, ref string) (string, error) {
					request := scope
					request.ValueRef = ref
					return resolver(ctx, request)
				}
			}
			var err error
			value, err = auth.ResolveSecret(ctx, source.env, source.ref, lookup)
			if err != nil {
				return nil, errHeaderResolution
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !validHeaderValue(value) {
			return nil, errHeaderResolution
		}
		headers.Set(name, value)
	}
	return headers, nil
}
