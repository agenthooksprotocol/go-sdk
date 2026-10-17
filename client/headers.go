package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
)

// HeaderRequest scopes a harness-owned secret lookup to one event destination.
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

// maxRegistrationHeaders bounds aggregate configured names and resolved values.
const maxRegistrationHeaders = 64 << 10

type headerSource struct{ literal, env, ref string }

func printableHeader(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}

func reservedHeader(name string) bool {
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "proxy-") || strings.HasPrefix(name, "sec-") || strings.HasPrefix(name, "ahp-") {
		return true
	}
	switch name {
	case "authorization", "cookie", "set-cookie", "host", "content-type", "accept", "content-length", "content-encoding", "connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "expect", "origin", "referer":
		return true
	}
	return false
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
	total := 0
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, errHeaderConfig
		}
		name, ok := token.(string)
		key := strings.ToLower(name)
		if !ok || !headerName.MatchString(name) || reservedHeader(name) {
			return nil, errHeaderConfig
		}
		if _, exists := result[key]; exists {
			return nil, errHeaderConfig
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return nil, errHeaderConfig
		}
		var source headerSource
		if len(raw) > 0 && raw[0] == '"' {
			if json.Unmarshal(raw, &source.literal) != nil || !printableHeader(source.literal) {
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
		total += len(name) + len(source.literal) + len(source.env) + len(source.ref) + 4
		if total > maxRegistrationHeaders {
			return nil, errHeaderConfig
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
	headers := make(http.Header, len(t.headers))
	total := 0
	for name, source := range t.headers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value := source.literal
		if source.env != "" {
			var ok bool
			value, ok = os.LookupEnv(source.env)
			if !ok || value == "" {
				return nil, errHeaderResolution
			}
		} else if source.ref != "" {
			if t.headerResolver == nil {
				return nil, errHeaderResolution
			}
			var err error
			value, err = t.headerResolver(ctx, HeaderRequest{BackendID: t.backendID, Destination: t.url, Purpose: auth.Event, ValueRef: source.ref})
			if err != nil || value == "" {
				return nil, errHeaderResolution
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !printableHeader(value) {
			return nil, errHeaderResolution
		}
		total += len(name) + len(value) + 4
		if total > maxRegistrationHeaders {
			return nil, errHeaderResolution
		}
		headers.Set(name, value)
	}
	return headers, nil
}
