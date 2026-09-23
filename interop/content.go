package interop

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// UploadBinding is independent of event authentication and transport.
type UploadBinding struct {
	Endpoint  string      `json:"endpoint"`
	TimeoutMs int         `json:"timeoutMs"`
	MaxBytes  *int64      `json:"maxBytes"`
	Auth      *UploadAuth `json:"auth,omitempty"`
}
type UploadAuth struct {
	Type     string `json:"type"`
	TokenEnv string `json:"tokenEnv"`
}

func uploadToken(a *UploadAuth) (string, error) {
	if a == nil {
		return "", nil
	}
	if a.Type != "bearer" || a.TokenEnv == "" {
		return "", fmt.Errorf("invalid upload authentication")
	}
	token := os.Getenv(a.TokenEnv)
	if token == "" {
		return "", fmt.Errorf("missing upload credential")
	}
	if strings.ContainsAny(token, "\r\n") {
		return "", fmt.Errorf("invalid upload credential")
	}
	return token, nil
}

// UploadContent sends arbitrary octets to the exact configured endpoint. The
// returned reference is usable only after validating synchronous 201 confirmation.
// The two string arguments are local fixture labels only; neither is sent on the wire.
func UploadContent(ctx context.Context, binding UploadBinding, _, _ string, body []byte) (Object, int, error) {
	if binding.MaxBytes != nil && int64(len(body)) > *binding.MaxBytes {
		return nil, 0, fmt.Errorf("upload exceeds configured maxBytes")
	}
	if binding.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(binding.TimeoutMs)*time.Millisecond)
		defer cancel()
	}
	u, e := url.Parse(binding.Endpoint)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, 0, fmt.Errorf("invalid upload endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return nil, 0, fmt.Errorf("upload requires HTTPS outside loopback")
	}
	token, e := uploadToken(binding.Auth)
	if e != nil {
		return nil, 0, e
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(body))
	r, e := http.NewRequestWithContext(ctx, "POST", binding.Endpoint, bytes.NewReader(body))
	if e != nil {
		return nil, 0, e
	}
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("AHP-Content-SHA256", sum)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	res, e := lifecycleHTTP.Do(r)
	if e != nil {
		return nil, 0, e
	}
	defer res.Body.Close()
	return confirmUpload(res, body)
}

// confirmUpload rejects a success status without an exact canonical descriptor.
func confirmUpload(res *http.Response, body []byte) (Object, int, error) {
	fail := func() (Object, int, error) {
		return nil, res.StatusCode, fmt.Errorf("invalid upload confirmation (HTTP %d)", res.StatusCode)
	}
	media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if res.StatusCode != http.StatusCreated || err != nil || media != "application/json" {
		return fail()
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 || !utf8.Valid(raw) {
		return fail()
	}
	var descriptor Object
	if json.Unmarshal(raw, &descriptor) != nil || len(descriptor) != 3 {
		return fail()
	}
	ref, ok := descriptor["ref"].(string)
	if !ok || ref == "" || descriptor["size"] != float64(len(body)) || descriptor["sha256"] != fmt.Sprintf("%x", sha256.Sum256(body)) {
		return fail()
	}
	return descriptor, res.StatusCode, nil
}

// uploadScopes derives grants from credentials and the exact configured route,
// never from a claimed subscription, reference, or JSON-RPC correlation ID.
func (s *lifecycleReceiver) uploadScopes(r *http.Request, bindings map[string]UploadBinding) ([]string, int64, int) {
	if len(r.Header.Values("Authorization")) > 1 {
		return nil, 0, 401
	}
	matches := func(token string) bool {
		expected := ""
		if token != "" {
			expected = "Bearer " + token
		}
		return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) == 1
	}
	if s.uploadToken != "" {
		if !matches(s.uploadToken) {
			return nil, 0, 401
		}
		if !uploadRoute(r, bindings) && r.URL.RequestURI() != "/upload" {
			return nil, 0, 404
		}
		scopes := []string{}
		for scope, granted := range s.uploadSubscriptions {
			if granted {
				scopes = append(scopes, scope)
			}
		}
		if len(scopes) == 0 {
			return nil, 0, 403
		}
		sort.Strings(scopes)
		limit := int64(16 << 20)
		for _, scope := range scopes {
			if binding, ok := bindings[scope]; ok && binding.MaxBytes != nil && *binding.MaxBytes < limit {
				limit = *binding.MaxBytes
			}
		}
		return scopes, limit, 201
	}
	scopes := []string{}
	recognized, route := false, false
	limit := int64(16 << 20)
	for scope, binding := range bindings {
		token, err := uploadToken(binding.Auth)
		authenticated := err == nil && matches(token)
		recognized = recognized || authenticated
		target := "/upload"
		if binding.Endpoint != "" {
			u, err := url.Parse(binding.Endpoint)
			if err != nil {
				continue
			}
			target = u.RequestURI()
		}
		if target != r.URL.RequestURI() {
			continue
		}
		route = true
		if !authenticated {
			continue
		}
		scopes = append(scopes, scope)
		if binding.MaxBytes != nil && *binding.MaxBytes < limit {
			limit = *binding.MaxBytes
		}
	}
	if !route {
		return nil, 0, 404
	}
	if len(scopes) == 0 {
		if recognized {
			return nil, 0, 403
		}
		return nil, 0, 401
	}
	sort.Strings(scopes)
	return scopes, limit, 201
}

// upload receives raw octets and allocates a fresh immutable reference.
func (s *lifecycleReceiver) upload(w http.ResponseWriter, r *http.Request, bindings map[string]UploadBinding) {
	scopes, limit, status := s.uploadScopes(r, bindings)
	var body []byte
	ref := ""
	if status == 201 && (r.Method != "POST" || r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Content-Encoding") != "" || r.ContentLength < 0 || r.Header.Get("Content-Length") != strconv.FormatInt(r.ContentLength, 10) || len(r.TransferEncoding) > 0 || len(r.Header.Values("AHP-Content-SHA256")) != 1) {
		status = 400
	}
	if status == 201 && r.ContentLength > limit {
		status = 413
	}
	if status == 201 {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, limit+1))
		if err != nil || int64(len(body)) != r.ContentLength || fmt.Sprintf("%x", sha256.Sum256(body)) != r.Header.Get("AHP-Content-SHA256") {
			status = 400
		}
	}
	if status == 201 {
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			status = 500
		} else {
			ref = fmt.Sprintf("content-%x", random[:])
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if status == 201 {
		for _, scope := range scopes {
			s.uploads[contentKey(scope, ref)] = string(body)
		}
	}
	scope := ""
	if len(scopes) > 0 {
		scope = scopes[0]
	}
	s.record(Object{"kind": "upload", "subscription": scope, "ref": ref, "status": status, "size": float64(r.ContentLength), "sha256": r.Header.Get("AHP-Content-SHA256")})
	if status == 201 {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	if status == 201 {
		_ = json.NewEncoder(w).Encode(Object{"ref": ref, "size": len(body), "sha256": fmt.Sprintf("%x", sha256.Sum256(body))})
	}
}

func checkContent(event Object, sub string, uploads map[string]string) error {
	// References can occur in normalized items and typed file before/after fields.
	var walk func(any) error
	walk = func(v any) error {
		switch x := v.(type) {
		case map[string]any:
			if ref, ok := x["ref"].(string); ok && x["sha256"] != nil && x["size"] != nil {
				body, found := uploads[contentKey(sub, ref)]
				if !found || x["size"] != float64(len(body)) || x["sha256"] != fmt.Sprintf("%x", sha256.Sum256([]byte(body))) {
					return fmt.Errorf("unavailable scoped content reference")
				}
			}
			for _, value := range x {
				if e := walk(value); e != nil {
					return e
				}
			}
		case []any:
			for _, value := range x {
				if e := walk(value); e != nil {
					return e
				}
			}
		}
		return nil
	}
	for _, field := range []string{"items", "changes", "delta", "partialOutput", "summary", "instructions", "removed"} {
		if e := walk(event[field]); e != nil {
			return e
		}
	}
	return nil
}

func contentKey(subscription, ref string) string {
	return fmt.Sprintf("%d:%s%s", len(subscription), subscription, ref)
}

func uploadRoute(r *http.Request, bindings map[string]UploadBinding) bool {
	for _, binding := range bindings {
		if binding.Endpoint == "" && r.URL.RequestURI() == "/upload" {
			return true
		}
		if u, e := url.Parse(binding.Endpoint); e == nil && u.RequestURI() == r.URL.RequestURI() {
			return true
		}
	}
	return false
}
