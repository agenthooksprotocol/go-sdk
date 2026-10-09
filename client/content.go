package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/agenthooksprotocol/go-sdk/internal/ownedcontent"
	"io"
	"math"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/auth"
	"strings"
	"time"
	"unicode/utf8"
)

// projectContent prepares a receiver-specific view. A returned error suppresses
// publication; no partially prepared event escapes this function. It deliberately
// does not normalize application data or infer authorization from event fields.
func (c *Hooks) projectContent(ctx context.Context, event map[string]any, subscription map[string]any, backendID string) (map[string]any, error) {
	selection, _ := subscription["content"].(map[string]any)
	mode, _ := selection["default"].(string)
	if !contentMode(mode) {
		return nil, errors.New("content selection requires a valid default")
	}
	for _, value := range selection {
		v, ok := value.(string)
		if !ok || !contentMode(v) {
			return nil, errors.New("invalid content selection")
		}
	}
	scope := ContentAuthorization{BackendID: backendID, Subscription: contentClone(subscription).(map[string]any)}
	scope.SubscriptionID, _ = subscription["id"].(string)
	var project func(any, string) (any, error)
	project = func(value any, path string) (any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		switch v := value.(type) {
		case map[string]any:
			_, id := v["id"].(string)
			_, kind := v["kind"].(string)
			_, media := v["mediaType"].(string)
			if contentItemPath(path) {
				if !id || !kind || !media {
					return nil, errors.New("malformed normalized content item")
				}
				item := v
				sources, _ := ctx.Value(contentSourcesContextKey{}).(map[string]*ContentSource)
				if prepared, ok := ctx.Value(preparedContextKey{}).(*preparedBoundary); ok {
					sources = prepared.sources
				}
				if sources != nil {
					if source := sources[path]; source != nil {
						item = contentClone(v).(map[string]any)
						item["body"] = source
					}
				}
				var verify func([]byte) error
				if item != nil && (path == "/elicitation/request" || path == "/elicitation/result") {
					if p, ok := ctx.Value(preparedContextKey{}).(*preparedBoundary); ok {
						verify = func(raw []byte) error { _, err := p.sourceElicitation(event, path, raw); return err }
					}
				}
				return c.projectContentItem(ctx, item, selection, subscription, scope, verify)
			}
			out := make(map[string]any, len(v))
			for key, child := range v {
				childPath := path + "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
				if event["type"] == "file.changed" && fileChangeReferencePath(childPath) {
					// Bare file references are not normalized items on the wire. Prepare them
					// through a private descriptor, emitting only an authorized confirmed body.
					item := map[string]any{"id": childPath, "kind": "file", "category": "files", "mediaType": "application/octet-stream", "synthesized": true, "body": child}
					if p, ok := ctx.Value(preparedContextKey{}).(*preparedBoundary); ok && p.sources[childPath] != nil {
						item["body"] = p.sources[childPath]
					}
					prepared, err := c.projectContentItem(ctx, item, selection, subscription, scope)
					if err != nil {
						return nil, err
					}
					if body, ok := prepared["body"]; ok {
						out[key] = body
					}
					continue
				}
				if key == "native" || key == "input" || key == "output" {
					if key == "native" && subscription["includeNative"] != true {
						continue
					}
					if c.opts.Content.ProjectOpaque == nil {
						continue
					}
					safe, err := c.opts.Content.ProjectOpaque(ctx, scope, childPath, contentClone(child))
					if err != nil {
						return nil, err
					}
					out[key] = contentClone(safe)
					continue
				}
				safe, err := project(child, childPath)
				if err != nil {
					return nil, err
				}
				out[key] = safe
			}
			return out, nil
		case []any:
			out := make([]any, len(v))
			for i, child := range v {
				safe, err := project(child, fmt.Sprintf("%s/%d", path, i))
				if err != nil {
					return nil, err
				}
				out[i] = safe
			}
			return out, nil
		case []map[string]any:
			out := make([]any, len(v))
			for i, child := range v {
				safe, err := project(child, fmt.Sprintf("%s/%d", path, i))
				if err != nil {
					return nil, err
				}
				out[i] = safe
			}
			return out, nil
		default:
			return contentClone(value), nil
		}
	}
	projected, err := project(event, "")
	if err != nil {
		return nil, err
	}
	return projected.(map[string]any), nil
}

// Content positions, not descriptor-shaped arbitrary application objects, decide
// which values are normalized items. Application normalization remains host-owned.
func contentItemPath(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	switch len(parts) {
	case 1:
		return parts[0] == "instructions" || parts[0] == "summary" || parts[0] == "partialOutput" || parts[0] == "delta"
	case 2:
		return parts[0] == "items" || (parts[0] == "elicitation" && (parts[1] == "request" || parts[1] == "result"))
	case 3:
		return (parts[0] == "attention" && (parts[1] == "title" || parts[1] == "message")) || (parts[0] == "message" && (parts[1] == "text" || parts[1] == "payload")) || (parts[0] == "fileChanges" && (parts[2] == "before" || parts[2] == "after"))
	}
	return false
}

func contentMode(s string) bool { return s == "body" || s == "metadata" || s == "omit" }
func contentCategory(item map[string]any) string {
	if item["kind"] == "reasoning" {
		return "reasoning"
	}
	if category, ok := item["category"].(string); ok && category != "" {
		return category
	}
	media, _ := item["mediaType"].(string)
	media = strings.TrimSpace(strings.SplitN(strings.ToLower(media), ";", 2)[0])
	switch {
	case strings.HasPrefix(media, "text/") || media == "application/json":
		return "text"
	case strings.HasPrefix(media, "image/"):
		return "images"
	case strings.HasPrefix(media, "audio/"):
		return "audio"
	case strings.HasPrefix(media, "video/"):
		return "video"
	default:
		return "files"
	}
}

func (c *Hooks) projectContentItem(ctx context.Context, item, selection, subscription map[string]any, scope ContentAuthorization, validators ...func([]byte) error) (map[string]any, error) {
	out := map[string]any{}
	// Only canonical descriptor fields survive. Payload permission flags, inline
	// aliases and arbitrary duplicate bytes are never forwarded as metadata.
	for _, key := range []string{"id", "kind", "mediaType", "role", "parentItemId", "category", "size", "sha256", "synthesized"} {
		if v, ok := item[key]; ok {
			out[key] = contentClone(v)
		}
	}
	mode := selection["default"].(string)
	if s, ok := selection[contentCategory(item)].(string); ok {
		mode = s
	}
	out["selection"] = mode
	if mode != "body" {
		return out, nil
	}
	scope.Item = contentClone(out).(map[string]any)
	authorized := false
	if c.opts.Content.AuthorizeContent != nil {
		var err error
		authorized, err = c.opts.Content.AuthorizeContent(ctx, scope)
		if err != nil {
			return nil, err
		}
	}
	if !authorized {
		out["gap"] = map[string]any{"reason": "withheld"}
		return out, nil
	}
	body, exists := item["body"]
	if !exists || body == nil {
		if gap, present := item["gap"]; present {
			out["gap"] = contentClone(gap)
		} else {
			out["gap"] = map[string]any{"reason": "unavailable"}
		}
		return out, nil
	}
	upload, ok := subscription["upload"].(map[string]any)
	if !ok {
		return nil, errors.New("selected content requires upload configuration")
	}
	limit := c.opts.MaxContentBytes
	if limit == 0 {
		limit = 4 << 20
	}
	if limit < 0 {
		return nil, errors.New("invalid content limit")
	}
	uploadLimit, ok := contentInt(upload["maxBytes"])
	if !ok || uploadLimit < 0 {
		return nil, errors.New("invalid upload byte limit")
	}
	if uploadLimit < limit {
		limit = uploadLimit
	}
	// LimitReader uses limit+1; keep the overflow case bounded as well.
	if limit == math.MaxInt64 {
		limit--
	}
	var raw []byte
	switch source := body.(type) {
	case *ContentSource:
		var err error
		timeout, valid := contentInt(upload["timeoutMs"])
		if !valid || timeout < 1 || timeout > math.MaxInt64/int64(time.Millisecond) {
			return nil, errors.New("invalid upload timeout")
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
		defer cancel()
		total := c.opts.MaxContentBytes
		if total == 0 {
			total = 4 << 20
		}
		if total == math.MaxInt64 {
			total--
		}
		if budget, ok := ctx.Value(contentSourceBudgetKey{}).(*contentSourceBudget); ok {
			raw, err = budget.snapshot(ctx, source, total, total)
		} else {
			raw, err = ownedcontent.Borrow(source, ctx, total)
		}
		if err != nil {
			return nil, err
		}
		// Destination-specific limits do not poison the immutable occurrence
		// snapshot for independently authorized receivers with larger limits.
		if int64(len(raw)) > limit {
			return nil, errors.New("content exceeds upload byte limit")
		}
	case []byte:
		if int64(len(source)) > limit {
			return nil, errors.New("content exceeds byte limit")
		}
		raw = bytes.Clone(source)
	case string:
		if int64(len(source)) > limit {
			return nil, errors.New("content exceeds byte limit")
		}
		raw = []byte(source)
	case map[string]any:
		ref, ok := source["ref"].(string)
		if !ok || ref == "" || len(source) != 1 || item["size"] != nil || item["sha256"] != nil {
			return nil, errors.New("invalid host content reference")
		}
		resolver := c.opts.Content.Resolver
		if resolver == nil {
			out["gap"] = map[string]any{"reason": "unavailable"}
			return out, nil
		}
		stream, err := resolver(ctx, ref)
		if err != nil {
			return nil, err
		}
		if stream == nil {
			return nil, errors.New("content resolver returned no reader")
		}
		raw, err = readOwnedContent(ctx, stream, limit)
		if err != nil {
			return nil, err
		}
		if int64(len(raw)) > limit {
			return nil, errors.New("content exceeds byte limit")
		}
	default:
		return nil, errors.New("content body must be raw bytes, text, or a host reference")
	}
	if err := contentMatches(item, raw); err != nil {
		return nil, err
	}
	for _, validate := range validators {
		if validate != nil {
			if err := validate(raw); err != nil {
				return nil, err
			}
		}
	}
	descriptor, err := c.uploadContent(ctx, upload, raw, scope.BackendID)
	if err != nil {
		return nil, err
	}
	out["body"] = map[string]any{"ref": descriptor.Ref}
	delete(out, "size")
	delete(out, "sha256")
	return out, nil
}

func contentMatches(metadata map[string]any, raw []byte) error {
	if size, present := metadata["size"]; present {
		n, ok := contentInt(size)
		if !ok || n != int64(len(raw)) {
			return errors.New("content size mismatch")
		}
	}
	if hash, present := metadata["sha256"]; present {
		s, ok := hash.(string)
		if !ok || s != fmt.Sprintf("%x", sha256.Sum256(raw)) {
			return errors.New("content SHA-256 mismatch")
		}
	}
	return nil
}

func (c *Hooks) uploadContent(ctx context.Context, config map[string]any, raw []byte, backendIDs ...string) (*ahp.ContentUploadReceipt, error) {
	endpoint, ok := config["endpoint"].(string)
	if !ok || strings.ContainsAny(endpoint, "\r\n") {
		return nil, errors.New("invalid upload endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid upload endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	loopback := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback && c.opts.Content.AllowLoopbackHTTP) {
		return nil, errors.New("upload requires HTTPS")
	}
	timeout, ok := contentInt(config["timeoutMs"])
	if !ok || timeout < 1 || timeout > math.MaxInt64/int64(time.Millisecond) {
		return nil, errors.New("invalid upload timeout")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
	defer cancel()
	// Do not copy the event client, its cookies, credentials or TLS configuration.
	client := http.Client{}
	if c.opts.UploadClient != nil {
		client = *c.opts.UploadClient
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("invalid upload request")
	}
	request.ContentLength = int64(len(raw))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("AHP-Content-SHA256", fmt.Sprintf("%x", sha256.Sum256(raw)))
	var binding json.RawMessage
	if value, present := config["auth"]; present {
		binding = sdkJSON(value)
	}
	backendID := ""
	if len(backendIDs) > 0 {
		backendID = backendIDs[0]
	}
	response, err := auth.Do(&client, request, auth.Request{Binding: binding, BackendID: backendID, Destination: endpoint, Purpose: auth.Upload}, c.opts.AuthProvider, false)
	if err != nil {
		return nil, errors.New("content upload failed")
	}
	defer response.Body.Close()
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusCreated || err != nil || media != "application/json" {
		return nil, errors.New("invalid content upload confirmation")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(encoded) > 64<<10 || !utf8.Valid(encoded) {
		return nil, errors.New("invalid content upload descriptor")
	}
	// Parse tokens to reject duplicate keys as well as unknown descriptor fields.
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid content upload descriptor")
	}
	descriptor := map[string]any{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, errors.New("invalid content upload descriptor")
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("invalid content upload descriptor")
		}
		if _, exists := descriptor[key]; exists {
			return nil, errors.New("duplicate upload descriptor field")
		}
		var value any
		if decoder.Decode(&value) != nil {
			return nil, errors.New("invalid content upload descriptor")
		}
		descriptor[key] = value
	}
	if _, err = decoder.Token(); err != nil {
		return nil, errors.New("invalid content upload descriptor")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("invalid content upload descriptor")
	}
	ref, ok := descriptor["ref"].(string)
	if !ok || ref == "" || len(descriptor) != 3 {
		return nil, errors.New("invalid content upload descriptor")
	}
	if err = contentMatches(descriptor, raw); err != nil {
		return nil, err
	}
	if _, ok := descriptor["size"]; !ok {
		return nil, errors.New("missing upload size")
	}
	if _, ok := descriptor["sha256"]; !ok {
		return nil, errors.New("missing upload hash")
	}
	return &ahp.ContentUploadReceipt{Ref: ref, Size: descriptor["size"].(json.Number), Sha256: descriptor["sha256"].(string)}, nil
}

func contentInt(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v < math.MinInt64 || v >= float64(math.MaxInt64) || math.Trunc(v) != v {
			return 0, false
		}
		return int64(v), true
	case json.Number:
		n, ok := new(big.Rat).SetString(string(v))
		if !ok || !n.IsInt() || !n.Num().IsInt64() {
			return 0, false
		}
		return n.Num().Int64(), true
	default:
		return 0, false
	}
}
func contentClone(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			out[key] = contentClone(child)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = contentClone(child)
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(v))
		for i, child := range v {
			out[i] = contentClone(child).(map[string]any)
		}
		return out
	case []byte:
		return bytes.Clone(v)
	default:
		return value
	}
}

// fileChangeReferencePath identifies legacy bare wire references, not content items.
func fileChangeReferencePath(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	return len(parts) == 3 && parts[0] == "changes" && (parts[2] == "before" || parts[2] == "after")
}
