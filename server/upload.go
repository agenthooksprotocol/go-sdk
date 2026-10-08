package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

var ErrUploadFraming = errors.New("server: invalid upload framing")
var ErrUploadSize = errors.New("server: upload size mismatch or limit exceeded")
var ErrUploadDigest = errors.New("server: upload digest mismatch")
var ErrUploadUnverified = errors.New("server: upload is not verified")

// Upload is a single-reader stream with immutable declared metadata. It owns the
// request body only after ParseUpload succeeds. Verification requires successful
// EOF, not just reading the declared number of bytes. It is not concurrency-safe.
type Upload struct {
	body     io.ReadCloser
	size     int64
	digest   string
	count    int64
	hash     hash.Hash
	verified bool
	closed   bool
	terminal error
}

// ParseUpload validates raw-octet framing without consuming the body. maxBytes
// must be nonnegative; zero permits only empty uploads. Authentication and
// credential-derived authorization scope must be checked by the application.
func ParseUpload(r *http.Request, maxBytes int64) (*Upload, error) {
	if r == nil || r.Body == nil || r.Method != http.MethodPost || maxBytes < 0 {
		return nil, ErrUploadFraming
	}
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/octet-stream" || len(params) != 0 || len(r.Header.Values("Content-Type")) != 1 || len(r.TransferEncoding) != 0 || r.Header.Get("Transfer-Encoding") != "" || len(r.Header.Values("Content-Encoding")) != 0 {
		return nil, ErrUploadFraming
	}
	if r.ContentLength < 0 {
		return nil, ErrUploadFraming
	}
	// Incoming net/http requests retain Content-Length. Require an explicit
	// declaration even for empty bodies, and agreement with parsed framing.
	lengths := r.Header.Values("Content-Length")
	if len(lengths) != 1 {
		return nil, ErrUploadFraming
	}
	if len(lengths) == 1 {
		n, e := strconv.ParseInt(lengths[0], 10, 64)
		if e != nil || n != r.ContentLength || strings.Trim(lengths[0], "0123456789") != "" {
			return nil, ErrUploadFraming
		}
	}
	if r.ContentLength > maxBytes || r.ContentLength == int64(^uint64(0)>>1) {
		return nil, ErrUploadSize
	}
	hashes := r.Header.Values("AHP-Content-SHA256")
	if len(hashes) != 1 || len(hashes[0]) != 64 || strings.Trim(hashes[0], "0123456789abcdef") != "" {
		return nil, ErrUploadFraming
	}
	return &Upload{body: r.Body, size: r.ContentLength, digest: hashes[0], hash: sha256.New()}, nil
}
func (u *Upload) Read(p []byte) (int, error) {
	if u.closed {
		return 0, io.ErrClosedPipe
	}
	if u.terminal != nil {
		return 0, u.terminal
	}
	if len(p) == 0 {
		return 0, nil
	}
	// Probe at most one byte past the declared size, including empty bodies.
	remaining := u.size - u.count + 1
	if int64(len(p)) > remaining {
		p = p[:int(remaining)]
	}
	n, err := u.body.Read(p)
	if n > 0 {
		u.count += int64(n)
		_, _ = u.hash.Write(p[:n])
	}
	if u.count > u.size {
		u.terminal = ErrUploadSize
		return n, u.terminal
	}
	if err == io.EOF {
		if u.count != u.size {
			u.terminal = ErrUploadSize
		} else if hex.EncodeToString(u.hash.Sum(nil)) != u.digest {
			u.terminal = ErrUploadDigest
		} else {
			u.verified = true
			u.terminal = io.EOF
		}
		return n, u.terminal
	}
	if err != nil {
		u.terminal = err
	}
	return n, err
}
func (u *Upload) Close() error {
	if u.closed {
		return nil
	}
	u.closed = true
	err := u.body.Close()
	if err != nil {
		u.verified = false
	}
	return err
}
func (u *Upload) Verified() bool { return u.verified }

// Receipt returns a detached upload confirmation only after EOF verification. It does
// not publish bytes or prove storage availability. Allocate an immutable ref in
// the authenticated scope and commit staging storage before responding.
func (u *Upload) Receipt(ref string) (ahp.ContentUploadReceipt, error) {
	if !u.verified {
		return ahp.ContentUploadReceipt{}, ErrUploadUnverified
	}
	result := ahp.ContentUploadReceipt{Ref: ref, Size: json.Number(strconv.FormatInt(u.size, 10)), Sha256: u.digest}
	b, err := ahp.EncodeContentUploadReceipt(result)
	if err != nil || !canonical("content-upload-receipt", b) {
		return ahp.ContentUploadReceipt{}, ErrUploadFraming
	}
	return result, nil
}

// WriteUploadResponse validates a receipt and writes the canonical 201
// confirmation. The application must first atomically publish verified bytes.
func WriteUploadResponse(w http.ResponseWriter, ref ahp.ContentUploadReceipt) error {
	b, err := ahp.EncodeContentUploadReceipt(ref)
	if err != nil || !ahp.ParseContentUploadReceipt(b).OK || !canonical("content-upload-receipt", b) {
		return ErrUploadFraming
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(b)
	return err
}
