package interop

// Adversarial fixture framing is not the production upload API. Negative size
// fixtures must reach the actual receiver; a local transport error is not proof.
import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func uploadFixture(ctx context.Context, binding UploadBinding, sub, ref string, body []byte, step Object) (Object, int, error) {
	sum := fmt.Sprintf("%x", sha256.Sum256(body))
	size, ok := step["size"].(float64)
	if !ok {
		size = float64(len(body))
	}
	hash, ok := step["sha256"].(string)
	if !ok {
		hash = sum
	}
	if size == float64(len(body)) && hash == sum {
		return UploadContent(ctx, binding, sub, ref, body)
	}
	timeout := 5 * time.Second
	if binding.TimeoutMs > 0 {
		timeout = time.Duration(binding.TimeoutMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u, e := url.Parse(binding.Endpoint)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, 0, fmt.Errorf("invalid upload fixture endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return nil, 0, fmt.Errorf("unsafe upload fixture endpoint")
	}
	token, e := uploadToken(binding.Auth)
	if e != nil {
		return nil, 0, e
	}
	if strings.ContainsAny(token+hash, "\r\n") {
		return nil, 0, fmt.Errorf("invalid fixture header")
	}
	addr := u.Host
	if u.Port() == "" {
		port := "443"
		if u.Scheme == "http" {
			port = "80"
		}
		addr = net.JoinHostPort(u.Hostname(), port)
	}
	dial := net.Dialer{}
	conn, e := dial.DialContext(ctx, "tcp", addr)
	if e != nil {
		return nil, 0, e
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if u.Scheme == "https" {
		secure := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		if e = secure.HandshakeContext(ctx); e != nil {
			return nil, 0, e
		}
		conn = secure
	}
	header := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: %.0f\r\nAHP-Content-SHA256: %s\r\n", u.RequestURI(), u.Host, size, hash)
	if token != "" {
		header += "Authorization: Bearer " + token + "\r\n"
	}
	if _, e = conn.Write(append([]byte(header+"\r\n"), body...)); e != nil {
		return nil, 0, e
	}
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		if e = closer.CloseWrite(); e != nil {
			return nil, 0, e
		}
	}
	res, e := http.ReadResponse(bufio.NewReader(conn), nil)
	if e != nil {
		return nil, 0, e
	}
	defer res.Body.Close()
	return confirmUpload(res, body)
}
