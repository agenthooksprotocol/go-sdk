package interop

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Auth struct {
	Mode          string  `json:"mode"`
	Token         string  `json:"token"`
	TokenEndpoint string  `json:"tokenEndpoint"`
	ClientID      string  `json:"clientId"`
	ClientSecret  string  `json:"clientSecret"`
	Assertion     string  `json:"assertion"`
	SigningKey    string  `json:"signingKey"`
	Issuer        string  `json:"issuer"`
	Audience      string  `json:"audience"`
	Purpose       string  `json:"purpose"`
	Clock         float64 `json:"clock"`
	CAFile        string  `json:"caFile"`
	CertFile      string  `json:"certFile"`
	KeyFile       string  `json:"keyFile"`
}

func (a Auth) mode() string {
	if a.Mode == "" {
		return "none"
	}
	return a.Mode
}
func (a Auth) validMode() bool {
	switch a.mode() {
	case "none", "bearer", "oauth", "mtls", "workload":
		return true
	}
	return false
}
func (a Auth) tlsConfig(server bool) (*tls.Config, error) {
	cert, e := tls.LoadX509KeyPair(a.CertFile, a.KeyFile)
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(a.CAFile)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("invalid CA")
	}
	c := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, RootCAs: pool}
	if server {
		c.ClientCAs = pool
		c.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return c, nil
}
func (a Auth) authorize(r *http.Request) bool {
	if len(r.Header.Values("Authorization")) > 1 {
		return false
	}
	switch a.mode() {
	case "none":
		return true
	case "mtls":
		return r.TLS != nil && len(r.TLS.VerifiedChains) > 0
	case "bearer":
		return a.Token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+a.Token)) == 1
	case "oauth", "workload":
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			return false
		}
		return a.verifyJWT(strings.TrimPrefix(h, "Bearer "))
	}
	return false
}
func (a Auth) verifyJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || a.SigningKey == "" || a.Issuer == "" || a.Audience == "" || a.Purpose == "" {
		return false
	}
	dec := base64.RawURLEncoding.DecodeString
	h, e := dec(parts[0])
	if e != nil {
		return false
	}
	var header Object
	if json.Unmarshal(h, &header) != nil || (header["alg"] != "HS256" || header["typ"] != "JWT") {
		return false
	}
	signature, e := dec(parts[2])
	if e != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(a.SigningKey))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(mac.Sum(nil), signature) {
		return false
	}
	b, e := dec(parts[1])
	if e != nil {
		return false
	}
	var claims Object
	if json.Unmarshal(b, &claims) != nil {
		return false
	}
	now := a.Clock
	if now == 0 {
		now = float64(time.Now().Unix())
	}
	iat, issued := claims["iat"].(float64)
	if !issued || iat > now {
		return false
	}
	exp, ok := claims["exp"].(float64)
	if !ok || exp <= now {
		return false
	}
	if value, present := claims["nbf"]; present {
		n, ok := value.(float64)
		if !ok || n > now {
			return false
		}
	}
	return claims["iss"] == a.Issuer && (claims["aud"] == a.Audience || has(claims["aud"], a.Audience)) && claims["purpose"] == a.Purpose
}
func (a Auth) client(ctx context.Context) (*http.Client, string, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	token := ""
	switch a.mode() {
	case "none":
	case "bearer":
		token = a.Token
		if token == "" {
			return nil, "", fmt.Errorf("bearer token missing")
		}
	case "workload":
		token = a.Assertion
		if token == "" {
			return nil, "", fmt.Errorf("workload assertion missing")
		}
	case "mtls":
		c, e := a.tlsConfig(false)
		if e != nil {
			return nil, "", e
		}
		transport.TLSClientConfig = c
	case "oauth":
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {a.ClientID}, "client_secret": {a.ClientSecret}, "audience": {a.Audience}}
		req, e := http.NewRequestWithContext(ctx, "POST", a.TokenEndpoint, strings.NewReader(form.Encode()))
		if e != nil {
			return nil, "", e
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(a.ClientID, a.ClientSecret)
		res, e := client.Do(req)
		if e != nil {
			return nil, "", fmt.Errorf("token endpoint unavailable")
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, "", fmt.Errorf("token endpoint rejected request")
		}
		var body Object
		if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body) != nil {
			return nil, "", fmt.Errorf("invalid token response")
		}
		token = str(body["access_token"])
		if token == "" {
			return nil, "", fmt.Errorf("missing access token")
		}
	default:
		return nil, "", fmt.Errorf("unsupported auth mode")
	}
	return client, token, nil
}
