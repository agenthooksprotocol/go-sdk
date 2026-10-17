package auth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type headerCapture func(*http.Request) (*http.Response, error)

func (f headerCapture) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type forbiddenProvider struct{ t *testing.T }

func (p forbiddenProvider) Credential(context.Context, Request) (Credential, error) {
	p.t.Error("unexpected credential callback")
	return Credential{}, nil
}
func (p forbiddenProvider) Challenge(context.Context, Request, Challenge) (*Credential, error) {
	p.t.Error("unexpected challenge callback")
	return nil, nil
}

func TestConfiguredHeadersOverrideDefaultsAndSuppressAuth(t *testing.T) {
	for _, authorization := range []string{"Bearer abc123", ""} {
		req, _ := http.NewRequest(http.MethodPost, "http://localhost/events", strings.NewReader("body"))
		req.Header["content-type"] = []string{"application/default"}
		req.Header["AUTHORIZATION"] = []string{"Bearer old"}
		req.Header["x-key"] = []string{"default"}
		calls := 0
		client := &http.Client{Transport: headerCapture(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Header.Get("Authorization") != authorization || len(r.Header.Values("Authorization")) != 1 || r.Header.Get("Content-Type") != "text/custom" || r.Header.Get("X-Key") != "configured" {
				t.Error("configured headers did not win")
			}
			for _, key := range []string{"AUTHORIZATION", "content-type", "x-key"} {
				if _, ok := r.Header[key]; ok {
					t.Error("uncanonicalized default survived")
				}
			}
			return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		})}
		response, err := DoWithHeaders(client, req, Request{Destination: req.URL.String(), Purpose: Event, Binding: []byte(`{"type":"oauth","flow":"client_credentials"}`)}, forbiddenProvider{t}, true, http.Header{"aUtHoRiZaTiOn": {authorization}, "Content-Type": {"text/custom"}, "X-Key": {"configured"}})
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if calls != 1 {
			t.Error("explicit authorization retried")
		}
	}
}
