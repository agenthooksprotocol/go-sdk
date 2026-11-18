package authutil

import "testing"

func TestNormalizeEndpoint(t *testing.T) {
	for _, group := range [][]string{
		{"https://Hooks.Example.test/events", "HTTPS://hooks.example.test:443/events", "https://hooks.example.test:443/events"},
		{"http://127.0.0.1:80", "http://127.0.0.1/", "HTTP://127.0.0.1:80/"},
		{"http://[::1]:8080/hooks", "http://[::1]:8080/hooks"},
		{"http://[::1]/x", "http://[::1]:80/x"},
	} {
		for _, raw := range group {
			if got, want := NormalizeEndpoint(raw), NormalizeEndpoint(group[0]); got != want {
				t.Errorf("%q -> %q; want %q", raw, got, want)
			}
		}
	}
	for _, pair := range [][2]string{
		{"https://hooks.example.test/events", "https://hooks.example.test/Events"},
		{"https://hooks.example.test/events", "https://hooks.example.test:8443/events"},
		{"https://hooks.example.test/events", "http://hooks.example.test/events"},
		{"https://hooks.example.test/events", "https://hooks.example.test/events?x=1"},
	} {
		if NormalizeEndpoint(pair[0]) == NormalizeEndpoint(pair[1]) {
			t.Errorf("%q and %q compare equal", pair[0], pair[1])
		}
	}
}
