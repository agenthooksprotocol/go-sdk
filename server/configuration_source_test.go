package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

const configurationRequest = `{"jsonrpc":"2.0","id":"config-1","method":"hooks/configuration","params":{"protocolVersion":"draft"}}`

type configurationTenantKey struct{}
type customConfigurationSource struct{ configuration *ahp.Configuration }

func (s *customConfigurationSource) ResolveConfiguration(context.Context) (*ahp.Configuration, error) {
	return s.configuration, nil
}

func TestDynamicConfigurationRequestContext(t *testing.T) {
	calls := 0
	handler, err := NewHandler(Handlers{Configuration: ahp.ConfigurationFunc(func(ctx context.Context) (*ahp.Configuration, error) {
		calls++
		tenant, ok := ctx.Value(configurationTenantKey{}).(string)
		if !ok {
			t.Fatal("middleware context lost")
		}
		raw := strings.ReplaceAll(`{"subscriptions":[{"events":["tool.before"],"mode":"intercept","timeoutMs":750,"failurePolicy":"fail-open","content":{"default":"metadata"}}]}`, "tool.before", tenant)
		var configuration ahp.Configuration
		if err := json.Unmarshal([]byte(raw), &configuration); err != nil {
			return nil, err
		}
		return &configuration, nil
	})}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("dynamic source invoked at setup")
	}
	// Authentication is application middleware; unauthenticated traffic never reaches SDK dispatch.
	middleware := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := r.Header.Get("X-Test-Tenant")
		if tenant == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), configurationTenantKey{}, tenant)))
	})
	for _, tenant := range []string{"tool.before", "tool.after"} {
		req := httptest.NewRequest("POST", "/hooks", strings.NewReader(configurationRequest))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-Tenant", tenant)
		recorder := httptest.NewRecorder()
		middleware.ServeHTTP(recorder, req)
		if !canonical("configuration-response", recorder.Body.Bytes()) || !strings.Contains(recorder.Body.String(), tenant) {
			t.Fatal(recorder.Body.String())
		}
	}
	if calls != 2 {
		t.Fatal("source was cached across requests")
	}
	request(middleware, []byte(configurationRequest))
	if calls != 2 {
		t.Fatal("unauthenticated request invoked source")
	}
}

func TestDynamicConfigurationValidationBeforeCallback(t *testing.T) {
	calls := 0
	handler, err := NewHandler(Handlers{Configuration: ahp.ConfigurationFunc(func(context.Context) (*ahp.Configuration, error) { calls++; return configurationFixture(t), nil })}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{`, `{"jsonrpc":"2.0","id":1,"method":"hooks/configuration","params":{}}`, `{"jsonrpc":"2.0","id":1,"method":"hooks/configuration","params":{"protocolVersion":"old"}}`, `{"jsonrpc":"2.0","method":"hooks/configuration","params":{"protocolVersion":"draft"}}`, `{"jsonrpc":"2.0","id":1,"method":"unknown","params":{}}`} {
		request(handler, []byte(body))
	}
	if calls != 0 {
		t.Fatal("malformed discovery invoked source")
	}
}

func TestDynamicConfigurationFailuresAreSanitized(t *testing.T) {
	for _, mode := range []string{"error", "nil", "invalid", "panic"} {
		t.Run(mode, func(t *testing.T) {
			diagnostics := 0
			handler, err := NewHandler(Handlers{Configuration: ahp.ConfigurationFunc(func(context.Context) (*ahp.Configuration, error) {
				switch mode {
				case "error":
					return nil, errors.New("private-secret")
				case "nil":
					return nil, nil
				case "invalid":
					return &ahp.Configuration{}, nil
				default:
					panic("private-secret")
				}
			})}, Options{Diagnostic: func(_ context.Context, err error) {
				diagnostics++
				if err != ErrConfigurationUnavailable || strings.Contains(err.Error(), "private-secret") {
					t.Fatal("diagnostic leaked callback failure")
				}
			}})
			if err != nil {
				t.Fatal(err)
			}
			reply := request(handler, []byte(configurationRequest))
			if !strings.Contains(reply.Body.String(), "-32004") || strings.Contains(reply.Body.String(), "private-secret") || diagnostics != 1 {
				t.Fatalf("unsanitized failure: %s diagnostics=%d", reply.Body.String(), diagnostics)
			}
		})
	}
}

func TestConfigurationSourceTypedNilIsAbsent(t *testing.T) {
	var static *ahp.Configuration
	var function ahp.ConfigurationFunc
	var custom *customConfigurationSource
	for _, source := range []ahp.ConfigurationSource{nil, static, function, custom} {
		handler, err := NewHandler(Handlers{Configuration: source}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		reply := request(handler, []byte(configurationRequest))
		if !strings.Contains(reply.Body.String(), "-32601") {
			t.Fatal(reply.Body.String())
		}
	}
}

func TestDynamicConfigurationCancellation(t *testing.T) {
	entered := make(chan struct{})
	handler, err := NewHandler(Handlers{Configuration: ahp.ConfigurationFunc(func(ctx context.Context) (*ahp.Configuration, error) {
		close(entered)
		<-ctx.Done()
		return configurationFixture(t), nil
	})}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest("POST", "/hooks", strings.NewReader(configurationRequest)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { handler.ServeHTTP(recorder, req); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("source not invoked")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation not propagated")
	}
	if !strings.Contains(recorder.Body.String(), "-32004") {
		t.Fatal("cancelled result was served")
	}
}

func TestDynamicConfigurationSnapshotAndCustomSource(t *testing.T) {
	configuration := configurationFixture(t)
	resolve, err := prepareConfiguration(&customConfigurationSource{configuration: configuration})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	*configuration = ahp.Configuration{}
	if !canonical("configuration", snapshot) {
		t.Fatal("source result was not detached")
	}
}

func TestDynamicConfigurationStdio(t *testing.T) {
	calls := 0
	handler, err := NewHandler(Handlers{Configuration: ahp.ConfigurationFunc(func(ctx context.Context) (*ahp.Configuration, error) {
		calls++
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		return configurationFixture(t), nil
	})}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	output := new(writeClose)
	input := &readClose{Reader: strings.NewReader(configurationRequest + "\n" + configurationRequest + "\n")}
	if err := ServeStdio(context.Background(), input, output, handler); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("stdio callbacks: %d", calls)
	}
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if !canonical("configuration-response", []byte(line)) {
			t.Fatal(line)
		}
	}
}
