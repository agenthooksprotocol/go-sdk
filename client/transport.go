package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"time"
)

// maxTransportMessage is an implementation limit, not a protocol limit.
const maxTransportMessage = 4 << 20

type backendTransport interface {
	Exchange(context.Context, []byte, bool) ([]byte, error)
	Close() error
}

// EventTransportResolver supplies an explicitly authenticated HTTP client for a
// backend's registered authentication binding. It runs for each delivery, within
// that delivery's context and serialized backend exchange. It must honor context
// cancellation. Returning a client affirms that its transport implements and
// validates the configured binding, including credential acquisition and refresh.
// The backend is a detached snapshot that the resolver may retain or modify.
// Errors are redacted and never cause fallback to unauthenticated delivery.
// The returned client is cloned, redirects are disabled, and its transport is not
// closed by the SDK. Resolvers apply only to authenticated HTTP backends.
type EventTransportResolver func(context.Context, *ahp.Backend) (*http.Client, error)

func newBackendTransport(backend *ahp.Backend, eventClient *http.Client, resolvers ...EventTransportResolver) (backendTransport, error) {
	if len(resolvers) > 1 {
		return nil, errors.New("at most one event transport resolver is permitted")
	}
	var resolver EventTransportResolver
	if len(resolvers) == 1 {
		resolver = resolvers[0]
	}
	if backend == nil {
		return nil, errors.New("nil backend")
	}
	var credential *backendCredential
	if backend.Authentication.Present {
		credential = &backendCredential{}
		encoded, err := json.Marshal(backend.Authentication.Value)
		if err != nil || json.Unmarshal(encoded, credential) != nil {
			credential = &backendCredential{}
		}
	}
	t := backend.Transport
	if t.HttpTransport.Present == t.StdioTransport.Present {
		return nil, errors.New("exactly one backend transport is required")
	}
	if t.HttpTransport.Present {
		cfg := t.HttpTransport.Value
		if cfg == nil || cfg.Type != ahp.HttpTransportTypeHTTP {
			return nil, errors.New("invalid HTTP transport")
		}
		u, err := url.Parse(cfg.URL)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, errors.New("invalid backend URL")
		}
		if u.Scheme == "http" && u.Hostname() != "localhost" {
			ip := net.ParseIP(u.Hostname())
			if ip == nil || !ip.IsLoopback() {
				return nil, errors.New("HTTP requires a loopback endpoint")
			}
		}
		c := http.Client{}
		if eventClient != nil {
			c = *eventClient
		}
		// Registration has no redirect opt-in; never forward payloads to another URL.
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		var snapshot []byte
		if credential != nil && resolver != nil {
			snapshot, err = json.Marshal(backend)
			if err != nil {
				return nil, errors.New("invalid backend configuration")
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		return &httpBackend{url: cfg.URL, client: &c, ctx: ctx, cancel: cancel, gate: make(chan struct{}, 1), credential: credential, resolver: resolver, snapshot: snapshot}, nil
	}
	cfg := t.StdioTransport.Value
	if cfg == nil || cfg.Type != ahp.StdioTransportTypeStdio || cfg.Command == "" || (cfg.Lifecycle != ahp.StdioTransportLifecyclePersistent && cfg.Lifecycle != ahp.StdioTransportLifecyclePerEvent) {
		return nil, errors.New("invalid stdio transport")
	}
	copied := *cfg
	copied.Args.Value = append([]string(nil), cfg.Args.Value...)
	ctx, cancel := context.WithCancel(context.Background())
	return &stdioBackend{credential: credential, cfg: copied, gate: make(chan struct{}, 1), ctx: ctx, cancel: cancel, processes: make(map[*backendProcess]struct{})}, nil
}

// Credential lookup is deferred until Exchange so interception failure policy applies.
// No automatic OAuth acquisition, secret-reference lookup or TLS reconfiguration occurs.
type backendCredential struct {
	Type     string `json:"type"`
	TokenEnv string `json:"tokenEnv"`
	TokenRef string `json:"tokenRef"`
}

var bearerTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)

func (c *backendCredential) resolve(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if c == nil {
		return "", nil
	}
	if c.Type != "bearer" || c.TokenEnv == "" || c.TokenRef != "" {
		return "", errors.New("configured authentication binding is unsupported")
	}
	token := os.Getenv(c.TokenEnv)
	if token == "" || !bearerTokenPattern.MatchString(token) {
		return "", errors.New("backend credential unavailable or invalid")
	}
	return token, nil
}

type httpBackend struct {
	resolver   EventTransportResolver
	snapshot   []byte
	gate       chan struct{}
	credential *backendCredential
	url        string
	client     *http.Client
	ctx        context.Context
	cancel     context.CancelFunc
}

func (t *httpBackend) Close() error { t.cancel(); t.gate <- struct{}{}; <-t.gate; return nil }
func (t *httpBackend) Exchange(ctx context.Context, body []byte, notification bool) ([]byte, error) {
	select {
	case t.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.ctx.Done():
		return nil, errors.New("transport closed")
	}
	defer func() { <-t.gate }()
	if len(body) > maxTransportMessage {
		return nil, errors.New("request exceeds transport limit")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(t.ctx, cancel)
	defer stop()
	if t.ctx.Err() != nil {
		return nil, errors.New("transport closed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid HTTP request")
	}
	client := t.client
	if t.credential != nil && t.resolver != nil {
		var backend ahp.Backend
		if err := json.Unmarshal(t.snapshot, &backend); err != nil {
			return nil, errors.New("invalid backend authentication configuration")
		}
		resolved, err := t.resolver(ctx, &backend)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil || resolved == nil {
			return nil, errors.New("backend authentication resolution failed")
		}
		copied := *resolved
		copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &copied
	} else {
		token, err := t.credential.resolve(ctx)
		if err != nil {
			return nil, err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("backend HTTP exchange failed")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTransportMessage+1))
	if err != nil {
		return nil, errors.New("backend HTTP body read failed")
	}
	if len(data) > maxTransportMessage {
		return nil, errors.New("response exceeds transport limit")
	}
	if notification {
		if (resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent) || len(data) != 0 {
			return nil, errors.New("invalid HTTP notification acknowledgement")
		}
		return nil, nil
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || err != nil || media != "application/json" {
		return nil, errors.New("invalid backend HTTP response")
	}
	return data, nil
}

type backendProcess struct {
	cmd    *exec.Cmd
	stdin  *os.File
	stdout *os.File
	reader *bufio.Reader
	done   chan struct{}
	err    error // published by closing done
	once   sync.Once
}

func (p *backendProcess) stop() {
	p.once.Do(func() { killBackendProcess(p.cmd); p.stdin.Close(); p.stdout.Close() })
	<-p.done
}

type stdioBackend struct {
	credential *backendCredential
	cfg        ahp.StdioTransport
	gate       chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	processes  map[*backendProcess]struct{}
	current    *backendProcess // guarded by gate
	workers    sync.WaitGroup
}

func (t *stdioBackend) start() (*backendProcess, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ctx.Err() != nil {
		return nil, errors.New("transport closed")
	}
	if len(t.processes) >= 64 {
		return nil, errors.New("backend process concurrency limit reached")
	}
	cmd := exec.Command(t.cfg.Command, t.cfg.Args.Value...)
	if t.cfg.CWD.Present {
		cmd.Dir = t.cfg.CWD.Value
	}
	// The schema has no env override. Inherit the host environment.
	cmd.Stderr = nil // discard diagnostics without leaking credentials or blocking
	configureBackendProcess(cmd)
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		return nil, errors.New("backend pipe creation failed")
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		inRead.Close()
		inWrite.Close()
		return nil, errors.New("backend pipe creation failed")
	}
	cmd.Stdin, cmd.Stdout = inRead, outWrite
	err = cmd.Start()
	inRead.Close()
	outWrite.Close()
	if err != nil {
		inWrite.Close()
		outRead.Close()
		return nil, errors.New("backend process start failed")
	}
	p := &backendProcess{cmd: cmd, stdin: inWrite, stdout: outRead, reader: bufio.NewReader(outRead), done: make(chan struct{})}
	t.processes[p] = struct{}{}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	return p, nil
}
func (t *stdioBackend) remove(p *backendProcess) {
	p.stop()
	t.mu.Lock()
	delete(t.processes, p)
	t.mu.Unlock()
}
func (t *stdioBackend) Close() error {
	t.mu.Lock()
	t.cancel()
	ps := make([]*backendProcess, 0, len(t.processes))
	for p := range t.processes {
		ps = append(ps, p)
	}
	t.mu.Unlock()
	for _, p := range ps {
		t.remove(p)
	}
	// Drain the outstanding exchange's I/O worker.
	t.gate <- struct{}{}
	<-t.gate
	t.workers.Wait()
	return nil
}
func (t *stdioBackend) Exchange(ctx context.Context, body []byte, notification bool) ([]byte, error) {
	if len(body) > maxTransportMessage {
		return nil, errors.New("request exceeds transport limit")
	}
	if bytes.ContainsAny(body, "\r\n") || !json.Valid(body) {
		return nil, errors.New("invalid stdio message framing")
	}
	select {
	case t.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.ctx.Done():
		return nil, errors.New("transport closed")
	}
	defer func() { <-t.gate }()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if t.ctx.Err() != nil {
		return nil, errors.New("transport closed")
	}
	if t.credential != nil {
		return nil, errors.New("configured authentication has no supported stdio binding")
	}
	p := t.current
	if p == nil {
		var err error
		p, err = t.start()
		if err != nil {
			return nil, err
		}
		t.current = p
	}
	perEvent := t.cfg.Lifecycle == ahp.StdioTransportLifecyclePerEvent
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		_, err := p.stdin.Write(append(append([]byte(nil), body...), '\n'))
		if perEvent {
			p.stdin.Close()
		}
		if err != nil {
			done <- result{err: errors.New("backend write failed")}
			return
		}
		if notification {
			done <- result{}
			return
		}
		var data []byte
		for {
			fragment, e := p.reader.ReadSlice('\n')
			if len(data)+len(fragment) > maxTransportMessage+1 {
				done <- result{err: errors.New("response exceeds transport limit")}
				return
			}
			data = append(data, fragment...)
			if e == bufio.ErrBufferFull {
				continue
			}
			if e != nil {
				done <- result{err: errors.New("backend response framing failed")}
				return
			}
			break
		}
		data = bytes.TrimSuffix(data, []byte{'\n'})
		var request, response struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(body, &request) != nil || json.Unmarshal(data, &response) != nil || len(request.ID) == 0 || !bytes.Equal(bytes.TrimSpace(request.ID), bytes.TrimSpace(response.ID)) {
			done <- result{err: errors.New("backend response correlation failed")}
			return
		}
		if perEvent {
			<-p.done
			if p.err != nil {
				done <- result{err: errors.New("backend process failed")}
				return
			}
		}
		done <- result{data: data}
	}()
	var r result
	select {
	case r = <-done:
	case <-ctx.Done():
		p.stop()
		<-done
		r.err = ctx.Err()
	case <-t.ctx.Done():
		p.stop()
		<-done
		r.err = errors.New("transport closed")
	}
	if r.err != nil || (perEvent && !notification) {
		t.remove(p)
		t.current = nil
	}
	if perEvent && notification && r.err == nil {
		t.current = nil
		t.workers.Add(1)
		go func() {
			defer t.workers.Done()
			timer := time.NewTimer(30 * time.Second)
			defer timer.Stop()
			select {
			case <-p.done:
			case <-t.ctx.Done():
			case <-timer.C:
			}
			t.remove(p)
		}()
	}
	return r.data, r.err
}
