package interop

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"time"
)

type exchange func(context.Context, string, []byte) ([]byte, error)

func connection(ctx context.Context, c Config) (exchange, func(), error) {
	if c.Transport == "http" {
		client, token, e := c.Auth.client(ctx)
		if e != nil {
			return nil, nil, e
		}
		return func(ctx context.Context, method string, b []byte) ([]byte, error) {
			path := "/intercept"
			verb := "POST"
			if method == "hooks/capabilities" {
				path = "/capabilities"
				verb = "GET"
			}
			base := strings.TrimSuffix(strings.TrimSuffix(c.Endpoint, "/"), "/intercept")
			r, e := http.NewRequestWithContext(ctx, verb, base+path, bytes.NewReader(b))
			if e != nil {
				return nil, fmt.Errorf("invalid endpoint")
			}
			r.Header.Set("Content-Type", "application/json")
			if token != "" {
				r.Header.Set("Authorization", "Bearer "+token)
			}
			res, e := client.Do(r)
			if e != nil {
				return nil, fmt.Errorf("HTTP exchange failed")
			}
			defer res.Body.Close()
			if res.StatusCode != 200 {
				return nil, fmt.Errorf("HTTP status %d", res.StatusCode)
			}
			out, e := io.ReadAll(io.LimitReader(res.Body, (4<<20)+1))
			if len(out) > 4<<20 {
				return nil, fmt.Errorf("response too large")
			}
			return out, e
		}, func() { client.CloseIdleConnections() }, nil
	}
	if c.Transport != "stdio" || len(c.ServerCommand) == 0 {
		return nil, nil, fmt.Errorf("missing stdio server command")
	}
	args := append(append([]string{}, c.ServerCommand[1:]...), "--config", c.ServerConfig)
	cmd := exec.CommandContext(ctx, c.ServerCommand[0], args...)
	cmd.Dir = c.ServerCwd
	setProcessGroup(cmd)
	cmd.Stderr = os.Stderr
	in, e := cmd.StdinPipe()
	if e != nil {
		return nil, nil, e
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		return nil, nil, e
	}
	if e = cmd.Start(); e != nil {
		return nil, nil, e
	}
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	cleanup := func() {
		in.Close()
		if cmd.Process != nil {
			killProcessGroup(cmd)
		}
		cmd.Wait()
	}
	return func(ctx context.Context, _ string, b []byte) ([]byte, error) {
		frame, err := ndjson(b)
		if err != nil {
			return nil, err
		}
		if _, e := in.Write(frame); e != nil {
			return nil, fmt.Errorf("stdio write failed")
		}
		type answer struct {
			b []byte
			e error
		}
		ch := make(chan answer, 1)
		go func() {
			if scanner.Scan() {
				ch <- answer{append([]byte(nil), scanner.Bytes()...), nil}
			} else {
				ch <- answer{nil, fmt.Errorf("stdio stream closed")}
			}
		}()
		select {
		case a := <-ch:
			return a.b, a.e
		case <-ctx.Done():
			killProcessGroup(cmd)
			a := <-ch
			_ = a
			return nil, fmt.Errorf("stdio timeout")
		}
	}, cleanup, nil
}

type Result struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Actual Object `json:"actual"`
	Error  string `json:"error,omitempty"`
}

func Client(ctx context.Context, c Config) error {
	ss, e := scenarios(c.ScenarioFile)
	if e != nil {
		return e
	}
	results := []Result{}
	failed := false
	finish := func() error {
		if e := writeAtomic(c.ReportFile, Object{"language": "go", "results": results}); e != nil {
			return e
		}
		if failed {
			return fmt.Errorf("applicable interop failures")
		}
		return nil
	}
	if !c.Auth.validMode() || (c.Transport == "stdio" && c.Auth.mode() != "none") {
		status := "unsupported"
		if c.Transport == "stdio" {
			status = "inapplicable"
		}
		for _, s := range ss {
			results = append(results, Result{ID: s.ID, Status: status, Actual: Object{}})
		}
		return finish()
	}
	v, e := NewValidator(c.SchemaDir)
	if e != nil {
		return e
	}
	conn, close, e := connection(ctx, c)
	if e != nil {
		for _, s := range ss {
			results = append(results, Result{ID: s.ID, Status: "failed", Actual: Object{}, Error: "connection setup failed"})
		}
		failed = true
		return finish()
	}
	defer close()
	discovery := []byte(`{"jsonrpc":"2.0","id":"capabilities","method":"hooks/capabilities","params":{"protocolVersion":"draft"}}`)
	if c.Transport == "stdio" {
		if _, err := v.Validate("capabilities-request", discovery); err != nil {
			return err
		}
	}
	call, cancel := context.WithTimeout(ctx, 20*time.Second)
	caps, discoveryErr := conn(call, "hooks/capabilities", discovery)
	cancel()
	if discoveryErr == nil {
		var envelope Object
		discoveryErr = json.Unmarshal(caps, &envelope)
		if c.Transport == "stdio" {
			if envelope["id"] != "capabilities" || envelope["jsonrpc"] != "2.0" {
				discoveryErr = fmt.Errorf("capabilities correlation failed")
			}
			if discoveryErr == nil {
				_, discoveryErr = v.Validate("capabilities-response", caps)
			}
			var advertised Object
			for _, raw := range array(obj(obj(envelope["result"])["manifest"])["events"]) {
				event := obj(raw)
				if event["event"] == "tool.before" && has(event["modes"], "intercept") {
					advertised = obj(event["capabilities"])
					break
				}
			}
			if advertised == nil {
				discoveryErr = fmt.Errorf("tool.before capability discovery missing")
			}
			envelope = advertised
		}
		caps, _ = json.Marshal(envelope)
		if discoveryErr == nil {
			_, discoveryErr = v.Validate("capabilities", caps)
		}
	}
	for _, s := range ss {
		r := Result{ID: s.ID, Status: "failed", Actual: Object{}}
		err := discoveryErr
		responseRejected := false
		if err == nil {
			req, ve := v.Validate("intercept-request", s.Request)
			err = ve
			if err == nil {
				err = checkContent(obj(obj(req["params"])["event"]), "", nil)
			}
			if err == nil {
				call, cancel := context.WithTimeout(ctx, 20*time.Second)
				delete(obj(req["params"]), "subscriptionId")
				wire, marshalErr := json.Marshal(req)
				if marshalErr != nil {
					cancel()
					return marshalErr
				}
				b, ce := conn(call, "hooks/intercept", wire)
				cancel()
				err = ce
				if err == nil {
					res, ve := v.Validate("intercept-response", b)
					err = ve
					if err == nil {
						r.Actual, err = Apply(req, res)
					}
					responseRejected = err != nil
				}
			}
		}
		if s.ExpectError && responseRejected {
			r.Status = "passed"
			r.Actual = Object{"rejected": true}
		} else if err != nil {
			r.Error = "request, response, transport or application rejected"
		} else if s.ExpectError {
			r.Error = "expected rejection"
		} else {
			r.Status = "passed"
			for key, value := range s.Expected {
				if !reflect.DeepEqual(r.Actual[key], value) {
					r.Status = "failed"
					r.Error = "expected result mismatch: " + key
					break
				}
			}
		}
		if r.Status == "failed" {
			failed = true
		}
		results = append(results, r)
	}
	return finish()
}
