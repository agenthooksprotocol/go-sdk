package interop

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

type lifecycleReceiver struct {
	suite               string
	mu                  sync.Mutex
	changed             chan struct{}
	entries             []any
	released            map[string]bool
	responses           map[string]Object
	sequences           map[string][]Object
	occurrences         map[string]int
	uploads             map[string]string
	validator           *lifecycleValidator
	uploadToken         string
	uploadSubscriptions map[string]bool
	lineage             TaskLineage
	eventScopes         []string
}

func (s *lifecycleReceiver) record(m Object) {
	s.entries = append(s.entries, m)
	close(s.changed)
	s.changed = make(chan struct{})
}
func (s *lifecycleReceiver) wait(ctx context.Context, predicate func() bool) error {
	for {
		s.mu.Lock()
		ok := predicate()
		ch := s.changed
		s.mu.Unlock()
		if ok {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func (s *lifecycleReceiver) dispatch(ctx context.Context, m Object) (Object, error) {
	if s.suite == "catalogue" {
		return s.catalogueDispatch(m)
	}
	if m["method"] == "hooks/observe" {
		if e := s.validator.validate("observe", m); e != nil {
			return nil, e
		}
		p := obj(m["params"])
		ev := obj(p["event"])
		sub := "" // scope comes from receiver policy after event authentication
		s.mu.Lock()
		defer s.mu.Unlock()
		if e := checkContent(ev, sub, s.eventContent()); e != nil {
			return nil, e
		}
		if e := s.lineage.Accept(ev); e != nil {
			return nil, e
		}
		gate := str(ev["id"]) + ":observers"
		_, held := s.sequences[gate]
		if held {
			s.record(Object{"kind": "observer-blocked", "id": ev["id"]})
		}
		s.record(Object{"kind": "observed", "eventId": ev["id"], "event": clone(ev), "message": clone(m)})
		if held {
			s.mu.Unlock()
			err := s.wait(ctx, func() bool { return s.released[lifecycleID(Object{"id": gate})] })
			s.mu.Lock()
			if err != nil {
				return nil, err
			}
		}
		r := lifecycleReply("unsolicited-observer")
		obj(r["result"])["effects"] = []any{Object{"type": "deny", "reason": "observer must not decide"}}
		return r, nil
	}
	if e := s.validator.validate("intercept-request", m); e != nil {
		return nil, e
	}
	id := lifecycleID(m)
	s.mu.Lock()
	if e := checkContent(obj(obj(m["params"])["event"]), "", s.eventContent()); e != nil {
		s.mu.Unlock()
		return nil, e
	}
	if e := s.lineage.Accept(obj(obj(m["params"])["event"])); e != nil {
		s.mu.Unlock()
		return nil, e
	}
	response, ok := s.responses[id]
	if ok {
		n := s.occurrences[id]
		s.occurrences[id] = n + 1
		if n < len(s.sequences[id]) {
			response = s.sequences[id][n]
		}
		s.record(Object{"kind": "received", "id": m["id"], "message": clone(m)})
	}
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown intercept")
	}
	if e := s.wait(ctx, func() bool { return s.released[id] }); e != nil {
		return nil, e
	}
	s.mu.Lock()
	s.record(Object{"kind": "replied", "id": m["id"]})
	s.mu.Unlock()
	return response, nil
}
func LifecycleServer(parent context.Context, c LifecycleConfig) error {
	if c.Suite != "" && c.Suite != "lifecycle" && c.Suite != "catalogue" {
		return fmt.Errorf("unknown suite")
	}
	if !c.Auth.validMode() {
		return fmt.Errorf("unsupported auth mode")
	}
	if c.Transport == "stdio" && c.Auth.mode() != "none" {
		return fmt.Errorf("HTTP auth is inapplicable to trusted stdio")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	v, e := newLifecycleValidator(c.SchemaDir)
	if e != nil {
		return e
	}
	fixtures, e := lifecycleFixtures(c.ScenarioFile)
	if e != nil {
		return e
	}
	s := &lifecycleReceiver{changed: make(chan struct{}), entries: []any{}, released: map[string]bool{}, responses: map[string]Object{}, sequences: map[string][]Object{}, occurrences: map[string]int{}, uploads: map[string]string{}, validator: v}
	s.suite = c.Suite
	s.uploadToken = c.UploadAuth.Token
	s.uploadSubscriptions = map[string]bool{}
	// A configured independent upload credential grants this synthetic receiver's
	// single content scope. Optional local grants can restrict that policy; an
	// explicitly empty list grants nothing. Neither grant is a wire identity.
	if c.UploadAuth.Token != "" && c.UploadAuth.Subscriptions == nil {
		c.UploadAuth.Subscriptions = []string{"upload-principal"}
	}
	for _, sub := range c.UploadAuth.Subscriptions {
		s.uploadSubscriptions[sub] = true
		s.eventScopes = append(s.eventScopes, sub)
	}
	for scope := range c.Uploads {
		s.eventScopes = append(s.eventScopes, scope)
	}
	for _, sc := range fixtures {
		if sc.Chain["holdObservers"] == true {
			s.sequences[str(sc.Requests["a"]["id"])+":observers"] = []Object{}
		}
		for k, r := range sc.Requests {
			if e = v.validate("intercept-request", r); e != nil {
				return e
			}
			response := sc.Responses[k]
			if e = v.validate("intercept-response", response); e != nil {
				return e
			}
			s.responses[lifecycleID(r)] = response
			for _, reply := range sc.ResponseSequences[k] {
				if e = v.validate("intercept-response", reply); e != nil {
					return e
				}
			}
			s.sequences[lifecycleID(r)] = sc.ResponseSequences[k]
		}
	}
	control, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	defer control.Close()
	var out sync.Mutex // shared by normal replies and control-injected frames
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if uploadRoute(r, c.Uploads) || (r.URL.Path == "/upload" && s.uploadToken != "") {
			s.upload(w, r, c.Uploads)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		m := Object{}
		if r.Method == "POST" {
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&m) != nil {
				w.WriteHeader(400)
				return
			}
		}
		status := 200
		var result any = Object{"ok": true}
		switch r.URL.Path {
		case "/health":
			result = Object{"ready": true}
		case "/receipts":
			s.mu.Lock()
			result = Object{"entries": append([]any{}, s.entries...)}
			s.mu.Unlock()
		case "/shutdown":
			defer cancel()
		case "/release":
			s.mu.Lock()
			s.released[lifecycleID(m)] = true
			close(s.changed)
			s.changed = make(chan struct{})
			s.mu.Unlock()
		case "/emit":
			response := obj(m["response"])
			if c.Transport != "stdio" {
				status = 400
				break
			}
			if e := v.validate("intercept-response", response); e != nil {
				status = 400
				break
			}
			out.Lock()
			s.mu.Lock()
			s.record(Object{"kind": "emitted", "id": response["id"]})
			s.mu.Unlock()
			// os.Stdout is unbuffered: Encode completes the write before the control reply.
			if e := json.NewEncoder(os.Stdout).Encode(response); e != nil {
				status = 500
			}
			out.Unlock()
		case "/mark":
			s.mu.Lock()
			s.record(Object{"kind": m["kind"], "id": m["id"], "scenario": m["scenario"]})
			s.mu.Unlock()
		case "/wait", "/wait-observed":
			count := 1
			if n, ok := m["count"].(float64); ok {
				count = int(n)
			}
			e := s.wait(r.Context(), func() bool {
				n := 0
				for _, raw := range s.entries {
					x := obj(raw)
					if r.URL.Path == "/wait" && x["kind"] == "received" && x["id"] == m["id"] {
						n++
					}
					if r.URL.Path == "/wait-observed" && (x["kind"] == "observed" || x["kind"] == "rejected") && x["eventId"] == m["eventId"] {
						n++
					}
				}
				return n >= count || ctx.Err() != nil
			})
			if e != nil || ctx.Err() != nil {
				status = 503
			}
		default:
			status = 404
		}
		w.WriteHeader(status)
		if status != 204 {
			_ = json.NewEncoder(w).Encode(result)
		}
	})
	cs := &http.Server{Handler: mux}
	defer cs.Close()
	go cs.Serve(control)
	endpoint := ""
	fatal := make(chan error, 1)
	if c.Transport == "http" {
		ln, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return e
		}
		defer ln.Close()
		scheme := "http"
		if c.Auth.mode() == "mtls" {
			tc, err := c.Auth.tlsConfig(true)
			if err != nil {
				return err
			}
			ln = tls.NewListener(ln, tc)
			scheme = "https"
		}
		endpoint = scheme + "://" + ln.Addr().String()
		hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !c.Auth.authorize(r) {
				w.WriteHeader(401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			var m Object
			if r.Method != "POST" || (r.URL.Path != "/intercept" && r.URL.Path != "/observe" && !(c.Suite == "catalogue" && r.URL.Path == "/capabilities")) {
				w.WriteHeader(404)
				return
			}
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&m) != nil {
				w.WriteHeader(400)
				return
			}
			reply, e := s.dispatch(ctx, m)
			if e != nil {
				status := 409
				if rejection, ok := e.(catalogueRejection); ok && rejection.kind == "schema" {
					status = 400
				}
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(Object{"error": e.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(reply)
		})}
		defer hs.Close()
		go hs.Serve(ln)
	} else if c.Transport == "stdio" {
		go func() {
			scan := bufio.NewScanner(os.Stdin)
			scan.Buffer(make([]byte, 4096), 16<<20)
			for scan.Scan() {
				var m Object
				if e := json.Unmarshal(scan.Bytes(), &m); e != nil {
					select {
					case fatal <- e:
					default:
					}
					return
				}
				go func(m Object) {
					reply, e := s.dispatch(ctx, m)
					if e != nil {
						if _, ok := e.(catalogueRejection); ok {
							return
						}
						select {
						case fatal <- e:
						default:
						}
						return
					}
					if reply == nil {
						return
					}
					out.Lock()
					e = json.NewEncoder(os.Stdout).Encode(reply)
					out.Unlock()
					if e != nil {
						select {
						case fatal <- e:
						default:
						}
					}
				}(m)
			}
			cancel()
		}()
	} else {
		return fmt.Errorf("unknown transport")
	}
	if e = writeAtomic(c.ReadinessFile, Object{"endpoint": endpoint, "controlEndpoint": "http://" + control.Addr().String(), "uploadEndpoint": "http://" + control.Addr().String() + "/upload", "pid": os.Getpid()}); e != nil {
		return e
	}
	select {
	case <-ctx.Done():
		s.mu.Lock()
		close(s.changed)
		s.changed = make(chan struct{})
		s.mu.Unlock()
		return nil
	case e := <-fatal:
		return e
	}
}

// eventContent projects explicit receiver grants for its independently
// authenticated event principal (or trusted stdio peer). IDs are not grants.
// Call while holding s.mu.
func (s *lifecycleReceiver) eventContent() map[string]string {
	content := map[string]string{}
	for _, scope := range s.eventScopes {
		prefix := contentKey(scope, "")
		for key, body := range s.uploads {
			if strings.HasPrefix(key, prefix) {
				content[contentKey("", strings.TrimPrefix(key, prefix))] = body
			}
		}
	}
	return content
}
