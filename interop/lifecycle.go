package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type LifecycleConfig struct {
	Config
	Suite      string        `json:"suite"`
	Upload     UploadBinding `json:"upload"`
	UploadAuth struct {
		Token         string   `json:"token"`
		Subscriptions []string `json:"subscriptions"`
	} `json:"uploadAuth"`
	Uploads           map[string]UploadBinding     `json:"uploads"`
	ContentSelections map[string]map[string]string `json:"contentSelections"`
	ControlEndpoint   string                       `json:"controlEndpoint"`
	ChildPidFile      string                       `json:"childPidFile"`
}
type lifecycleScenario struct {
	Chain             Object              `json:"chain"`
	ID                string              `json:"id"`
	Requests          map[string]Object   `json:"requests"`
	Responses         map[string]Object   `json:"responses"`
	ResponseSequences map[string][]Object `json:"responseSequences"`
	Steps             []Object            `json:"steps"`
}

func lifecycleFixtures(path string) ([]lifecycleScenario, error) {
	var f struct {
		Scenarios []lifecycleScenario `json:"scenarios"`
	}
	e := Load(path, &f)
	return f.Scenarios, e
}

type lifecycleValidator struct {
	core          *Validator
	observe, item *jsonschema.Schema
}

func newLifecycleValidator(dir string) (*lifecycleValidator, error) {
	v, e := NewValidator(dir)
	if e != nil {
		return nil, e
	}
	if dir == "" {
		dir = os.Getenv("AHP_SCHEMA_DIR")
	}
	if dir == "" {
		dir = "../agent-hooks-protocol/schema/draft"
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat = true
	paths, e := filepath.Glob(filepath.Join(dir, "*.schema.json"))
	if e != nil {
		return nil, e
	}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil {
			return nil, e
		}
		var m Object
		if e = json.Unmarshal(b, &m); e != nil {
			return nil, e
		}
		if e = c.AddResource(str(m["$id"]), bytes.NewReader(b)); e != nil {
			return nil, e
		}
	}
	o, e := c.Compile("https://agenthooksprotocol.org/schemas/draft/observe-notification.schema.json")
	if e != nil {
		return nil, e
	}
	i, e := c.Compile("https://agenthooksprotocol.org/schemas/draft/content-item.schema.json")
	return &lifecycleValidator{v, o, i}, e
}
func (v *lifecycleValidator) validate(kind string, m Object) error {
	b, e := json.Marshal(m)
	if e != nil {
		return e
	}
	if kind != "observe" {
		_, e = v.core.Validate(kind, b)
		return e
	}
	if !ahp.ParseObserveNotification(b).OK {
		return fmt.Errorf("generated observe codec rejected notification")
	}
	if e = v.observe.Validate(m); e != nil {
		return e
	}
	event := obj(obj(m["params"])["event"])
	for _, x := range array(event["items"]) {
		b, _ := json.Marshal(x)
		if !ahp.ParseContentItem(b).OK {
			return fmt.Errorf("generated content codec rejected item")
		}
		if e = v.item.Validate(x); e != nil {
			return e
		}
	}
	return nil
}

var lifecycleHTTP = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func lifecycleCall(ctx context.Context, url string, body any) (Object, int, error) {
	return lifecycleCallWith(ctx, lifecycleHTTP, "", url, body)
}
func lifecycleCallWith(ctx context.Context, client *http.Client, token, url string, body any) (Object, int, error) {
	var r io.Reader
	method := "GET"
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return nil, 0, e
		}
		r = bytes.NewReader(b)
		method = "POST"
	}
	req, e := http.NewRequestWithContext(ctx, method, url, r)
	if e != nil {
		return nil, 0, e
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, e := client.Do(req)
	if e != nil {
		return nil, 0, e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if e != nil {
		return nil, res.StatusCode, e
	}
	var m Object
	if len(b) > 0 {
		if e = json.Unmarshal(b, &m); e != nil {
			return nil, res.StatusCode, e
		}
	}
	return m, res.StatusCode, nil
}
func lifecycleControl(ctx context.Context, base, path string, body any) (Object, error) {
	m, s, e := lifecycleCall(ctx, base+path, body)
	if e == nil && s != 200 {
		e = fmt.Errorf("control %s: HTTP %d", path, s)
	}
	return m, e
}
func lifecycleID(m Object) string { b, _ := json.Marshal(m["id"]); return string(b) }
func lifecycleReply(id any) Object {
	return Object{"jsonrpc": "2.0", "id": id, "result": Object{"protocolVersion": "draft", "effects": []any{}}}
}
