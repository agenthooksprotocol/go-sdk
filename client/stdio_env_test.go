package client

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

func TestBackendEnvironmentBase(t *testing.T) {
	host := []string{"PATH=/bin", "HOME=/home/u", "LC_CTYPE=C.UTF-8", "AHP_SECRET=host-only", "TMPDIR=/tmp", "HOME=/dup"}
	got := backendEnvironment(host, map[string]string{"HOME": "/override", "AHP_CHILD": "v"}, false, false)
	want := []string{"PATH=/bin", "LC_CTYPE=C.UTF-8", "TMPDIR=/tmp", "AHP_CHILD=v", "HOME=/override"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	if env := backendEnvironment(nil, nil, false, false); env == nil || len(env) != 0 {
		t.Fatalf("empty environment must be non-nil and empty: %#v", env)
	}
	if got := backendEnvironment(host, nil, true, false); !reflect.DeepEqual(got, host[:5]) {
		t.Fatalf("inherit: %q", got)
	}
	windows := backendEnvironment([]string{"Path=C:\\bin", "SystemRoot=C:\\Windows", "ComSpec=cmd.exe", "Secret=x"}, map[string]string{"PATH": "D:\\bin"}, false, true)
	if !reflect.DeepEqual(windows, []string{"SystemRoot=C:\\Windows", "ComSpec=cmd.exe", "PATH=D:\\bin"}) {
		t.Fatalf("windows: %q", windows)
	}
}

func childEnvironment(t *testing.T, env map[string]string, inherit bool) map[string]string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ahp.StdioTransport{Type: ahp.StdioTransportTypeStdio, Command: exe, Args: ahp.Some([]string{"-test.run=^TestTransportHelper$", "--", "ahp-helper=env"}), Lifecycle: ahp.StdioTransportLifecyclePersistent}
	if env != nil {
		cfg.Env = ahp.Some(env)
	}
	tr, err := newBackendTransport(&ahp.Backend{Transport: ahp.BackendTransport{StdioTransport: ahp.Some(cfg)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	tr.(*stdioBackend).inheritEnvironment = inherit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := tr.Exchange(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"env"}`), false)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result map[string]string `json:"result"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	return response.Result
}

func TestStdioBackendEnvironment(t *testing.T) {
	t.Setenv("AHP_HOST_ONLY", "host-secret")
	t.Setenv("HOME", "/host-home")
	got := childEnvironment(t, map[string]string{"AHP_CHILD": "literal $HOME", "HOME": "/child-home"}, false)
	if got["AHP_CHILD"] != "literal $HOME" {
		t.Fatalf("registration env entry missing or interpolated: %q", got["AHP_CHILD"])
	}
	if got["HOME"] != "/child-home" {
		t.Fatalf("registration env must override base: %q", got["HOME"])
	}
	if _, ok := got["AHP_HOST_ONLY"]; ok {
		t.Fatal("host-only variable inherited by default")
	}
	inherited := childEnvironment(t, nil, true)
	if inherited["AHP_HOST_ONLY"] != "host-secret" || inherited["HOME"] != "/host-home" {
		t.Fatal("InheritEnvironment did not pass the host environment")
	}
}

func TestStdioEnvironmentRejectsUnrepresentableEntries(t *testing.T) {
	for _, env := range []map[string]string{{"": "x"}, {"A=B": "x"}, {"A": "x\x00y"}} {
		cfg := &ahp.StdioTransport{Type: ahp.StdioTransportTypeStdio, Command: "backend", Lifecycle: ahp.StdioTransportLifecyclePersistent, Env: ahp.Some(env)}
		_, err := newBackendTransport(&ahp.Backend{Transport: ahp.BackendTransport{StdioTransport: ahp.Some(cfg)}}, nil)
		if err == nil || strings.Contains(err.Error(), "x") {
			t.Fatalf("accepted or leaked %q: %v", env, err)
		}
	}
}
