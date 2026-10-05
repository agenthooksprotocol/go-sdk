package interop

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLifecycleOrdinaryNotificationSilence(t *testing.T) {
	validator, err := newLifecycleValidator(schemaPath(t))
	if err != nil {
		t.Fatal(err)
	}
	receiver := &lifecycleReceiver{validator: validator, changed: make(chan struct{}), sequences: map[string][]Object{}, uploads: map[string]string{}}
	note := Object{"jsonrpc": "2.0", "method": "hooks/observe", "params": Object{"protocolVersion": "draft", "event": obj(request("ordinary-notification")["params"])["event"]}}
	reply, err := receiver.dispatch(context.Background(), note)
	if err != nil {
		t.Fatal(err)
	}
	if reply != nil {
		t.Fatalf("ordinary notification produced stdio frame: %#v", reply)
	}
	httpReceiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeLifecycleReply(w, reply) }))
	defer httpReceiver.Close()
	response, err := http.Get(httpReceiver.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("notification acknowledgement: status=%d body=%s", response.StatusCode, body)
	}
	if len(receiver.entries) != 1 || obj(receiver.entries[0])["kind"] != "observed" {
		t.Fatal("notification was not recorded")
	}
}
