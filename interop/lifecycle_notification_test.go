package interop

import (
	"context"
	"errors"
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

func TestLifecycleNotificationAcknowledgementScope(t *testing.T) {
	malicious := response("unsolicited-observer", Object{"type": "deny", "reason": "observer must not decide"})
	for _, tc := range []struct {
		name, eventID     string
		status            int
		body              Object
		valid, diagnostic bool
	}{
		{"accepted-empty", "ordinary-notification", 202, nil, true, false},
		{"no-content", "ordinary-notification", 204, nil, true, false},
		{"ordinary-ok-empty", "ordinary-notification", 200, nil, false, true},
		{"ordinary-ok-effects", "ordinary-notification", 200, malicious, false, true},
		{"ordinary-accepted-effects", "ordinary-notification", 202, malicious, false, true},
		{"hostile-fixture", "settled-observer-effects-ignored:a", 200, malicious, false, true},
		{"nearby-event", "settled-observer-effects-ignored:b", 200, malicious, false, true},
		{"fixture-wrong-status", "settled-observer-effects-ignored:a", 500, malicious, false, true},
		{"fixture-empty-ok", "settled-observer-effects-ignored:a", 200, nil, false, true},
		{"fixture-unexpected-envelope", "settled-observer-effects-ignored:a", 200, response("other", Object{"type": "allow"}), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				if tc.body != nil {
					_, _ = w.Write(jsonBytes(tc.body))
				}
			}))
			defer peer.Close()
			got, err := lifecyclePublicCall(context.Background(), publicLifecycleObservation(tc.eventID), nil, peer.Client(), "", peer.URL)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v response=%#v error=%v", tc.valid, got, err)
			}
			var acknowledgement *lifecycleObservationAcknowledgementError
			if errors.As(err, &acknowledgement) != tc.diagnostic {
				t.Fatalf("expected diagnostic=%v, error=%v", tc.diagnostic, err)
			}
			if err != nil && got != nil {
				t.Fatalf("rejected effects escaped: %#v", got)
			}
		})
	}
}
