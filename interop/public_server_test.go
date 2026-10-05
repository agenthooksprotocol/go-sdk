package interop

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"github.com/agenthooksprotocol/go-sdk/server"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestPublicServerOrdinaryAndAdversarialFixtures(t *testing.T) {
	validator, err := NewValidator(schemaPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, negative := range []bool{false, true} {
		req := request("public-server")
		reply := response("fixture-id", Object{"type": "message", "text": "accepted"})
		if negative {
			reply = response("deliberately-wrong-id", Object{"type": "unknown"})
		}
		raw := wire(reply)
		state := &serverState{validator: validator, scenarios: []Scenario{{ID: "public-server", Response: raw, ExpectError: negative}}, barriers: map[string]chan struct{}{}}
		handler, err := state.publicHandler(nil)
		if err != nil {
			t.Fatal(err)
		}
		incoming := httptest.NewRequest(http.MethodPost, "/hooks", bytes.NewReader(wire(req)))
		incoming.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, incoming)
		got := recorder.Body.Bytes()
		if negative {
			if string(got) != string(raw) {
				t.Fatal("adversarial response changed")
			}
		} else {
			var actual Object
			if err := json.Unmarshal(got, &actual); err != nil {
				t.Fatal(err)
			}
			reply["id"] = req["id"]
			if !reflect.DeepEqual(actual, reply) {
				t.Fatalf("public callback response: %#v", actual)
			}
		}
	}
}

func TestHostSchemaRefusalRetainsAcceptedEffects(t *testing.T) {
	req := request("schema-refusal")
	actual, err := Apply(req, response("schema-refusal", Object{"type": "message", "text": "accepted message"}, Object{"type": "modify", "target": "input", "operation": "replace", "value": Object{"task": float64(0)}}))
	if err != nil {
		t.Fatalf("host refusal became protocol rejection: %v", err)
	}
	if actual["executed"] != false || actual["hostInputRejected"] != true || !reflect.DeepEqual(actual["input"], Object{"task": float64(0)}) || !reflect.DeepEqual(actual["messages"], []any{"accepted message"}) {
		t.Fatalf("accepted effects lost: %#v", actual)
	}
}

func TestPublicHTTPOrdinaryRoundTrip(t *testing.T) {
	validator, err := NewValidator(schemaPath(t))
	if err != nil {
		t.Fatal(err)
	}
	scenarios := testScenarios()
	state := &serverState{validator: validator, scenarios: scenarios, barriers: map[string]chan struct{}{}}
	handler, err := state.publicHandler(nil)
	if err != nil {
		t.Fatal(err)
	}
	receiver := httptest.NewServer(handler)
	defer receiver.Close()
	conn, closeConn, err := connection(context.Background(), Config{Transport: "http", Endpoint: receiver.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer closeConn()
	for _, scenario := range scenarios {
		t.Run(scenario.ID, func(t *testing.T) {
			var req Object
			if err := json.Unmarshal(scenario.Request, &req); err != nil {
				t.Fatal(err)
			}
			actual, rejected, err := publicIntercept(context.Background(), req, conn)
			if err != nil || rejected {
				t.Fatalf("round trip rejected: %v %v", err, rejected)
			}
			for key, value := range scenario.Expected {
				if !reflect.DeepEqual(actual[key], value) {
					t.Fatalf("%s: got %#v want %#v", key, actual[key], value)
				}
			}
		})
	}
}

func TestPublicStdioOrdinaryAndAdversarialFrames(t *testing.T) {
	validator, err := NewValidator(schemaPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, negative := range []bool{false, true} {
		req := request("stdio-public")
		reply := response("stdio-public", Object{"type": "message", "text": "accepted"})
		if negative {
			reply = response("deliberately-wrong-id", Object{"type": "unknown"})
		}
		raw := wire(reply)
		state := &serverState{validator: validator, scenarios: []Scenario{{ID: "stdio-public", Response: raw, ExpectError: negative}}, barriers: map[string]chan struct{}{}}
		host, receiver := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		handler, err := state.publicHandler(receiver)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- server.ServeStdio(ctx, receiver, receiver, handler) }()
		_ = host.SetDeadline(time.Now().Add(5 * time.Second))
		_, writeErr := host.Write(append(wire(req), '\n'))
		frame, readErr := bufio.NewReader(host).ReadBytes('\n')
		host.Close()
		serveErr := <-done
		cancel()
		if writeErr != nil || readErr != nil || serveErr != nil {
			t.Fatalf("stdio: write=%v read=%v serve=%v", writeErr, readErr, serveErr)
		}
		if !bytes.Equal(bytes.TrimSpace(frame), raw) {
			t.Fatalf("frame changed: %s", frame)
		}
	}
}
