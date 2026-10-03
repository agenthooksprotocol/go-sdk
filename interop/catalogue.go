package interop

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
)

var catalogueEvents = []string{"tool.before", "tool.after", "turn.start", "turn.finish.before", "turn.end", "turn.progress", "model.request.before", "model.response.after", "model.error", "model.switch.before", "model.switch.after", "tool.permission.request", "tool.permission.resolved", "tool.progress", "tool.batch.after", "context.compact.before", "context.compact.after", "task.change.before", "task.change.after", "workspace.change.before", "workspace.change.after", "file.changed"}

func catalogueManifest() Object {
	events := []any{}
	for _, name := range catalogueEvents {
		entry := Object{"event": name, "modes": []any{"observe"}}
		if name == "tool.before" {
			entry["modes"] = []any{"observe", "intercept"}
			entry["capabilities"] = ToolCapabilities()
		}
		events = append(events, entry)
	}
	return Object{"events": events, "gaps": []any{Object{"path": "events.hook.failure", "reason": "not supported by synthetic catalogue host"}}, "transports": []any{"http", "stdio"}, "authentication": []any{"bearer", "oauth", "workload", "mtls"}, "toolPaths": []any{"native"}, "contentCategories": []any{"text", "reasoning", "images", "audio", "video", "files"}, "limits": Object{"maxUploadBytes": 16 << 20, "maxContinuations": 4}, "managedPolicy": Object{"scopes": []any{"user", "project"}, "disableable": true}, "correlationIdentityFields": []any{"event.id", "call.id", "task.id", "parentEventId"}}
}

type catalogueRejection struct{ kind string }

func (e catalogueRejection) Error() string { return "catalogue " + e.kind + " rejection" }
func (s *lifecycleReceiver) catalogueDispatch(m Object) (Object, error) {
	if m["method"] == "hooks/capabilities" {
		if e := s.validator.validate("capabilities-request", m); e != nil {
			return nil, e
		}
		response := Object{"jsonrpc": "2.0", "id": m["id"], "result": Object{"protocolVersion": "draft", "manifest": catalogueManifest()}}
		if e := s.validator.validate("capabilities-response", response); e != nil {
			return nil, e
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.record(Object{"kind": "discovery", "request": clone(m), "response": clone(response)})
		return response, nil
	}
	if m["method"] != "hooks/observe" {
		return nil, fmt.Errorf("unsupported catalogue method")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event := obj(obj(m["params"])["event"])
	reject := func(kind string) (Object, error) {
		s.record(Object{"kind": "rejected", "eventId": event["id"], "message": clone(m), "errorKind": kind})
		return nil, catalogueRejection{kind}
	}
	if e := s.validator.validate("observe", m); e != nil {
		return reject("schema")
	}
	// Content access is receiver policy, never a payload correlation claim.
	if e := checkContent(event, "", s.eventContent()); e != nil {
		return reject("schema")
	}
	if e := s.lineage.Accept(event); e != nil {
		return reject("lineage")
	}
	s.record(Object{"kind": "observed", "eventId": event["id"], "event": clone(event), "message": clone(m)})
	return nil, nil
}

func catalogueClient(ctx context.Context, c LifecycleConfig, v *lifecycleValidator, fixtures []lifecycleScenario, pipe *lifecyclePipe, client *http.Client, token string) error {
	discoveryRequest := Object{"jsonrpc": "2.0", "id": "catalogue-discovery", "method": "hooks/capabilities", "params": Object{"protocolVersion": "draft"}}
	if e := v.validate("capabilities-request", discoveryRequest); e != nil {
		return e
	}
	var discovery Object
	if pipe != nil {
		done := make(chan lifecycleResult, 1)
		if e := pipe.send(discoveryRequest, done); e != nil {
			return e
		}
		select {
		case r := <-done:
			if r.err != nil {
				return r.err
			}
			discovery = r.response
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		response, status, e := lifecycleCallWith(ctx, client, token, c.Endpoint+"/capabilities", discoveryRequest)
		if e != nil {
			return e
		}
		if status != 200 {
			return fmt.Errorf("discovery HTTP %d", status)
		}
		discovery = response
	}
	if e := v.validate("capabilities-response", discovery); e != nil {
		return e
	}
	if !reflect.DeepEqual(discovery["id"], discoveryRequest["id"]) {
		return fmt.Errorf("discovery correlation mismatch")
	}
	manifest := obj(obj(discovery["result"])["manifest"])
	var lineage TaskLineage
	counts := map[string]int{}
	results := []any{}
	for _, sc := range fixtures {
		actual := Object{"sent": []any{}, "registrations": []any{}}
		for _, step := range sc.Steps {
			switch step["op"] {
			case "register":
				accepted := validateRegistration(v.core, obj(step["registration"]), manifest, array(step["requirements"]), obj(step["context"])) == nil
				actual["registrations"] = append(array(actual["registrations"]), Object{"accepted": accepted})
			case "notify", "rawNotify":
				m := obj(clone(step["message"]))
				delete(obj(m["params"]), "subscriptionId")
				event := obj(obj(m["params"])["event"])
				if step["op"] == "notify" {
					if e := v.validate("observe", m); e != nil {
						return e
					}
					if e := checkContent(event, "", nil); e != nil {
						return e
					}
					if e := lineage.Accept(event); e != nil {
						return e
					}
				}
				if pipe != nil {
					if e := pipe.send(m, nil); e != nil {
						return e
					}
				} else {
					_, status, e := lifecycleCallWith(ctx, client, token, c.Endpoint+"/observe", m)
					if e != nil {
						return e
					}
					if status != 200 && status != 204 && !(step["op"] == "rawNotify" && (status == 400 || status == 409)) {
						return fmt.Errorf("notify HTTP %d", status)
					}
				}
				actual["sent"] = append(array(actual["sent"]), m)
				id := str(event["id"])
				counts[id]++
				if _, e := lifecycleControl(ctx, c.ControlEndpoint, "/wait-observed", Object{"eventId": id, "count": counts[id]}); e != nil {
					return e
				}
			default:
				return fmt.Errorf("unknown catalogue operation %v", step["op"])
			}
		}
		results = append(results, Object{"id": sc.ID, "status": "passed", "actual": actual})
	}
	receipts, e := lifecycleControl(ctx, c.ControlEndpoint, "/receipts", nil)
	if e != nil {
		return e
	}
	return writeAtomic(c.ReportFile, Object{"language": "go", "discovery": discovery, "results": results, "receipts": receipts})
}
