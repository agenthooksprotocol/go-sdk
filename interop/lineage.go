package interop

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
)

type eventKey struct{ source, id string }

// TaskLineage tracks source-local identity, not task execution lifetime. A
// subscriber can receive a child first. Producers may require known parents.
type TaskLineage struct {
	mu                  sync.Mutex
	RequireKnownParents bool
	events              map[eventKey]Object
	parents             map[eventKey]eventKey
}

func pair(parent, child Object) error {
	for _, family := range []string{"task", "workspace"} {
		if parent["type"] != family+".change.before" || child["type"] != family+".change.after" {
			continue
		}
		a, b := obj(parent[family]), obj(child[family])
		identity := "id"
		if family == "workspace" {
			identity = "kind"
		}
		if a[identity] != b[identity] || (family == "task" && a["operation"] != b["operation"]) {
			return fmt.Errorf("after does not match known proposal")
		}
	}
	return nil
}
func actualChange(event Object) error {
	typ := str(event["type"])
	if typ == "task.change.after" || typ == "workspace.change.after" {
		family := strings.Split(typ, ".")[0]
		payload := obj(event[family])
		change, prior := obj(payload["change"]), obj(payload["prior"])
		if family == "task" && payload["operation"] != "update" {
			return nil
		}
		if len(change) == 0 {
			return fmt.Errorf("actual update has no changed fields")
		}
		if prior != nil {
			same := true
			for k, v := range change {
				old, ok := prior[k]
				if !ok || !reflect.DeepEqual(old, v) {
					same = false
				}
			}
			if same {
				return fmt.Errorf("actual update is unchanged")
			}
		}
	}
	if typ == "file.changed" {
		for _, raw := range array(event["changes"]) {
			c := obj(raw)
			if c["operation"] == "update" && c["before"] != nil && c["after"] != nil && reflect.DeepEqual(c["before"], c["after"]) {
				return fmt.Errorf("file update is unchanged")
			}
		}
	}
	return nil
}

// Accept follows canonical envelope validation. Rejected edges leave no state.
func (l *TaskLineage) Accept(event Object) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := actualChange(event); err != nil {
		return err
	}
	key := eventKey{str(event["source"]), str(event["id"])}
	if key.source == "" || key.id == "" {
		return fmt.Errorf("missing event identity")
	}
	var parent eventKey
	if id := str(event["parentEventId"]); id != "" {
		parent = eventKey{key.source, id}
	}
	if old, ok := l.events[key]; ok {
		if old["type"] != event["type"] || l.parents[key] != parent || (strings.HasPrefix(str(event["type"]), "task.change.") && obj(old["task"])["id"] != obj(event["task"])["id"]) {
			return fmt.Errorf("event identity changed")
		}
	}
	if parent.id != "" {
		if l.RequireKnownParents && l.events[parent] == nil {
			return fmt.Errorf("producer parent is unknown")
		}
		seen := map[eventKey]bool{key: true}
		for cursor := parent; cursor.id != ""; cursor = l.parents[cursor] {
			if seen[cursor] {
				return fmt.Errorf("cyclic parentEventId")
			}
			seen[cursor] = true
		}
		if p := l.events[parent]; p != nil {
			if e := pair(p, event); e != nil {
				return e
			}
		}
	}
	for child, edge := range l.parents {
		if edge == key {
			if e := pair(event, l.events[child]); e != nil {
				return e
			}
		}
	}
	if l.events == nil {
		l.events = map[eventKey]Object{}
		l.parents = map[eventKey]eventKey{}
	}
	l.events[key] = obj(clone(event))
	l.parents[key] = parent
	return nil
}
