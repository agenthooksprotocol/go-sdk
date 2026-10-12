package client

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

// The draft SDK has one authoritative consumer settlement, not parallel raw and
// typed snapshots. These assertions reject reintroduced migration surfaces.
func TestConsumerResultHasOneTypedSettlement(t *testing.T) {
	typ := reflect.TypeOf(Result{})
	for _, name := range []string{"SettledEvent", "SettledCandidate", "EffectiveInput", "EffectiveValues", "State", "Response", "AcceptedResponse", "Errors", "Observations"} {
		if _, exists := typ.FieldByName(name); exists {
			t.Errorf("compatibility field Result.%s returned", name)
		}
	}
	if _, exists := reflect.TypeOf(&Result{}).MethodByName("EffectiveValue"); exists {
		t.Fatal("raw canonical settlement accessor Result.EffectiveValue returned")
	}
	instructions, _ := typ.FieldByName("Instructions")
	injections, _ := typ.FieldByName("Injections")
	if instructions.Type != reflect.TypeOf(ahp.Optional[[]string]{}) || injections.Type != reflect.TypeOf(ahp.Optional[[]*ahp.InjectEffect]{}) {
		t.Fatal("accumulated settlement must be canonical and presence-aware")
	}
	event, _ := typ.FieldByName("Event")
	candidate, _ := typ.FieldByName("Candidate")
	if event.Type != reflect.TypeOf((*ahp.Event)(nil)) {
		t.Fatal("Event must be the canonical typed event")
	}
	if candidate.Type != reflect.TypeOf(ahp.Nullable[Candidate]{}) {
		t.Fatal("Candidate must be origin-correlated and typed")
	}
}

func TestHandwrittenPublicSurfaceRejectsCompatibilityExports(t *testing.T) {
	forbidden := map[string]bool{
		"Client": true, "ContentSource": true, "NewContentSource": true,
		"EventTransportResolver": true, "Observations": true,
		"Mode": true, "EventCapabilities": true, "Intercept": true, "Observe": true,
		"DeliveryCode": true, "DeliveryProtocolRejection": true, "DeliveryRemoteRPC": true,
		"DeliveryTransport": true, "DeliveryCancelled": true, "DeliveryDeadlineExceeded": true,
		"DeliveryPreparation": true, "DeliveryCapacity": true, "SettledCandidate": true,
	}
	for _, dir := range []string{".", "../content"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.Contains(name, "generated") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, declaration := range file.Decls {
				switch d := declaration.(type) {
				case *ast.FuncDecl:
					if d.Recv == nil && forbidden[d.Name.Name] {
						t.Errorf("compatibility function %s in %s", d.Name.Name, name)
					}
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						switch s := spec.(type) {
						case *ast.TypeSpec:
							if forbidden[s.Name.Name] || (dir == "../content" && s.Name.Name == "Attachment") {
								t.Errorf("compatibility type %s in %s", s.Name.Name, name)
							}
						case *ast.ValueSpec:
							for _, n := range s.Names {
								if forbidden[n.Name] {
									t.Errorf("compatibility value %s in %s", n.Name, name)
								}
							}
						}
					}
				}
			}
		}
	}
}
