package client_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/client"
)

func TestConsumerDecisionUsesGeneratedCandidate(t *testing.T) {
	var decision client.ToolDecision[struct{}, string, struct{}]
	decision.Candidate = ahp.Some(ahp.Candidate[string, struct{}]{Value: "answer"})
	if decision.Candidate.Value.Value != "answer" {
		t.Fatal("consumer candidate projection unavailable")
	}
}

func TestPrivateRuntimeTypesAbsentFromPublicNamespace(t *testing.T) {
	hidden := map[string]bool{"Composition": true, "ContractToolBeforeResult": true, "TypedCandidate": true, "StagedEffect": true, "DeclaredContracts": true, "ContextualEffects": true, "SchemaSourceSlots": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					if name, ok := spec.(*ast.TypeSpec); ok && hidden[name.Name.Name] {
						t.Errorf("implementation type %s is public", name.Name.Name)
					}
				}
			case *ast.FuncDecl:
				if decl.Recv == nil && hidden[decl.Name.Name] {
					t.Errorf("implementation helper %s is public", decl.Name.Name)
				}
			}
		}
	}
}
