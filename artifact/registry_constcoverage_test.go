package artifact

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// declaredTypeConsts parses artifact.go and returns the string value of every
// `<Name> Type = "<value>"` constant declared in the package. It is the ground
// truth for "what artifact types exist", independent of the hand-maintained
// allTypes slice and the Registry — so it can detect a const that was forgotten
// in BOTH. go test runs with the package directory as the working directory.
func declaredTypeConsts(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "artifact.go", nil, 0)
	if err != nil {
		t.Fatalf("parse artifact.go: %v", err)
	}
	out := map[string]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			// Only consts explicitly typed as Type (e.g. TypeHarness Type = "harness").
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != "Type" {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote %s value %q: %v", name.Name, lit.Value, err)
				}
				out[name.Name] = val
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("found no `Type = \"...\"` consts in artifact.go — parser logic is wrong")
	}
	return out
}

// TestEveryDeclaredTypeConstIsRegistered is the structural backstop against
// orphaned artifact types: a Type const that is declared (and therefore can be
// emitted via putArtifact) but has no Registry entry, so it carries no owner and
// no schema version. store.Put does not validate against the Registry, so such a
// gap is otherwise silent — exactly how repro_image and exposure_footprint slipped
// through. This test makes that class of bug impossible.
func TestEveryDeclaredTypeConstIsRegistered(t *testing.T) {
	declared := declaredTypeConsts(t)
	for name, val := range declared {
		if _, ok := Lookup(Type(val)); !ok {
			t.Errorf("const %s (%q) is declared but has no Registry entry — register it in registry.go", name, val)
		}
	}
	if got, want := len(registry), len(declared); got != want {
		t.Errorf("Registry has %d entries but %d Type consts are declared in artifact.go — they must be 1:1", got, want)
	}
}
