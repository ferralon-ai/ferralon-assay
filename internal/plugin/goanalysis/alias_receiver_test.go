package goanalysis

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"
)

// TestSCIPString_AliasReceiver: a method declared on a type alias, directly or through a pointer to
// it, gets the id of the method on the aliased named type: "<pkg>/handler#M().", whose last slash is
// the package boundary. The alias's own String is package-qualified and would put slashes in the
// descriptor.
func TestSCIPString_AliasReceiver(t *testing.T) {
	const src = `package main

type handler struct{}

type A = handler

type B = A

func (A) M() {}

func (*B) N() {}

func (handler) O() {}

func main() {}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := (&types.Config{}).Check("example.com/m/cmd/tool", fset, []*ast.File{f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	named := pkg.Scope().Lookup("handler").Type().(*types.Named)
	for _, want := range []string{"M", "N", "O"} {
		var m types.Object
		for i := range named.NumMethods() {
			if named.Method(i).Name() == want {
				m = named.Method(i)
			}
		}
		if m == nil {
			t.Fatalf("method %s not declared on handler", want)
		}
		id := SCIPString(pkg, m)
		if suffix := " example.com/m/cmd/tool/handler#" + want + "()."; !strings.HasSuffix(id, suffix) {
			t.Errorf("SCIPString(%s) = %q, want suffix %q", want, id, suffix)
		}
	}
}
