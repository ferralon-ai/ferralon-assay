// Hermetic tests for the request-accessor model (taint_ssa.go): the predicate that
// decides whether a call whose body is not built, made on a tainted router context,
// reads request data. The packages are type-checked in memory and built to SSA, so
// each case is the call the taint pass would meet, with no fixture load.
package goanalysis

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// accessorCalls type-checks deps in memory, in order, then builds appSrc, every
// function of which makes exactly one call, a method call on its first parameter. It
// returns each function's call by function name.
func accessorCalls(t *testing.T, deps []struct{ path, src string }, appSrc string) map[string]*ssa.CallCommon {
	t.Helper()
	fset := token.NewFileSet()
	parse := func(path, src string) *ast.File {
		f, err := parser.ParseFile(fset, path+".go", src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		return f
	}
	checked := map[string]*types.Package{}
	conf := &types.Config{Importer: importerFunc(func(path string) (*types.Package, error) {
		if p, ok := checked[path]; ok {
			return p, nil
		}
		return nil, fmt.Errorf("no package %q", path)
	})}
	for _, dep := range deps {
		pkg, err := conf.Check(dep.path, fset, []*ast.File{parse(dep.path, dep.src)}, nil)
		if err != nil {
			t.Fatalf("check %s: %v", dep.path, err)
		}
		checked[dep.path] = pkg
	}
	app, _, err := ssautil.BuildPackage(conf, fset, types.NewPackage("tegron.test/app", "app"),
		[]*ast.File{parse("tegron.test/app", appSrc)}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	calls := map[string]*ssa.CallCommon{}
	for name, m := range app.Members {
		fn, ok := m.(*ssa.Function)
		if !ok || len(fn.Params) == 0 {
			continue
		}
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				if c, ok := instr.(ssa.CallInstruction); ok {
					if _, dup := calls[name]; dup {
						t.Fatalf("app.%s makes more than one call", name)
					}
					calls[name] = c.Common()
				}
			}
		}
		if _, ok := calls[name]; !ok {
			t.Fatalf("app.%s makes no call", name)
		}
	}
	return calls
}

// TestIsRequestAccessor_NeedsGinsContext proves isRequestAccessor identifies gin's
// *Context by the import path of the package declaring it, never by a method or type
// name alone: Param and Query on a Context declared under another path, in a package
// also named gin, are no request accessor, while gin's own are.
func TestIsRequestAccessor_NeedsGinsContext(t *testing.T) {
	const ctxSrc = `package gin
type Context struct{}
func (c *Context) Param(key string) string { return key }
func (c *Context) Query(key string) string { return key }`
	calls := accessorCalls(t, []struct{ path, src string }{
		{"github.com/gin-gonic/gin", ctxSrc},
		{"tegron.test/othergin", ctxSrc},
	}, `package app
import (
	"github.com/gin-gonic/gin"
	other "tegron.test/othergin"
)
func ginParam(c *gin.Context) string     { return c.Param("id") }
func ginQuery(c *gin.Context) string     { return c.Query("q") }
func otherParam(c *other.Context) string { return c.Param("id") }
func otherQuery(c *other.Context) string { return c.Query("q") }`)
	for _, tc := range []struct {
		fn   string
		want bool
	}{
		{"ginParam", true},
		{"ginQuery", true},
		{"otherParam", false},
		{"otherQuery", false},
	} {
		c, ok := calls[tc.fn]
		if !ok {
			t.Fatalf("no app.%s", tc.fn)
		}
		if got := isRequestAccessor(c.StaticCallee()); got != tc.want {
			t.Errorf("%s: isRequestAccessor(%s) = %v, want %v", tc.fn, c.StaticCallee(), got, tc.want)
		}
	}
}
