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

// accessorCall is the one call an app function makes, with the function's parameter
// named c: the router context the taint pass would hold as tainted.
type accessorCall struct {
	common *ssa.CallCommon
	ctx    ssa.Value
}

// access names what contextAccess makes of the call: "read" when its result is request
// data, "bind" when it names a target the request is decoded into, "" when neither.
func (c accessorCall) access() string {
	target, read := contextAccess(c.common, c.common.StaticCallee(), c.ctx)
	switch {
	case target != nil:
		return "bind"
	case read:
		return "read"
	}
	return ""
}

// accessorCalls type-checks deps in memory, in order, then builds appSrc, every
// function of which takes a parameter named c and makes exactly one call. It returns
// each function's call by function name.
func accessorCalls(t *testing.T, deps []struct{ path, src string }, appSrc string) map[string]accessorCall {
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
	calls := map[string]accessorCall{}
	for name, m := range app.Members {
		fn, ok := m.(*ssa.Function)
		if !ok || len(fn.Params) == 0 {
			continue
		}
		var ctx ssa.Value
		for _, p := range fn.Params {
			if p.Name() == "c" {
				ctx = p
			}
		}
		if ctx == nil {
			t.Fatalf("app.%s has no parameter c", name)
		}
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				if c, ok := instr.(ssa.CallInstruction); ok {
					if _, dup := calls[name]; dup {
						t.Fatalf("app.%s makes more than one call", name)
					}
					calls[name] = accessorCall{common: c.Common(), ctx: ctx}
				}
			}
		}
		if _, ok := calls[name]; !ok {
			t.Fatalf("app.%s makes no call", name)
		}
	}
	return calls
}

// checkAccess asserts what contextAccess makes of each app function's call.
func checkAccess(t *testing.T, calls map[string]accessorCall, cases []struct{ fn, want string }) {
	t.Helper()
	for _, tc := range cases {
		c, ok := calls[tc.fn]
		if !ok {
			t.Fatalf("no app.%s", tc.fn)
		}
		if got := c.access(); got != tc.want {
			t.Errorf("%s: contextAccess = %q, want %q", tc.fn, got, tc.want)
		}
	}
}

// TestContextAccess_NeedsGinsContext proves contextAccess models a call as a gin
// request read or bind only on gin's *Context, identified by the import path of the
// package declaring it, never by a method or type name alone. A Context declared under
// another path, in a package also named gin, reads and binds nothing; nor does a
// method with an accessor's or a binder's name on another gin type (Engine here), nor
// a call on gin's Context that is handed the tainted value as an argument rather than
// made on it as the receiver. And FullPath, which returns the registered route
// template, reads no request data even on gin's own Context.
func TestContextAccess_NeedsGinsContext(t *testing.T) {
	const ctxSrc = `package gin
type Context struct{}
func (c *Context) Param(key string) string { return key }
func (c *Context) Query(key string) string { return key }
func (c *Context) FullPath() string { return "" }
func (c *Context) ShouldBind(obj any) error { return nil }`
	calls := accessorCalls(t, []struct{ path, src string }{
		{"github.com/gin-gonic/gin", ctxSrc + `
type Engine struct{}
func (e *Engine) Param(key string) string { return key }
func (e *Engine) ShouldBind(obj any) error { return nil }`},
		{"tegron.test/othergin", ctxSrc},
	}, `package app
import (
	"github.com/gin-gonic/gin"
	other "tegron.test/othergin"
)
type login struct{ User string }
func ginParam(c *gin.Context) string        { return c.Param("id") }
func ginQuery(c *gin.Context) string        { return c.Query("q") }
func ginFullPath(c *gin.Context) string     { return c.FullPath() }
func ginBind(c *gin.Context) error          { var l login; return c.ShouldBind(&l) }
func otherParam(c *other.Context) string    { return c.Param("id") }
func otherQuery(c *other.Context) string    { return c.Query("q") }
func otherBind(c *other.Context) error      { var l login; return c.ShouldBind(&l) }
func engineParam(c *gin.Engine) string      { return c.Param("id") }
func engineBind(c *gin.Engine) error        { var l login; return c.ShouldBind(&l) }
func ctxArgBind(d *gin.Context, c any) error { return d.ShouldBind(c) }`)
	checkAccess(t, calls, []struct{ fn, want string }{
		{"ginParam", "read"},
		{"ginQuery", "read"},
		{"ginBind", "bind"},
		{"ginFullPath", ""},
		{"otherParam", ""},
		{"otherQuery", ""},
		{"otherBind", ""},
		{"engineParam", ""},
		{"engineBind", ""},
		{"ctxArgBind", ""},
	})
}

// TestContextAccess_NeedsEchosContext proves contextAccess models an invoke call as an
// echo request read or bind only when it is made on the tainted context itself and
// that context is echo's Context interface, identified by the import path of the
// package declaring it. A Context interface declared under another path, in a package
// also named echo, reads and binds nothing; nor does another echo interface with an
// accessor's method name (Router here, a stand-in), nor echo's Binder, whose Bind is
// handed the context as an argument rather than called on it.
func TestContextAccess_NeedsEchosContext(t *testing.T) {
	const ctxSrc = `package echo
type Context interface {
	Param(name string) string
	QueryParam(name string) string
	Bind(i any) error
}`
	calls := accessorCalls(t, []struct{ path, src string }{
		{"github.com/labstack/echo/v4", ctxSrc + `
type Binder interface{ Bind(i any, c Context) error }
type Router interface{ Param(name string) string }`},
		{"tegron.test/otherecho", ctxSrc},
	}, `package app
import (
	"github.com/labstack/echo/v4"
	other "tegron.test/otherecho"
)
type login struct{ User string }
func echoParam(c echo.Context) string                { return c.Param("id") }
func echoQueryParam(c echo.Context) string           { return c.QueryParam("q") }
func echoBind(c echo.Context) error                  { var l login; return c.Bind(&l) }
func otherParam(c other.Context) string              { return c.Param("id") }
func otherQueryParam(c other.Context) string         { return c.QueryParam("q") }
func otherBind(c other.Context) error                { var l login; return c.Bind(&l) }
func routerParam(c echo.Router) string               { return c.Param("id") }
func binderBind(b echo.Binder, c echo.Context) error { var l login; return b.Bind(&l, c) }`)
	checkAccess(t, calls, []struct{ fn, want string }{
		{"echoParam", "read"},
		{"echoQueryParam", "read"},
		{"echoBind", "bind"},
		{"otherParam", ""},
		{"otherQueryParam", ""},
		{"otherBind", ""},
		{"routerParam", ""},
		{"binderBind", ""},
	})
}
