// Hermetic goanalysis tests for chi ingress detection (ingress.go). They load a real
// fixture (chimod) with the Go toolchain — no live model, no Docker, no network: the
// fixture's go.mod replaces github.com/go-chi/chi and github.com/go-chi/chi/v5 with
// local stubs so the detector matches the package paths without fetching the real
// modules, and replaces the net/http types chi's API uses with a stand-in
// (nethttpstub) so a load fits the per-test time limit.
//
// They prove every chi registration form — the verb methods, Method/MethodFunc,
// Handle/HandleFunc, and handlers reached through Route, Group, With and Mount —
// surfaces its handler as an Ingress{Kind:"http_route"} that heads the taint trace to
// that form's sink (the trace attackerIngressInTrace matches against), and that the
// detector does not over-fire: an unregistered handler-shaped func and every handler
// registered on a look-alike router (chi's package, type and method names under
// another import path) are no ingress at all.
package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	chiFixtureDir = "testdata/chimod"
	// chiFixtureSCIP prefixes the SCIP id of a func or method declared in chimod's
	// main package.
	chiFixtureSCIP = "scip-go gomod tegron.test/chimod . tegron.test/chimod/"
)

// chiForms lists each chi registration form with the handler it registers (as the
// tail of its SCIP id) and the sink only that handler reaches.
var chiForms = []struct {
	form, handler, sink string
}{
	{"Get", "server#getForm().", "sinkGet"},
	{"Post", "server#postForm().", "sinkPost"},
	{"Put", "server#putForm().", "sinkPut"},
	{"Patch", "server#patchForm().", "sinkPatch"},
	{"Delete", "server#deleteForm().", "sinkDelete"},
	{"Head", "server#headForm().", "sinkHead"},
	{"Options", "server#optionsForm().", "sinkOptions"},
	{"Connect", "server#connectForm().", "sinkConnect"},
	{"Trace", "server#traceForm().", "sinkTrace"},
	{"Method", "server#methodForm().", "sinkMethod"},
	{"MethodFunc", "server#methodFuncForm().", "sinkMethodFunc"},
	{"Handle", "server#handleForm().", "sinkHandle"},
	{"HandleFunc", "server#handleFuncForm().", "sinkHandleFunc"},
	{"Route", "server#routeForm().", "sinkRoute"},
	{"Group", "main$2$1().", "sinkGroup"}, // a closure registered inside the Group closure
	{"With", "server#withForm().", "sinkWith"},
	{"Mount", "mountedHandler#ServeHTTP().", "sinkMount"},
	{"Mount sub-router", "server#mountSubForm().", "sinkMountSub"},
	{"chi v1 path", "server#v1Form().", "sinkV1"},
	{"nested Route in a named func", "server#nestedRouteForm().", "sinkNestedRoute"},
	{"Route on a method value", "server#methodRouteForm().", "sinkMethodRoute"},
	{"non-constant Route pattern", "server#dynRouteForm().", "sinkDynRoute"},
}

func chiIngresses(t *testing.T) []plugin.Ingress {
	t.Helper()
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: chiFixtureDir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	return res.Ingresses
}

// TestChi_RegistrationFormsAreRouteIngresses proves each chi registration form's
// handler surfaces as an http_route ingress — the kind the net/http and macaron
// registrars emit, which attackerControllableKinds already covers.
func TestChi_RegistrationFormsAreRouteIngresses(t *testing.T) {
	kinds := map[string]string{}
	for _, in := range chiIngresses(t) {
		kinds[in.Symbol.SCIP] = in.Kind
	}
	for _, f := range chiForms {
		if got := kinds[chiFixtureSCIP+f.handler]; got != "http_route" {
			t.Errorf("chi %s: handler %s kind = %q, want http_route; ingresses = %v", f.form, f.handler, got, kinds)
		}
	}
}

// TestChi_RouteIngressHeadsTaintTrace proves each form's handler is the ingress at the
// head of the taint trace to its own sink, so attackerIngressInTrace finds an
// attacker-controllable ingress on it; and that the negatives' sinks get no path.
func TestChi_RouteIngressHeadsTaintTrace(t *testing.T) {
	var sinks []string
	for _, f := range chiForms {
		sinks = append(sinks, chiFixtureSCIP+f.sink+"().")
	}
	negSinks := []string{chiFixtureSCIP + "sinkNeverRegistered().", chiFixtureSCIP + "sinkLookalike()."}
	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: chiFixtureDir,
		Sinks:    append(sinks, negSinks...),
	})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	bySink := map[string]plugin.ReachPath{}
	for _, p := range res.Paths {
		bySink[p.Sink.SCIP] = p
	}
	for _, f := range chiForms {
		p, ok := bySink[chiFixtureSCIP+f.sink+"()."]
		if !ok {
			t.Errorf("chi %s: no taint path to %s; paths = %+v", f.form, f.sink, res.Paths)
			continue
		}
		want := chiFixtureSCIP + f.handler
		if p.Ingress.SCIP != want || len(p.Trace) == 0 || p.Trace[0].SCIP != want {
			t.Errorf("chi %s: path to %s has ingress %q trace %v, want %q at the trace head", f.form, f.sink, p.Ingress.SCIP, p.Trace, want)
		}
	}
	for _, s := range negSinks {
		if p, ok := bySink[s]; ok {
			t.Errorf("no chi-registered handler reaches %s, yet a path exists from %q", s, p.Ingress.SCIP)
		}
	}
}

// TestChi_UnregisteredHandlerIsNoIngress proves a handler-shaped func that no router
// registers — a method and a package-scope func — yields no ingress of any kind, and
// neither do the arguments of chi's Route, Group and With: the grouping closures
// (main$1 for Route, main$2 for Group) and the With middleware are not handlers.
func TestChi_UnregisteredHandlerIsNoIngress(t *testing.T) {
	assertNoChiIngress(t, chiIngresses(t),
		"server#neverRegistered().",
		"unregisteredFunc().",
		"main$1().",
		"main$2().",
		"middleware().",
	)
}

// TestChi_AdapterAndRouterServeHTTPAreNoIngress proves no http_route ingress lies
// outside the fixture's own package: neither the adapter's HandlerFunc.ServeHTTP (a
// handler reaching chi as an http.HandlerFunc in a variable, through fwdRouter) nor
// a chi router's own ServeHTTP (a bare sub-router mounted directly).
func TestChi_AdapterAndRouterServeHTTPAreNoIngress(t *testing.T) {
	for _, in := range chiIngresses(t) {
		if in.Kind == "http_route" && !strings.HasPrefix(in.Symbol.SCIP, chiFixtureSCIP) {
			t.Errorf("http_route ingress outside the fixture: %s (selector %q)", in.Symbol.SCIP, in.Selector)
		}
	}
}

// TestChi_NetHTTPHandlerFuncIsNoHandler pins routerHandler's explicit net/http
// exclusion, which no chimod fixture can reach: the fixture stands net/http in at
// another path, and a value boxed into its own Handler interface is already caught by
// the adapter clause. Here a net/http HandlerFunc is boxed into an http.Handler-shaped
// interface declared elsewhere, so only the net/http clause keeps its ServeHTTP from
// becoming a chi (or gin) handler. The packages are type-checked in memory (no
// net/http load).
func TestChi_NetHTTPHandlerFuncIsNoHandler(t *testing.T) {
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
	for _, dep := range []struct{ path, src string }{
		{"net/http", `package http
type ResponseWriter interface{ Write([]byte) (int, error) }
type Request struct{}
type HandlerFunc func(ResponseWriter, *Request)
func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) { f(w, r) }`},
		{"tegron.test/iface", `package iface
import "net/http"
type Handler interface{ ServeHTTP(http.ResponseWriter, *http.Request) }`},
	} {
		pkg, err := conf.Check(dep.path, fset, []*ast.File{parse(dep.path, dep.src)}, nil)
		if err != nil {
			t.Fatalf("check %s: %v", dep.path, err)
		}
		checked[dep.path] = pkg
	}
	appSrc := `package app
import ("net/http"; "tegron.test/iface")
func Box(f http.HandlerFunc) iface.Handler { return f }`
	app, _, err := ssautil.BuildPackage(conf, fset, types.NewPackage("tegron.test/app", "app"),
		[]*ast.File{parse("tegron.test/app", appSrc)}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var mi *ssa.MakeInterface
	for _, b := range app.Func("Box").Blocks {
		for _, instr := range b.Instrs {
			if m, ok := instr.(*ssa.MakeInterface); ok {
				mi = m
			}
		}
	}
	if mi == nil {
		t.Fatal("no MakeInterface in app.Box")
	}
	sp := &ssaProgram{prog: app.Prog}
	for _, r := range pathRouters {
		if fn := sp.routerHandler(r, mi); fn != nil {
			t.Errorf("net/http HandlerFunc boxed into %s resolved to handler %s, want none", mi.Type(), fn)
		}
	}
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

// TestChi_MethodSelectorIsPattern proves Method and MethodFunc drop their leading
// HTTP-method argument: the selector is the route pattern, never the method.
func TestChi_MethodSelectorIsPattern(t *testing.T) {
	want := map[string]string{"server#methodForm().": "/method", "server#methodFuncForm().": "/methodfunc"}
	seen := map[string]bool{}
	for _, in := range chiIngresses(t) {
		for h, sel := range want {
			if in.Kind == "http_route" && in.Symbol.SCIP == chiFixtureSCIP+h {
				seen[h] = true
				if in.Selector != sel {
					t.Errorf("%s selector = %q, want %q", h, in.Selector, sel)
				}
			}
		}
	}
	for h := range want {
		if !seen[h] {
			t.Errorf("%s: no http_route ingress found", h)
		}
	}
}

// TestChi_RoutePrefixIsComposed proves a route registered inside a Route closure has
// the full composed pattern as its selector: one Route deep, Routes nested through a
// named func and a Group and on a With result, and a method value handed to Route.
// A route on the root router, or directly in a Group (which adds no prefix), keeps its
// own pattern, and so does one under a Route whose pattern is no constant — never a
// guessed prefix.
func TestChi_RoutePrefixIsComposed(t *testing.T) {
	want := map[string]string{
		"server#getForm().":         "/get/{id}",
		"main$2$1().":               "/group",
		"server#routeForm().":       "/route/{id}",
		"server#nestedRouteForm().": "/admin/users/{id}",
		"server#methodRouteForm().": "/m/{id}",
		"server#dynRouteForm().":    "/dyn",
	}
	got := map[string][]string{}
	for _, in := range chiIngresses(t) {
		if in.Kind == "http_route" {
			got[in.Symbol.SCIP] = append(got[in.Symbol.SCIP], in.Selector)
		}
	}
	for h, sel := range want {
		if g := got[chiFixtureSCIP+h]; len(g) != 1 || g[0] != sel {
			t.Errorf("%s selectors = %q, want [%q]", h, g, sel)
		}
	}
}

// TestChi_LookalikeRouterIsNoIngress proves the router is identified by its import
// path: a router with chi's package name, type and method names under another path
// registers nothing, through any form (verbs, Handle, Method, Mount, Route).
func TestChi_LookalikeRouterIsNoIngress(t *testing.T) {
	assertNoChiIngress(t, chiIngresses(t),
		"server#lookalikeGet().",
		"server#lookalikePost().",
		"server#lookalikeHandle().",
		"server#lookalikeMethod().",
		"server#lookalikeRoute().",
		"lookalikeMounted#ServeHTTP().",
	)
}

func assertNoChiIngress(t *testing.T, ingresses []plugin.Ingress, handlers ...string) {
	t.Helper()
	for _, h := range handlers {
		for _, in := range ingresses {
			if in.Symbol.SCIP == chiFixtureSCIP+h {
				t.Errorf("%s must be no ingress; got Kind %q selector %q", h, in.Kind, in.Selector)
			}
		}
	}
}
