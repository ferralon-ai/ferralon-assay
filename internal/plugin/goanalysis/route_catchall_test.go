package goanalysis

import (
	"context"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// echoPkgSCIP prefixes the SCIP id of a func declared in the echo stub's package.
const echoPkgSCIP = "scip-go gomod github.com/labstack/echo/v4 "

// TestCatchAllStore_EchoOwnDefaultsAreNoRoute proves the stores echo makes in its own
// package are no catch-all route even when echo's code is the build's own (a
// workspace member, or echo's repository under analysis): the default not-found and
// method-not-allowed closures echo assigns to NotFoundHandler and
// MethodNotAllowedHandler, and the defaultHTTPErrorHandler its New stores into
// Echo.HTTPErrorHandler. Only then are echo's bodies in the program, so only then
// does the own-package check in catchAllStoreRoutes decide anything; the fixture's
// own catch-all stores still register. (echo's DefaultHTTPErrorHandler, stored from
// the fixture's main, registers here too: echo is the build's own code in this
// program, unlike in the fixture's normal load, where
// TestEcho_OwnHandlersAndAdaptersAreNoIngress pins that it does not.)
func TestCatchAllStore_EchoOwnDefaultsAreNoRoute(t *testing.T) {
	res, err := LoadProgram(context.Background(), echoFixtureDir)
	if err != nil {
		t.Fatalf("LoadProgram: %v", err)
	}
	// Load echo as a workspace member is loaded: its bodies built, its package the
	// build's own.
	packages.Visit(res.Packages, nil, func(p *packages.Package) {
		if p.PkgPath == "github.com/labstack/echo/v4" {
			res.members = append(res.members, p)
		}
	})
	if len(res.members) != 1 {
		t.Fatalf("echo stub package not found among the fixture's imports")
	}
	sp, err := buildSSAWith(res, ssautil.Packages)
	if err != nil {
		t.Fatalf("buildSSA: %v", err)
	}

	// echo's own defaults: every func echo stores into a catch-all var or field in its
	// own package. They must be in the program, or the test would pass by not seeing
	// them.
	defaults := map[string]bool{}
	for fn := range ssautil.AllFunctions(sp.prog) {
		if fn.Pkg == nil || fn.Pkg.Pkg.Path() != "github.com/labstack/echo/v4" {
			continue
		}
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				st, ok := instr.(*ssa.Store)
				if !ok {
					continue
				}
				if _, ok := catchAllStoreRouter(st.Addr); !ok {
					continue
				}
				if h := staticHandler(st.Val); h != nil {
					defaults[sp.scipFunc(h)] = true
				}
			}
		}
	}
	if len(defaults) != 3 || !defaults[echoPkgSCIP+"v4.12.0 github.com/labstack/echo/v4/defaultHTTPErrorHandler()."] {
		t.Fatalf("echo's own catch-all defaults in the program = %v, want the NotFoundHandler and MethodNotAllowedHandler closures and defaultHTTPErrorHandler", defaults)
	}

	got := map[string]bool{}
	for _, r := range sp.discoverRoutes() {
		got[r.symbol] = true
		if defaults[r.symbol] {
			t.Errorf("echo's own default registered as a route: %s (selector %q)", r.symbol, r.selector)
		}
	}
	for _, h := range []string{"server#notFoundHandlerForm().", "server#methodNotAllowedForm().", "server#httpErrorForm()."} {
		if !got[echoFixtureSCIP+h] {
			t.Errorf("the fixture's catch-all store %s registers no route", h)
		}
	}
}
