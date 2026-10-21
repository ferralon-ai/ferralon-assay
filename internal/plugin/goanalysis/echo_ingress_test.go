// Hermetic goanalysis tests for echo ingress detection (ingress.go), the third
// framework on chi's recognition rule (pathRouter). They load a real fixture (echomod)
// with the Go toolchain — no live model, no Docker, no network: the fixture's go.mod
// replaces github.com/labstack/echo/v4 with a local stub so the detector matches the
// package path without fetching the real module, and replaces the net/http types
// echo's API uses with a stand-in (nethttpstub) so a load fits the per-test time limit.
//
// They prove every echo registration form — the verb methods, Any, Add, Match, a
// route that also carries route middleware, handlers registered on a Group (nested,
// through Add and Match, and in a helper), and net/http handlers adapted by
// WrapHandler — surfaces its handler as an Ingress{Kind:"http_route"} with the full
// composed route pattern as its selector, heading the taint trace to that form's sink
// from the echo.Context parameter, an interface whose modeled accessors are invoke
// calls; and that the detector does not over-fire: an unregistered handler-shaped
// func, Pre, Use, Group and route middleware, WrapMiddleware, echo's own
// Echo.ServeHTTP and wrapper closures, the HandlerFunc adapter, and every handler
// registered on a look-alike router are no ingress at all.
package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	echoFixtureDir = "testdata/echomod"
	// echoFixtureSCIP prefixes the SCIP id of a func or method declared in echomod's
	// main package.
	echoFixtureSCIP = "scip-go gomod tegron.test/echomod . tegron.test/echomod/"
)

// echoForms lists each echo registration form with the handler it registers (as the
// tail of its SCIP id), the selector it registers under, and the sink only that
// handler reaches.
var echoForms = []struct {
	form, handler, selector, sink string
}{
	{"GET", "server#getForm().", "/get/:id", "sinkGet"},
	{"POST", "server#postForm().", "/post", "sinkPost"},
	{"PUT", "server#putForm().", "/put", "sinkPut"},
	{"PATCH", "server#patchForm().", "/patch", "sinkPatch"},
	{"DELETE", "server#deleteForm().", "/delete/:id", "sinkDelete"},
	{"HEAD", "server#headForm().", "/head", "sinkHead"},
	{"OPTIONS", "server#optionsForm().", "/options", "sinkOptions"},
	{"CONNECT", "server#connectForm().", "/connect", "sinkConnect"},
	{"TRACE", "server#traceForm().", "/trace", "sinkTrace"},
	{"Any", "server#anyForm().", "/any", "sinkAny"},
	{"Add", "server#addForm().", "/add/:id", "sinkAdd"},
	{"Match", "server#matchForm().", "/match", "sinkMatch"},
	{"route middleware", "server#routeMWForm().", "/mw/:id", "sinkRouteMW"},
	{"Group", "main$1().", "/api/users/:id", "sinkGroup"}, // a closure registered on the Group
	{"nested Group", "server#nestedForm().", "/api/admin/:id", "sinkNested"},
	{"Group Add", "server#groupAddForm().", "/api/add/:id", "sinkGroupAdd"},
	{"Group Match", "server#groupMatchForm().", "/api/match/:id", "sinkGroupMatch"},
	{"Group in a helper", "server#helperForm().", "/v2/items", "sinkHelper"},
	{"non-constant Group prefix", "server#dynamicForm().", "/dynamic/:id", "sinkDynamic"},
	{"WrapHandler", "wrappedHandler#ServeHTTP().", "/wraph", "sinkWrapH"},
	{"WrapHandler(http.HandlerFunc)", "server#netForm().", "/wrapf", "sinkWrapF"},
}

// echoAccessors lists each modeled echo.Context accessor; accessorsForm hands its
// result (for Bind, its bound target) to sink<name>.
var echoAccessors = []string{
	"Param", "QueryParam", "QueryParams", "FormValue", "FormParams", "Request", "Cookie", "Bind",
}

func echoIngresses(t *testing.T) []plugin.Ingress {
	t.Helper()
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: echoFixtureDir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	return res.Ingresses
}

// TestEcho_RegistrationFormsAreRouteIngresses proves each echo registration form's
// handler surfaces as an http_route ingress whose selector is the full route pattern.
// Add and Match report their path, never the HTTP method(s) they take ahead of it; a
// route on a Group, a nested Group, or a Group passed to a helper is composed under
// the group prefixes; and a route under a Group whose prefix is no constant keeps its
// local pattern.
func TestEcho_RegistrationFormsAreRouteIngresses(t *testing.T) {
	selectors := map[string][]string{}
	for _, in := range echoIngresses(t) {
		if in.Kind == "http_route" {
			selectors[in.Symbol.SCIP] = append(selectors[in.Symbol.SCIP], in.Selector)
		}
	}
	for _, f := range echoForms {
		got := selectors[echoFixtureSCIP+f.handler]
		if len(got) != 1 || got[0] != f.selector {
			t.Errorf("echo %s: handler %s http_route selectors = %q, want [%q]", f.form, f.handler, got, f.selector)
		}
	}
}

// TestEcho_RouteIngressHeadsTaintTrace proves each form's handler is the ingress at
// the head of the taint trace to its own sink, and that every modeled echo.Context
// accessor carries taint from the handler's context parameter — an interface, so each
// accessor is an invoke call — to its own sink from accessorsForm. Path, which reads
// no request data, does not, and neither the negatives' sinks nor the middleware's
// get a path.
func TestEcho_RouteIngressHeadsTaintTrace(t *testing.T) {
	want := map[string]string{}
	for _, f := range echoForms {
		want[echoFixtureSCIP+f.sink+"()."] = echoFixtureSCIP + f.handler
	}
	for _, a := range echoAccessors {
		want[echoFixtureSCIP+"sink"+a+"()."] = echoFixtureSCIP + "server#accessorsForm()."
	}
	negSinks := []string{
		echoFixtureSCIP + "sinkNotRequestData().",
		echoFixtureSCIP + "sinkNeverRegistered().",
		echoFixtureSCIP + "sinkMiddleware().",
		echoFixtureSCIP + "sinkLookalike().",
	}
	sinks := append([]string(nil), negSinks...)
	for s := range want {
		sinks = append(sinks, s)
	}
	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{BuildDir: echoFixtureDir, Sinks: sinks})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	bySink := map[string]plugin.ReachPath{}
	for _, p := range res.Paths {
		bySink[p.Sink.SCIP] = p
	}
	for sink, ingress := range want {
		p, ok := bySink[sink]
		if !ok {
			t.Errorf("echo: no taint path to %s", strings.TrimPrefix(sink, echoFixtureSCIP))
			continue
		}
		if p.Ingress.SCIP != ingress || len(p.Trace) == 0 || p.Trace[0].SCIP != ingress {
			t.Errorf("echo: path to %s has ingress %q trace %v, want %q at the trace head", sink, p.Ingress.SCIP, p.Trace, ingress)
		}
	}
	for _, s := range negSinks {
		if p, ok := bySink[s]; ok {
			t.Errorf("no echo-registered handler reaches %s, yet a path exists from %q", s, p.Ingress.SCIP)
		}
	}
}

// TestEcho_UnregisteredHandlerAndMiddlewareAreNoIngress proves a handler-shaped func
// that no router registers yields no ingress of any kind, and neither does
// middleware: Pre, Use and Group middleware, the route middleware after a route's
// handler, the handler closures each returns, and net/http middleware adapted by
// WrapMiddleware.
func TestEcho_UnregisteredHandlerAndMiddlewareAreNoIngress(t *testing.T) {
	assertNoEchoIngress(t, echoIngresses(t),
		"server#neverRegistered().",
		"unregisteredFunc().",
		"preMiddleware().", "preMiddleware$1().",
		"useMiddleware().", "useMiddleware$1().",
		"groupMiddleware().", "groupMiddleware$1().",
		"routeMiddleware().", "routeMiddleware$1().",
		"netMiddleware().",
	)
}

// TestEcho_OwnHandlersAndAdaptersAreNoIngress proves no http_route ingress lies outside
// the fixture's own package: not echo's Echo.ServeHTTP (an echo router mounted through
// WrapHandler: the router-path clause), not the HandlerFunc adapter's ServeHTTP (a
// handler reaching WrapHandler as an http.HandlerFunc in a variable, through
// fwdRouter: the adapter clause), and not the closures echo's WrapHandler and
// WrapMiddleware build.
func TestEcho_OwnHandlersAndAdaptersAreNoIngress(t *testing.T) {
	for _, in := range echoIngresses(t) {
		if in.Kind == "http_route" && !strings.HasPrefix(in.Symbol.SCIP, echoFixtureSCIP) {
			t.Errorf("http_route ingress outside the fixture: %s (selector %q)", in.Symbol.SCIP, in.Selector)
		}
	}
}

// TestEcho_LookalikeRouterIsNoIngress proves the router is identified by its import
// path: a router with echo's package name, type and method names under another path
// registers nothing, through any form (verbs, Add, Group), and its WrapHandler
// look-alike on a real echo route resolves to no handler.
func TestEcho_LookalikeRouterIsNoIngress(t *testing.T) {
	assertNoEchoIngress(t, echoIngresses(t),
		"server#lookalikeGet().",
		"server#lookalikePost().",
		"server#lookalikeAdd().",
		"server#lookalikeGroup().",
		"server#lookalikeNet().",
	)
}

func assertNoEchoIngress(t *testing.T, ingresses []plugin.Ingress, handlers ...string) {
	t.Helper()
	for _, h := range handlers {
		for _, in := range ingresses {
			if in.Symbol.SCIP == echoFixtureSCIP+h {
				t.Errorf("%s must be no ingress; got Kind %q selector %q", h, in.Kind, in.Selector)
			}
		}
	}
}
