// Hermetic goanalysis tests for gin ingress detection (ingress.go), the second
// framework on chi's recognition rule (pathRouter). They load a real fixture (ginmod)
// with the Go toolchain — no live model, no Docker, no network: the fixture's go.mod
// replaces github.com/gin-gonic/gin with a local stub so the detector matches the
// package path without fetching the real module, and replaces the net/http types
// gin's API uses with a stand-in (nethttpstub) so a load fits the per-test time limit.
//
// They prove every gin registration form — the verb methods, Any, Handle, Match, a
// route's handler chain, handlers registered through Group (nested, and in a helper)
// and the IRoutes interface, NoRoute and NoMethod, and net/http handlers adapted by
// WrapF and WrapH — surfaces its handler as an Ingress{Kind:"http_route"} with the
// full composed route pattern as its selector, heading the taint trace to that form's
// sink from the *gin.Context parameter; that every modeled accessor and binder carries
// that taint; and that the detector does not over-fire: an unregistered
// handler-shaped func, Use and Group middleware, the Static* registrars, gin's own
// Engine.ServeHTTP and wrapper closures, the HandlerFunc adapter, and every handler
// registered on a look-alike router are no ingress at all.
package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	ginFixtureDir = "testdata/ginmod"
	// ginFixtureSCIP prefixes the SCIP id of a func or method declared in ginmod's
	// main package.
	ginFixtureSCIP = "scip-go gomod tegron.test/ginmod . tegron.test/ginmod/"
)

// ginForms lists each gin registration form with the handler it registers (as the
// tail of its SCIP id), the selector it registers under, and the sink only that
// handler reaches.
var ginForms = []struct {
	form, handler, selector, sink string
}{
	{"GET", "server#getForm().", "/get/:id", "sinkGet"},
	{"POST", "server#postForm().", "/post", "sinkPost"},
	{"PUT", "server#putForm().", "/put", "sinkPut"},
	{"PATCH", "server#patchForm().", "/patch", "sinkPatch"},
	{"DELETE", "server#deleteForm().", "/delete/:id", "sinkDelete"},
	{"HEAD", "server#headForm().", "/head", "sinkHead"},
	{"OPTIONS", "server#optionsForm().", "/options", "sinkOptions"},
	{"Any", "server#anyForm().", "/any", "sinkAny"},
	{"Handle", "server#handleForm().", "/x", "sinkHandle"},
	{"Match", "server#matchForm().", "/y", "sinkMatch"},
	{"chain (first handler)", "server#chainAuth().", "/chain/:id", "sinkChainAuth"},
	{"chain (last handler)", "server#chainForm().", "/chain/:id", "sinkChain"},
	{"Group", "main$1().", "/v1/users/:id", "sinkGroup"}, // a closure registered on the Group
	{"nested Group", "server#nestedForm().", "/v1/admin/:id", "sinkNested"},
	{"IRouter interface", "server#iroutesForm().", "/api/iroutes", "sinkIRoutes"},
	{"WrapF", "server#netForm().", "/wrapf", "sinkWrapF"},
	{"WrapH", "wrappedHandler#ServeHTTP().", "/wraph", "sinkWrapH"},
	{"NoRoute", "server#noRouteForm().", "*", "sinkNoRoute"},
	{"NoMethod", "server#noMethodForm().", "*", "sinkNoMethod"},
	{"non-constant Group prefix", "server#dynamicForm().", "/dynamic/:id", "sinkDynamic"},
}

// ginAccessors lists each modeled *gin.Context accessor and binder with the sink only
// its result (or, for a binder, its bound target) reaches from accessorsForm.
var ginAccessors = []string{
	"DefaultQuery", "GetQuery", "QueryArray", "QueryMap", "GetPostForm", "PostFormArray",
	"GetHeader", "Cookie", "GetRawData", "FullPath",
	"Bind", "BindJSON", "BindQuery", "BindUri", "MustBindWith",
	"ShouldBind", "ShouldBindJSON", "ShouldBindQuery", "ShouldBindUri", "ShouldBindHeader",
	"ShouldBindWith", "ShouldBindBodyWith",
}

func ginIngresses(t *testing.T) []plugin.Ingress {
	t.Helper()
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: ginFixtureDir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	return res.Ingresses
}

// TestGin_RegistrationFormsAreRouteIngresses proves each gin registration form's
// handler surfaces as an http_route ingress whose selector is the full route pattern —
// the kind the net/http, macaron and chi registrars emit, which
// attackerControllableKinds already covers. Handle and Match report "/x" and "/y",
// never the HTTP method(s) they take ahead of the pattern; a route on a Group, a
// nested Group, or a Group passed to a helper is composed under the group prefixes;
// NoRoute and NoMethod register under the catch-all "*"; and a route under a Group
// whose prefix is no constant keeps its local pattern.
func TestGin_RegistrationFormsAreRouteIngresses(t *testing.T) {
	selectors := map[string][]string{}
	for _, in := range ginIngresses(t) {
		if in.Kind == "http_route" {
			selectors[in.Symbol.SCIP] = append(selectors[in.Symbol.SCIP], in.Selector)
		}
	}
	for _, f := range ginForms {
		got := selectors[ginFixtureSCIP+f.handler]
		if len(got) != 1 || got[0] != f.selector {
			t.Errorf("gin %s: handler %s http_route selectors = %q, want [%q]", f.form, f.handler, got, f.selector)
		}
	}
}

// TestGin_RouteIngressHeadsTaintTrace proves each form's handler is the ingress at the
// head of the taint trace to its own sink — taint seeded from the *gin.Context
// parameter and carried through its Param/Query/PostForm accessors and its Request
// field, exactly as from a net/http handler's *http.Request — so
// attackerIngressInTrace finds an attacker-controllable ingress on it; and that the
// negatives' sinks get no path.
func TestGin_RouteIngressHeadsTaintTrace(t *testing.T) {
	var sinks []string
	for _, f := range ginForms {
		sinks = append(sinks, ginFixtureSCIP+f.sink+"().")
	}
	negSinks := []string{
		ginFixtureSCIP + "sinkNeverRegistered().",
		ginFixtureSCIP + "sinkMiddleware().",
		ginFixtureSCIP + "sinkLookalike().",
	}
	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: ginFixtureDir,
		Sinks:    append(sinks, negSinks...),
	})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	bySink := map[string]plugin.ReachPath{}
	for _, p := range res.Paths {
		bySink[p.Sink.SCIP] = p
	}
	for _, f := range ginForms {
		p, ok := bySink[ginFixtureSCIP+f.sink+"()."]
		if !ok {
			t.Errorf("gin %s: no taint path to %s; paths = %+v", f.form, f.sink, res.Paths)
			continue
		}
		want := ginFixtureSCIP + f.handler
		if p.Ingress.SCIP != want || len(p.Trace) == 0 || p.Trace[0].SCIP != want {
			t.Errorf("gin %s: path to %s has ingress %q trace %v, want %q at the trace head", f.form, f.sink, p.Ingress.SCIP, p.Trace, want)
		}
	}
	for _, s := range negSinks {
		if p, ok := bySink[s]; ok {
			t.Errorf("no gin-registered handler reaches %s, yet a path exists from %q", s, p.Ingress.SCIP)
		}
	}
}

// TestGin_ContextAccessorsCarryTaint proves every modeled *gin.Context accessor taints
// its result, and every Bind / ShouldBind* binder the target it decodes into, when
// called on the handler's tainted context: each reaches its own sink from
// accessorsForm. HandlerName, which reads no request data, does not.
func TestGin_ContextAccessorsCarryTaint(t *testing.T) {
	var sinks []string
	for _, a := range ginAccessors {
		sinks = append(sinks, ginFixtureSCIP+"sink"+a+"().")
	}
	neg := ginFixtureSCIP + "sinkNotRequestData()."
	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: ginFixtureDir,
		Sinks:    append(sinks, neg),
	})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	bySink := map[string]string{}
	for _, p := range res.Paths {
		bySink[p.Sink.SCIP] = p.Ingress.SCIP
	}
	want := ginFixtureSCIP + "server#accessorsForm()."
	for i, a := range ginAccessors {
		if got, ok := bySink[sinks[i]]; !ok || got != want {
			t.Errorf("gin %s: path to sink%s from %q (found %v), want from %q", a, a, got, ok, want)
		}
	}
	if got, ok := bySink[neg]; ok {
		t.Errorf("HandlerName reads no request data, yet sinkNotRequestData is reached from %q", got)
	}
}

// TestGin_HelperCalledTwiceRegistersUnderEachPrefix proves a route registered in a
// helper is composed under the prefix of every group a caller passes it — here a
// top-level group and one nested in /v1.
func TestGin_HelperCalledTwiceRegistersUnderEachPrefix(t *testing.T) {
	var got []string
	for _, in := range ginIngresses(t) {
		if in.Kind == "http_route" && in.Symbol.SCIP == ginFixtureSCIP+"server#twiceForm()." {
			got = append(got, in.Selector)
		}
	}
	if len(got) != 2 || got[0] != "/a/twice/:id" || got[1] != "/v1/b/twice/:id" {
		t.Errorf("twiceForm selectors = %q, want [/a/twice/:id /v1/b/twice/:id]", got)
	}
}

// TestGin_StaticIsNoIngress proves the file-serving registrars register no ingress:
// Static, StaticFile and StaticFS take no first-party handler, so neither the file
// system StaticFS serves (handler-shaped as it is) nor any selector they name
// surfaces.
func TestGin_StaticIsNoIngress(t *testing.T) {
	ingresses := ginIngresses(t)
	assertNoGinIngress(t, ingresses, "assetFS#ServeHTTP().")
	for _, in := range ingresses {
		switch in.Selector {
		case "/assets", "/favicon.ico", "/fs":
			t.Errorf("a Static* path is an ingress: %s (selector %q)", in.Symbol.SCIP, in.Selector)
		}
	}
}

// TestGin_UnregisteredHandlerIsNoIngress proves a handler-shaped func that no router
// registers — a method (reaching gin only through fwdRouter's forwarding) and a
// package-scope func(*gin.Context) — yields no ingress of any kind.
func TestGin_UnregisteredHandlerIsNoIngress(t *testing.T) {
	assertNoGinIngress(t, ginIngresses(t),
		"server#neverRegistered().",
		"unregisteredFunc().",
	)
}

// TestGin_MiddlewareIsNoIngress proves middleware is no route ingress: neither the
// engine's Use middleware nor the handler arguments of Group, which are the group's
// middleware. Both run for every route under them and register none of their own.
func TestGin_MiddlewareIsNoIngress(t *testing.T) {
	assertNoGinIngress(t, ginIngresses(t),
		"useMiddleware().",
		"groupMiddleware().",
	)
}

// TestGin_OwnHandlersAndAdaptersAreNoIngress proves no http_route ingress lies outside
// the fixture's own package: not gin's Engine.ServeHTTP (an engine mounted through
// WrapH: the gin-path clause), not the HandlerFunc adapter's ServeHTTP (a handler
// reaching WrapH as an http.HandlerFunc in a variable, through fwdRouter: the adapter
// clause), and not the closures gin's WrapF/WrapH build around what they wrap.
func TestGin_OwnHandlersAndAdaptersAreNoIngress(t *testing.T) {
	for _, in := range ginIngresses(t) {
		if in.Kind == "http_route" && !strings.HasPrefix(in.Symbol.SCIP, ginFixtureSCIP) {
			t.Errorf("http_route ingress outside the fixture: %s (selector %q)", in.Symbol.SCIP, in.Selector)
		}
	}
}

// TestGin_LookalikeRouterIsNoIngress proves the router is identified by its import
// path: a router with gin's package name, type and method names under another path
// registers nothing, through any form (verbs, Handle, Match, Group), and its WrapF
// look-alike on a real gin route resolves to no handler.
func TestGin_LookalikeRouterIsNoIngress(t *testing.T) {
	assertNoGinIngress(t, ginIngresses(t),
		"server#lookalikeGet().",
		"server#lookalikePost().",
		"server#lookalikeHandle().",
		"server#lookalikeMatch().",
		"server#lookalikeGroup().",
		"server#lookalikeNet().",
	)
}

func assertNoGinIngress(t *testing.T, ingresses []plugin.Ingress, handlers ...string) {
	t.Helper()
	for _, h := range handlers {
		for _, in := range ingresses {
			if in.Symbol.SCIP == ginFixtureSCIP+h {
				t.Errorf("%s must be no ingress; got Kind %q selector %q", h, in.Kind, in.Selector)
			}
		}
	}
}
