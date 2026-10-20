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
	"testing"

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
// registers — a method and a package-scope func — yields no ingress of any kind.
func TestChi_UnregisteredHandlerIsNoIngress(t *testing.T) {
	assertNoChiIngress(t, chiIngresses(t), "server#neverRegistered().", "unregisteredFunc().")
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
