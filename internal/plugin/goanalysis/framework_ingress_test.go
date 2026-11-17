// Hermetic goanalysis tests for framework ingress detection (ingress_frameworks.go).
// They load a real fixture (frameworkmod) with the Go toolchain — no live model, no
// Docker, no network: the fixture's go.mod replaces beego, go-restful,
// gorilla/websocket and gRPC with local stubs so the detector matches the package
// paths without fetching the real modules.
//
// They prove every registration form surfaces its handler as an ingress of an
// attacker-controllable kind that heads the taint trace to that form's sink (the
// trace attackerIngressInTrace matches against), and that the detector does not
// over-fire: methods no mapping names, methods only inherited from the framework,
// handlers registered nowhere and handlers registered on look-alike registrars are no
// ingress at all.
package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	frameworkFixtureDir = "testdata/frameworkmod"
	// frameworkFixtureSCIP prefixes the SCIP id of a func or method declared in
	// frameworkmod's main package.
	frameworkFixtureSCIP = "scip-go gomod tegron.test/frameworkmod . tegron.test/frameworkmod/"
)

// frameworkForms lists each registration form with the handler it registers (as the
// tail of its SCIP id), the ingress kind and selector it gets, and the sink only that
// handler reaches.
var frameworkForms = []struct {
	form, handler, kind, selector, sink string
}{
	{"beego Router mapping", "AuthController#Login().", "http_route", "/api/login", "sinkBeegoMapped"},
	{"beego Router multi-verb mapping", "MultiController#Multi().", "http_route", "/api/multi", "sinkBeegoMulti"},
	{"beego Router second mapping entry", "MultiController#Logout().", "http_route", "/api/multi", "sinkBeegoLogout"},
	{"beego Router without mapping", "RESTController#Get().", "http_route", "/api/rest", "sinkBeegoREST"},
	{"beego Router non-constant mapping", "DynController#Anything().", "http_route", "/api/dyn", "sinkBeegoDyn"},
	{"beego Include", "IncController#Annotated().", "http_route", "", "sinkBeegoInclude"},
	{"beego AutoRouter", "AutoController#Auto().", "http_route", "", "sinkBeegoAuto"},
	{"beego ControllerRegister.Add", "AddController#Get().", "http_route", "/api/add", "sinkBeegoAdd"},
	{"beego ControllerRegister.Add with an option", "OptController#Opted().", "http_route", "/api/opt", "sinkBeegoOpts"},
	{"beego Prepare of a routed controller", "AuthController#Prepare().", "http_route", "/api/login", "sinkBeegoPrepare"},
	{"beego HttpServer.Router", "ServerController#Served().", "http_route", "/api/server", "sinkBeegoServer"},
	{"beego NSRouter", "NSController#NSRouted().", "http_route", "/ns", "sinkBeegoNSRouter"},
	{"beego NSInclude", "NSIncController#Included().", "http_route", "", "sinkBeegoNSInclude"},
	{"beego Namespace.Router", "NSController#NSMethod().", "http_route", "/nsm", "sinkBeegoNSMethod"},
	{"beego Get", "beegoFunc().", "http_route", "/func", "sinkBeegoFunc"},
	{"beego NSGet", "beegoNSGet().", "http_route", "/nsget", "sinkBeegoNSGet"},
	{"beego CtrlGet method expression", "CtrlController#Expr().", "http_route", "/ctrl", "sinkBeegoCtrl"},
	{"beego AddMethod", "beegoAddMethod().", "http_route", "/addmethod", "sinkBeegoAddMethod"},
	{"beego InsertFilter", "beegoFilter().", "http_route", "*", "sinkBeegoFilter"},
	{"beego NSBefore", "beegoNSBefore().", "http_route", "", "sinkBeegoNSBefore"},
	{"beego Handler", "beegoHandler#ServeHTTP().", "http_route", "/handler", "sinkBeegoHandler"},
	{"go-restful verb To", "server#restGet().", "http_route", "/nodes/{id}", "sinkRestGet"},
	{"go-restful Method Path To", "restMethod().", "http_route", "/put/{id}", "sinkRestMethod"},
	{"go-restful WebService.Filter", "restFilter().", "http_route", "", "sinkRestFilter"},
	{"go-restful RouteBuilder.Filter", "restRouteFilter().", "http_route", "", "sinkRestRouteFilter"},
	{"go-restful Container.Filter", "restContainerFilter().", "http_route", "", "sinkRestContainer"},
	{"go-restful Container.Handle", "restHandler#ServeHTTP().", "http_route", "/raw", "sinkRestHandle"},
	{"websocket Upgrader.Upgrade", "server#wsForm().", "handler", "", "sinkWS"},
	{"websocket Upgrade func", "server#wsLegacy().", "handler", "", "sinkWSLegacy"},
	{"gRPC Register on a registrar", "echoSvc#Echo().", "grpc", "Echo/Echo", "sinkGRPC"},
	{"gRPC Register on *grpc.Server", "legacySvc#Old().", "grpc", "Legacy/Old", "sinkGRPCLegacy"},
}

func frameworkIngresses(t *testing.T) []plugin.Ingress {
	t.Helper()
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: frameworkFixtureDir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	return res.Ingresses
}

// TestFramework_RegistrationFormsAreIngresses proves each form's handler surfaces as
// an ingress of its kind — one attackerControllableKinds covers — with the selector
// the registration carries.
func TestFramework_RegistrationFormsAreIngresses(t *testing.T) {
	type ks struct{ kind, selector string }
	got := map[string][]ks{}
	for _, in := range frameworkIngresses(t) {
		got[in.Symbol.SCIP] = append(got[in.Symbol.SCIP], ks{in.Kind, in.Selector})
	}
	for _, f := range frameworkForms {
		found := false
		for _, g := range got[frameworkFixtureSCIP+f.handler] {
			if g.kind == f.kind && g.selector == f.selector {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: handler %s = %v, want kind %q selector %q", f.form, f.handler, got[frameworkFixtureSCIP+f.handler], f.kind, f.selector)
		}
	}
}

// TestFramework_IngressHeadsTaintTrace proves each form's handler is the ingress at
// the head of the taint trace to its own sink, and that the negatives' sinks get no
// path.
func TestFramework_IngressHeadsTaintTrace(t *testing.T) {
	var sinks []string
	for _, f := range frameworkForms {
		sinks = append(sinks, frameworkFixtureSCIP+f.sink+"().")
	}
	negSinks := []string{frameworkFixtureSCIP + "sinkNeverRegistered().", frameworkFixtureSCIP + "sinkLookalike()."}
	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: frameworkFixtureDir,
		Sinks:    append(sinks, negSinks...),
	})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	bySink := map[string]plugin.ReachPath{}
	for _, p := range res.Paths {
		bySink[p.Sink.SCIP] = p
	}
	for _, f := range frameworkForms {
		p, ok := bySink[frameworkFixtureSCIP+f.sink+"()."]
		if !ok {
			t.Errorf("%s: no taint path to %s", f.form, f.sink)
			continue
		}
		want := frameworkFixtureSCIP + f.handler
		if p.Ingress.SCIP != want || len(p.Trace) == 0 || p.Trace[0].SCIP != want {
			t.Errorf("%s: path to %s has ingress %q trace %v, want %q at the trace head", f.form, f.sink, p.Ingress.SCIP, p.Trace, want)
		}
	}
	for _, s := range negSinks {
		if p, ok := bySink[s]; ok {
			t.Errorf("no registered handler reaches %s, yet a path exists from %q", s, p.Ingress.SCIP)
		}
	}
}

// TestFramework_UnregisteredAndInheritedAreNoIngress proves the detector's limits: a
// controller method no mapping names, a method beside the REST verbs on an unmapped
// controller, a controller, handler and service registered nowhere, an exported
// method outside the service interface, and every handler registered on a look-alike
// registrar yield no ingress of any kind.
func TestFramework_UnregisteredAndInheritedAreNoIngress(t *testing.T) {
	ingresses := map[string]string{}
	for _, in := range frameworkIngresses(t) {
		ingresses[in.Symbol.SCIP] = in.Kind
	}
	for _, tail := range []string{
		"AuthController#NotMapped().",
		"RESTController#Helper().",
		"AddController#Added().",
		"AutoController#Helper().",
		"OptController#Helper().",
		"NeverController#Get().",
		"beegoUnused().",
		"server#restNever().",
		"echoSvc#Internal().",
		"neverSvc#Echo().",
		"lookController#Get().",
		"lookFilter().",
		"lookRoute().",
		"lookSvc#Do().",
		"lookUpgrade().",
	} {
		if kind, ok := ingresses[frameworkFixtureSCIP+tail]; ok {
			t.Errorf("%s is an ingress of kind %q, want none", tail, kind)
		}
	}
}

// TestFramework_NoIngressOutsideTheFixture proves no route or service ingress lies in
// a framework or generated package: neither the base controller's inherited methods,
// the Unimplemented service's, nor a framework's own callers of its registrars.
func TestFramework_NoIngressOutsideTheFixture(t *testing.T) {
	for _, in := range frameworkIngresses(t) {
		if in.Kind != "main" && !strings.HasPrefix(in.Symbol.SCIP, frameworkFixtureSCIP) {
			t.Errorf("%s ingress outside the fixture: %s (selector %q)", in.Kind, in.Symbol.SCIP, in.Selector)
		}
	}
}

// TestFramework_PatternedRouteSupersedesImplied proves a handler routed once by
// pattern and again by a registration carrying none (Router, then Include) is listed
// under its pattern only.
func TestFramework_PatternedRouteSupersedesImplied(t *testing.T) {
	var selectors []string
	for _, in := range frameworkIngresses(t) {
		if in.Symbol.SCIP == frameworkFixtureSCIP+"MultiController#Multi()." {
			selectors = append(selectors, in.Selector)
		}
	}
	if len(selectors) != 1 || selectors[0] != "/api/multi" {
		t.Errorf("MultiController#Multi selectors = %q, want only /api/multi", selectors)
	}
}
