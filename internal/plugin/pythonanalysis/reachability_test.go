package pythonanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestReachability_IngressToSinkPathIsAlwaysPartial is the LOAD-BEARING honesty proof: the
// real lexical reachability connects the Flask route ingress (handle_fetch) through the
// utility hops (handle → fetch_url) to the sink (open_conn), emitting the ingress→sink
// trace — AND declares Partial(dynamic_dispatch) even though a path WAS found. Python
// static reachability is a candidate narrower, never an adjudicator, so it must NEVER
// return Complete (the critical difference from Java).
func TestReachability_IngressToSinkPathIsAlwaysPartial(t *testing.T) {
	dir := writeTree(t, map[string]string{"app.py": flaskApp})
	sink := funcSCIP("app", nil, "open_conn", 1)

	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("want exactly one reach path to the sink, got %d: %+v", len(res.Paths), res.Paths)
	}
	p := res.Paths[0]
	if p.Sink.SCIP != sink {
		t.Fatalf("path sink = %q, want %q", p.Sink.SCIP, sink)
	}
	if p.Ingress.SCIP == "" {
		t.Fatal("path must carry a non-empty ingress (the route handler entry)")
	}
	if p.Ingress.SCIP != p.Trace[0].SCIP {
		t.Fatalf("ingress %q must be the first trace frame %q", p.Ingress.SCIP, p.Trace[0].SCIP)
	}
	if p.Trace[len(p.Trace)-1].SCIP != sink {
		t.Fatalf("final trace frame must be the sink; got %q", p.Trace[len(p.Trace)-1].SCIP)
	}
	if len(p.Trace) < 3 {
		t.Fatalf("expected the multi-hop trace handle_fetch->handle->fetch_url->open_conn; got %v", p.Trace)
	}
	// The critical Python invariant: a reachable path is STILL Partial (never Complete).
	if res.Partiality.Complete {
		t.Fatal("Python reachability must NEVER return Complete, even when a path is found (structurally weak)")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Fatalf("Python reachability must always carry dynamic_dispatch; got %v", res.Partiality.Reasons)
	}
}

// TestReachability_NotReachedIsUnknownNeverSafe proves the inv.5 boundary: a sink no
// ingress/root reaches over the call graph yields NO path AND declares Partial
// (no_known_ingress + dynamic_dispatch) — an unreached sink is UNKNOWN, never a confident
// "not reachable"/"safe".
func TestReachability_NotReachedIsUnknownNeverSafe(t *testing.T) {
	src := `
@app.route('/ok')
def route():
    return harmless(1)

def harmless(x):
    return x

def orphan_sink(u):
    return u
`
	dir := writeTree(t, map[string]string{"clean.py": src})
	sink := funcSCIP("clean", nil, "orphan_sink", 1)

	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 0 {
		t.Fatalf("an unreached sink must yield NO resolved path; got %+v", res.Paths)
	}
	if res.Partiality.Complete {
		t.Fatal("an unreached sink must be Partial, never a confident not-reachable")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoIngress) {
		t.Fatalf("an unreached sink must declare no_known_ingress (UNKNOWN, never safe); got %v", res.Partiality.Reasons)
	}
}

func TestReachability_MissingBuildDirIsHardError(t *testing.T) {
	_, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: "testdata/does-not-exist",
		Symbols:  []string{"whatever"},
	})
	if err == nil {
		t.Fatal("a load failure in the call graph must be a hard error (inv.4), not partiality")
	}
}

// TestReachability_FlaskRouteToBoundaryNode: `import jwt; jwt.decode(t)` inside a Flask
// route yields a reach path from the route ingress to the pyjwt boundary node once the
// advisory symbol resolves onto it. The node is never listed as searched, and an unreached
// boundary node stays UNKNOWN (no_known_ingress).
func TestReachability_FlaskRouteToBoundaryNode(t *testing.T) {
	src := `
import jwt
from flask import Flask, request
app = Flask(__name__)

@app.route('/me')
def me():
    return load_claims(request.args['t'])

def load_claims(t):
    return jwt.decode(t)

def unused(t):
    return jwt.api_jws._verify_signature(t)
`
	dir := writeTree(t, map[string]string{"app.py": src})
	resolved, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        dir,
		PURL:            "pkg:pypi/pyjwt@2.8.0",
		AdvisorySymbols: []string{"jwt.decode"},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(resolved.Resolved) != 1 || resolved.Resolved[0].SCIP != "pypi:pyjwt#jwt.decode" {
		t.Fatalf("resolved = %+v, want the pyjwt boundary node", resolved.Resolved)
	}
	sink := resolved.Resolved[0].SCIP

	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("want one reach path to the boundary node, got %+v", res.Paths)
	}
	p := res.Paths[0]
	if want := funcSCIP("app", nil, "me", 0); p.Ingress.SCIP != want {
		t.Fatalf("ingress = %q, want the route handler %q", p.Ingress.SCIP, want)
	}
	if p.Trace[len(p.Trace)-1].SCIP != sink {
		t.Fatalf("trace must end at the boundary node; got %v", p.Trace)
	}
	if len(res.Searched) != 0 {
		t.Fatalf("boundary nodes are never searched; got %v", res.Searched)
	}

	// A boundary node no ingress or root reaches stays UNKNOWN.
	unreached := "pypi:pyjwt#jwt.api_jws._verify_signature"
	res, err = Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{unreached}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 0 || !hasReason(res.Partiality, plugin.PartialReasonNoIngress) || len(res.Searched) != 0 {
		t.Fatalf("unreached boundary node must be no path + no_known_ingress + not searched; got paths=%v reasons=%v searched=%v", res.Paths, res.Partiality.Reasons, res.Searched)
	}
}

// TestReachability_PrefersIngressOverModuleInitRoot: a helper called both by module-level
// code and by a route handler resolves to the route ingress, not the closer-or-equal
// module-init root.
func TestReachability_PrefersIngressOverModuleInitRoot(t *testing.T) {
	src := `
import jwt

@app.route('/x')
def handler():
    return helper(1)

def helper(t):
    return jwt.decode(t)

warm = helper(0)
`
	dir := writeTree(t, map[string]string{"app.py": src})
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{"pypi:pyjwt#jwt.decode"}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 1 || res.Paths[0].Ingress.SCIP != funcSCIP("app", nil, "handler", 0) {
		t.Fatalf("want the route-ingress path, got %+v", res.Paths)
	}
}

// TestReachability_TestCodeIsNotARoot: module-level code in test files runs under the test
// runner, never at runtime, so its module-init node is not a root and yields no path.
func TestReachability_TestCodeIsNotARoot(t *testing.T) {
	src := "import jwt\n\nTOKEN = jwt.decode('x')\n"
	cases := []struct {
		file     string
		wantPath bool
	}{
		{"tests/test_tok.py", false},
		{"test/tok.py", false},
		{"pkg/tests/helpers.py", false},
		{"test_tok.py", false},
		{"pkg/tok_test.py", false},
		{"conftest.py", false},
		{"tests.py", false},
		{"pkg/test.py", false},
		{"pkg/tok.py", true},
		{"pkg/testing.py", true},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			dir := writeTree(t, map[string]string{c.file: src})
			res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{"pypi:pyjwt#jwt.decode"}})
			if err != nil {
				t.Fatalf("Reachability: %v", err)
			}
			if got := len(res.Paths) > 0; got != c.wantPath {
				t.Fatalf("path present = %v, want %v; paths %+v", got, c.wantPath, res.Paths)
			}
		})
	}
}
