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
	if p.Sink != sink {
		t.Fatalf("path sink = %q, want %q", p.Sink, sink)
	}
	if p.Ingress == "" {
		t.Fatal("path must carry a non-empty ingress (the route handler entry)")
	}
	if p.Ingress != p.Trace[0] {
		t.Fatalf("ingress %q must be the first trace frame %q", p.Ingress, p.Trace[0])
	}
	if p.Trace[len(p.Trace)-1] != sink {
		t.Fatalf("final trace frame must be the sink; got %q", p.Trace[len(p.Trace)-1])
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
