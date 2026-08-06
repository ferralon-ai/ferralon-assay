package goanalysis

import (
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// scipID builds a recognizable synthetic SCIP-shaped id for the test frames so
// the derivation is exercised with strings that look like the real emitter's
// output without depending on a loaded program.
func scipID(pkg, sym string) string {
	return "scip-go gomod " + pkg + " v1.0.0 " + pkg + "/" + sym + "()."
}

// TestParseFindings_FiltersByGovulnGoID pins a load-bearing contract: the
// vulnID parseFindings filters by is govulncheck's own finding key, which is ALWAYS the
// advisory's GO-YYYY-NNNN id (the `osv` field of every finding) — NEVER its CVE/GHSA primary
// id. A govulncheck stream keyed GO-2024-3321 is kept only when the requested id is that same
// GO- id (or empty); requesting the CVE id (CVE-2024-45337) drops EVERY finding. That drop is
// the whole defect this pins against: it silently forces a CVE/GHSA-keyed advisory off the reachable path
// AND empties findings so reconcile()'s notReachable (findings>0 && paths==0) can never fire —
// bypassing inv.5's fail-open. Resolving the primary id to its GO- alias (govulnMatchID, pipeline
// side) is exactly what makes the GO-keyed branch below the one that runs in production.
func TestParseFindings_FiltersByGovulnGoID(t *testing.T) {
	// A minimal govulncheck -json stream: one symbol-level finding whose `osv` is the GO- id,
	// as govulncheck emits it for CVE-2024-45337 (golang.org/x/crypto/ssh).
	const stream = `{"finding":{"osv":"GO-2024-3321","trace":[{"module":"golang.org/x/crypto","package":"golang.org/x/crypto/ssh","function":"PublicKeyCallback"}]}}` + "\n"

	cases := []struct {
		name    string
		vulnID  string
		wantLen int
	}{
		{"GO- id matches (the resolved production id)", "GO-2024-3321", 1},
		{"CVE primary id drops everything (the bug)", "CVE-2024-45337", 0},
		{"GHSA alias drops everything too", "GHSA-v778-237x-gjrc", 0},
		{"empty id keeps all findings", "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := parseFindings([]byte(stream), tc.vulnID)
			if err != nil {
				t.Fatalf("parseFindings(%q) error: %v", tc.vulnID, err)
			}
			if len(findings) != tc.wantLen {
				t.Errorf("parseFindings(%q): got %d finding(s), want %d", tc.vulnID, len(findings), tc.wantLen)
			}
		})
	}
}

// TestStacksToReachPaths_MapsSinkIngressTrace asserts that a call stack ordered
// ingress->sink maps to a ReachPath whose Sink is the bottom frame, whose
// Ingress is the top (entry) frame, and whose Trace is the ordered SCIP ids.
func TestStacksToReachPaths_MapsSinkIngressTrace(t *testing.T) {
	main := scipID("tegron.test/fixturemod", "main")
	handle := scipID("tegron.test/fixturemod/service", "Handle")
	sink := scipID("example.com/vuln", "Sink")

	stacks := []CallStack{{
		Frames: []StackFrame{
			{SCIP: main, IsEntry: true},
			{SCIP: handle},
			{SCIP: sink},
		},
	}}

	paths := stacksToReachPaths(stacks)
	if len(paths) != 1 {
		t.Fatalf("want 1 path, got %d: %+v", len(paths), paths)
	}
	p := paths[0]
	if p.Sink != sink {
		t.Errorf("Sink: want %q (bottom of stack), got %q", sink, p.Sink)
	}
	if p.Ingress != main {
		t.Errorf("Ingress: want %q (top entry frame), got %q", main, p.Ingress)
	}
	wantTrace := []string{main, handle, sink}
	if !reflect.DeepEqual(p.Trace, wantTrace) {
		t.Errorf("Trace: want %v, got %v", wantTrace, p.Trace)
	}
}

// TestStacksToReachPaths_EmptyIngressWhenNoEntry asserts a reachable sink with no
// recognized entry point yields an empty Ingress (which feeds the nil-Ingress
// CandidatePair later) while the sink and trace are still populated.
func TestStacksToReachPaths_EmptyIngressWhenNoEntry(t *testing.T) {
	mid := scipID("example.com/dep", "Middle")
	sink := scipID("example.com/vuln", "Sink")

	stacks := []CallStack{{
		Frames: []StackFrame{
			{SCIP: mid}, // not an entry
			{SCIP: sink},
		},
	}}

	paths := stacksToReachPaths(stacks)
	if len(paths) != 1 {
		t.Fatalf("want 1 path, got %d", len(paths))
	}
	if paths[0].Ingress != "" {
		t.Errorf("Ingress: want empty (no known entry), got %q", paths[0].Ingress)
	}
	if paths[0].Sink != sink {
		t.Errorf("Sink: want %q, got %q", sink, paths[0].Sink)
	}
}

// TestStacksToReachPaths_SkipsEmptyStacks asserts stacks with no frames produce
// no path (module/package-level govulncheck findings carry no symbol trace).
func TestStacksToReachPaths_SkipsEmptyStacks(t *testing.T) {
	paths := stacksToReachPaths([]CallStack{{Frames: nil}, {Frames: []StackFrame{}}})
	if len(paths) != 0 {
		t.Fatalf("want 0 paths for empty stacks, got %d: %+v", len(paths), paths)
	}
}

// TestReconcile_TraceConsistentWithCallGraph asserts that when every adjacent
// pair in a derived trace is an edge in the call graph, reconciliation keeps the
// result Complete (no spurious partiality added).
func TestReconcile_TraceConsistentWithCallGraph(t *testing.T) {
	main := scipID("m", "main")
	handle := scipID("m/service", "Handle")
	sink := scipID("v", "Sink")

	paths := []plugin.ReachPath{{
		Sink:    sink,
		Ingress: main,
		Trace:   []string{main, handle, sink},
	}}
	cg := plugin.CallGraphResult{
		Partiality: plugin.Complete(),
		Edges: []plugin.CallEdge{
			{Caller: main, Callee: handle},
			{Caller: handle, Callee: sink},
		},
	}

	part := reconcile(paths, cg, false)
	if !part.Complete {
		t.Errorf("consistent trace should stay Complete, got %+v", part)
	}
}

// TestReconcile_AsymmetryNotReachableIsPartialNeverSafe is the load-bearing inv.5
// assertion: when govulncheck reported nothing reachable (notReachable=true), the
// reconciliation records declared partiality with the reachability-undetermined
// reason — it NEVER asserts "safe"/"unreachable". A miss is unknown, not safe.
//
// The reason must NOT be reflection/dynamic_dispatch: those name inherent limits of
// the method and render quietly (report.ClassifyPartialityReason); an undetermined
// result is specific to this run and must render loud (B-1).
func TestReconcile_AsymmetryNotReachableIsPartialNeverSafe(t *testing.T) {
	cg := plugin.CallGraphResult{Partiality: plugin.Complete()}

	part := reconcile(nil, cg, true)

	if part.Complete {
		t.Fatal("a govulncheck miss must NOT be reported as a complete/safe result (inv.5)")
	}
	if !hasReason(part.Reasons, plugin.PartialReasonReachabilityUndetermined) {
		t.Errorf("a miss must carry the reachability-undetermined reason (unknown, not safe); got %v", part.Reasons)
	}
	if hasReason(part.Reasons, plugin.PartialReasonReflection) || hasReason(part.Reasons, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("a miss must not be reported under the quiet reflection/dynamic_dispatch codes; got %v", part.Reasons)
	}
	for _, r := range part.Reasons {
		if r == "safe" || r == "unreachable" || r == "not_reachable" {
			t.Errorf("must never emit a safe/unreachable reason code; got %q", r)
		}
	}
}

// TestReconcile_InconsistentTraceDeclaresPartial asserts that a trace whose
// adjacent frames are NOT call-graph edges degrades partiality (the graphs
// disagree, which is an unknown gap, not silently accepted).
func TestReconcile_InconsistentTraceDeclaresPartial(t *testing.T) {
	main := scipID("m", "main")
	sink := scipID("v", "Sink")

	paths := []plugin.ReachPath{{
		Sink:    sink,
		Ingress: main,
		Trace:   []string{main, sink}, // no edge main->sink in the graph
	}}
	cg := plugin.CallGraphResult{
		Partiality: plugin.Complete(),
		Edges:      []plugin.CallEdge{{Caller: main, Callee: scipID("m", "Other")}},
	}

	part := reconcile(paths, cg, false)
	if part.Complete {
		t.Errorf("an inconsistent trace should declare partiality, got Complete")
	}
	if !hasReason(part.Reasons, plugin.PartialReasonReachabilityUndetermined) {
		t.Errorf("a graph-uncorroborated trace is an unknown gap and must carry reachability_undetermined; got %v", part.Reasons)
	}
}

// TestReconcile_IncompleteGraphNoReasonsIsUndetermined covers the third mint site: a
// call graph that is itself incomplete but declared no explicit reasons. The cause is
// unknown, so it must carry the undetermined code, not the quiet reflection/
// dynamic_dispatch codes (B-1).
func TestReconcile_IncompleteGraphNoReasonsIsUndetermined(t *testing.T) {
	cg := plugin.CallGraphResult{Partiality: plugin.Partiality{Complete: false}}

	part := reconcile(nil, cg, false)

	if !hasReason(part.Reasons, plugin.PartialReasonReachabilityUndetermined) {
		t.Errorf("an incomplete graph with no explicit reasons must carry reachability_undetermined; got %v", part.Reasons)
	}
	if hasReason(part.Reasons, plugin.PartialReasonReflection) || hasReason(part.Reasons, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("must not be reported under the quiet reflection/dynamic_dispatch codes; got %v", part.Reasons)
	}
}

// TestReconcile_CarriesCallGraphPartiality asserts the call graph's own declared
// partiality reasons flow through into the reconciled result.
func TestReconcile_CarriesCallGraphPartiality(t *testing.T) {
	cg := plugin.CallGraphResult{Partiality: plugin.Partial(plugin.PartialReasonCgo)}
	part := reconcile(nil, cg, false)
	if !hasReason(part.Reasons, plugin.PartialReasonCgo) {
		t.Errorf("call-graph partiality (cgo) should propagate; got %v", part.Reasons)
	}
}

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}
