package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// seedReachArtifact writes the reachability artifact in the exact shape the pipeline
// persists (call_graph + reachability legs), so finding() reads it as it would in a
// real run.
func seedReachArtifact(t *testing.T, store artifact.Store, aid string, cg plugin.CallGraphResult, reach plugin.ReachabilityResult) {
	t.Helper()
	putJSON(t, store, aid, artifact.TypeReachability, struct {
		Reachability plugin.ReachabilityResult `json:"reachability"`
		CallGraph    plugin.CallGraphResult    `json:"call_graph"`
	}{Reachability: reach, CallGraph: cg})
}

// depEdge is a dependency-closure call edge in the jvmref scheme the dependency-
// inclusive CallGraph emits (see javaanalysis.depEdgeSymbol).
func depEdge(caller, callee string) plugin.CallEdge {
	return plugin.CallEdge{Caller: plugin.Symbol{SCIP: caller}, Callee: plugin.Symbol{SCIP: callee}}
}

// TestFinding_DependencyInclusiveGraphYieldsNotExploitable is the PLAN-040 G verdict:
// the SSRF-0002 shape — a sink present in the closure but with NO reaching path, over
// a graph that carries edges proving the code was actually opened and searched —
// resolves not_exploitable. The dependency-inclusive edges are what supply that proof:
// the graph's only incompleteness is dynamic_dispatch, an inherent limit of static
// analysis (not a step that did not run), so the empty path set is a searched-negative,
// not an analysis that never happened.
func TestFinding_DependencyInclusiveGraphYieldsNotExploitable(t *testing.T) {
	store := artifact.NewMemStore()
	const aid = "ssrf0002"

	cg := plugin.CallGraphResult{
		Algorithm:  "source-lexical",
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch), // library calls only — inherent limit
		Edges: []plugin.CallEdge{
			depEdge("jvmref com/example/net/UrlKit#entry()V", "jvmref com/example/net/UrlKit#get(Ljava/lang/String;)V"),
		},
	}
	// The advisory sink is present but unreached: no candidate path.
	reach := plugin.ReachabilityResult{Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch)}
	seedReachArtifact(t, store, aid, cg, reach)

	f := finding(store, aid, report.Advisory{ID: "TEGRON-JAVA-SSRF-0002", Source: "corpus"}, nil)
	if f.Verdict != report.VerdictNotExploitable {
		t.Fatalf("verdict = %q, want %q — a searched COMPLETE-enough graph with no reaching path refutes",
			f.Verdict, report.VerdictNotExploitable)
	}
	if f.Evidence.Basis != verdict.BasisSymbolAbsent {
		t.Errorf("basis = %q, want %q", f.Evidence.Basis, verdict.BasisSymbolAbsent)
	}
}

// TestFinding_EmptyGraphYieldsUndetermined pins the pre-fix shape and the boundary the
// dependency-inclusive edges cross: with NO edges and a partial graph, the refutation
// has no searched structure to rest on, so finding() must return undetermined
// (analysis_did_not_run), never not_exploitable. This is the exact state SSRF-0002
// produced before (d.2) — an empty first-party graph (App's only calls are to
// libraries) — and the reason the honest verdict was undetermined until the opened
// dependency closure supplied edges.
func TestFinding_EmptyGraphYieldsUndetermined(t *testing.T) {
	store := artifact.NewMemStore()
	const aid = "ssrf0002-empty"

	cg := plugin.CallGraphResult{
		Algorithm:  "source-lexical",
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		// No edges: the analysis declined to call the graph complete AND has nothing in it.
	}
	reach := plugin.ReachabilityResult{Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch)}
	seedReachArtifact(t, store, aid, cg, reach)

	f := finding(store, aid, report.Advisory{ID: "TEGRON-JAVA-SSRF-0002", Source: "corpus"}, nil)
	if f.Verdict != report.VerdictUndetermined {
		t.Fatalf("verdict = %q, want %q — an empty partial graph is a refutation with nothing under it",
			f.Verdict, report.VerdictUndetermined)
	}
	if f.UndeterminedReason != report.ReasonAnalysisDidNotRun {
		t.Errorf("undetermined_reason = %q, want %q", f.UndeterminedReason, report.ReasonAnalysisDidNotRun)
	}
	if f.Evidence.Basis != "" {
		t.Errorf("basis = %q, want empty on an undetermined verdict", f.Evidence.Basis)
	}
}
