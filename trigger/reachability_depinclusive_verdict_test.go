package trigger

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
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
// resolves not_exploitable. The graph's only incompleteness is dynamic_dispatch, an
// inherent limit of static analysis (not a step that did not run), and the lane names
// the in-package sink as Searched, so the empty path set is a searched-negative, not an
// analysis that never happened.
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
	const sink = "jvmref com/example/net/UrlKit#get(Ljava/lang/String;)V"
	putJSON(t, store, aid, artifact.TypeNormalizedAdvisory, map[string]any{
		"module": "com.example:urlkit", "purl": "pkg:maven/com.example/urlkit@1.0.0",
		"advisory_symbols": []string{"com.example.net.UrlKit.get"}, "built_in": true,
	})
	putJSON(t, store, aid, artifact.TypeVulnerableSymbol, plugin.SymbolResolutionResult{
		Partiality: plugin.Complete(),
		Resolved:   []plugin.Symbol{{SCIP: sink}},
		Origins:    map[string]string{sink: "pkg:maven/com.example/urlkit"},
		Matched:    map[string][]string{"com.example.net.UrlKit.get": {sink}},
	})
	reach := plugin.ReachabilityResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Searched:   []string{sink},
	}
	seedReachArtifact(t, store, aid, cg, reach)

	pkg := &report.Package{Ecosystem: "Maven", Name: "com.example:urlkit", Version: "1.0.0", PURL: "pkg:maven/com.example/urlkit@1.0.0"}
	f := finding(store, aid, report.Advisory{ID: "FERRALON-JAVA-SSRF-0002", Source: "corpus"}, pkg)
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

	f := finding(store, aid, report.Advisory{ID: "FERRALON-JAVA-SSRF-0002", Source: "corpus"}, nil)
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

// A step that did not run holds the row wherever the lane declares it, including only on a call
// graph that has edges. The footprint is built by the real stage, so a footprint that stops
// harvesting the call graph fails here. A coordinate a complete build graph lacks is bounded to
// that package: it leaves the row for a package the build does ship alone, while the same
// coordinate missing beside an incomplete graph still holds it.
func TestFinding_CallGraphDidNotRunHoldsTheRow(t *testing.T) {
	const sink = "jvmref com/example/net/UrlKit#get(Ljava/lang/String;)V"
	unbounded := plugin.Partiality{Scoped: []plugin.ScopedReason{{Reason: plugin.PartialReasonToolFailure, Package: "pkg:maven/com.example/urlkit", Path: "lib"}}}
	tests := []struct {
		name        string
		cg          plugin.Partiality
		sym         plugin.Partiality
		wantVerdict report.Verdict
	}{
		{"an inherent limit on the graph", plugin.Partial(plugin.PartialReasonDynamicDispatch), plugin.Partiality{}, report.VerdictNotExploitable},
		{"a did-not-run reason on the graph", plugin.Partial(plugin.PartialReasonDynamicDispatch, plugin.PartialReasonToolFailure), plugin.Partiality{}, report.VerdictUndetermined},
		{"an unbounded scoped did-not-run limit on the graph", unbounded, plugin.Partiality{}, report.VerdictUndetermined},
		{"another coordinate absent from a complete build graph", plugin.Partial(plugin.PartialReasonDynamicDispatch),
			javaanalysis.NotInBuild("com.evil:netkit"), report.VerdictNotExploitable},
		{"another coordinate absent beside an incomplete build graph", plugin.Partial(plugin.PartialReasonDynamicDispatch),
			plugin.Partiality{Reasons: []string{"no_dependency_artifact"}, Scoped: []plugin.ScopedReason{{Reason: "no_dependency_artifact", Package: "pkg:maven/com.evil/netkit", Path: "com.evil:netkit"}}},
			report.VerdictUndetermined},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := assessment.NewMemStore().Create(assessment.Request{Vulnerability: assessment.VulnRef{ID: "FERRALON-JAVA-SSRF-0002"}})
			if err != nil {
				t.Fatal(err)
			}
			store := artifact.NewMemStore()
			putJSON(t, store, a.ID, artifact.TypeNormalizedAdvisory, map[string]any{
				"module": "com.example:urlkit", "purl": "pkg:maven/com.example/urlkit@1.0.0",
				"advisory_symbols": []string{"com.example.net.UrlKit.get"}, "built_in": true,
			})
			sym := tt.sym
			if sym.Reasons == nil && sym.Scoped == nil {
				sym = plugin.Complete()
			}
			putJSON(t, store, a.ID, artifact.TypeVulnerableSymbol, plugin.SymbolResolutionResult{
				Partiality: sym,
				Resolved:   []plugin.Symbol{{SCIP: sink}},
				Origins:    map[string]string{sink: "pkg:maven/com.example/urlkit"},
				Matched:    map[string][]string{"com.example.net.UrlKit.get": {sink}},
			})
			cg := plugin.CallGraphResult{
				Algorithm:  "source-lexical",
				Partiality: tt.cg,
				Edges:      []plugin.CallEdge{depEdge("jvmref com/example/net/UrlKit#entry()V", sink)},
			}
			seedReachArtifact(t, store, a.ID, cg, plugin.ReachabilityResult{
				Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
				Searched:   []string{sink},
			})
			if err := pipeline.NewExposureFootprint().Run(context.Background(), a, store); err != nil {
				t.Fatal(err)
			}

			pkg := &report.Package{Ecosystem: "Maven", Name: "com.example:urlkit", Version: "1.0.0", PURL: "pkg:maven/com.example/urlkit@1.0.0"}
			f := finding(store, a.ID, report.Advisory{ID: "FERRALON-JAVA-SSRF-0002", Source: "corpus"}, pkg)
			if f.Verdict != tt.wantVerdict {
				t.Fatalf("verdict = %q (%s), want %q", f.Verdict, f.UndeterminedReason, tt.wantVerdict)
			}
		})
	}
}
