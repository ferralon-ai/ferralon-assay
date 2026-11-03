package trigger

import (
	"fmt"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// The handler → helper → helper2 → sink shape: taint reaches the sink from handlerA, and its
// path records only [handlerA, sink]. The frames the report shows come from a reachability path
// that reaches the same sink, else from the call graph, while the entry point stays the one
// taint credits.
const (
	traceMain    = "scip-go gomod example.com/m . example.com/m/main()."
	traceA       = "scip-go gomod example.com/m . example.com/m/handlerA()."
	traceB       = "scip-go gomod example.com/m . example.com/m/handlerB()."
	traceHelper  = "scip-go gomod example.com/m . example.com/m/helper()."
	traceHelper2 = "scip-go gomod example.com/m . example.com/m/helper2()."
	traceSink    = "scip-go gomod example.com/dep v1.0.0 example.com/dep/Sink()."
	traceOther   = "scip-go gomod example.com/dep v1.0.0 example.com/dep/Other()."
)

func traceSyms(ids ...string) []plugin.Symbol {
	out := make([]plugin.Symbol, len(ids))
	for i, id := range ids {
		out[i] = plugin.Symbol{SCIP: id}
	}
	return out
}

func traceEdges(pairs ...[2]string) []plugin.CallEdge {
	out := make([]plugin.CallEdge, len(pairs))
	for i, p := range pairs {
		out[i] = plugin.CallEdge{Caller: plugin.Symbol{SCIP: p[0]}, Callee: plugin.Symbol{SCIP: p[1]}}
	}
	return out
}

// fullTraceEdges is the shape's call graph: main registers both handlers, and each handler
// calls helper, which calls helper2, which calls the sink.
var fullTraceEdges = traceEdges(
	[2]string{traceMain, traceA}, [2]string{traceMain, traceB},
	[2]string{traceA, traceHelper}, [2]string{traceB, traceHelper},
	[2]string{traceHelper, traceHelper2}, [2]string{traceHelper2, traceSink},
)

// TestReachabilityEvidence_TaintTraceFrames drives reachabilityEvidence over a seeded store,
// one row per case taintFrames distinguishes. Every row's credited entry point and grade are
// the taint path's own: only the frames between its ingress and its sink differ.
func TestReachabilityEvidence_TaintTraceFrames(t *testing.T) {
	chain := []string{traceA, traceHelper, traceHelper2, traceSink}
	rows := []struct {
		name       string
		taintFrom  string     // the taint path's ingress
		reach      [][]string // reachability traces, ingress→sink; nil for no artifact
		edges      []plugin.CallEdge
		wantFrames []string
		wantEntry  string
		wantGrade  report.ReachabilityGrade
	}{
		{
			name:       "reachability path heads at the taint ingress",
			taintFrom:  traceA,
			reach:      [][]string{chain},
			edges:      fullTraceEdges,
			wantFrames: chain,
			wantEntry:  "/a", wantGrade: report.GradeAttackerTainted,
		},
		{
			name:       "taint ingress lies inside the reachability path",
			taintFrom:  traceA,
			reach:      [][]string{{traceMain, traceA, traceHelper, traceHelper2, traceSink}},
			edges:      fullTraceEdges,
			wantFrames: chain,
			wantEntry:  "/a", wantGrade: report.GradeAttackerTainted,
		},
		{
			name:       "reachability path runs through another handler: call-graph chain from the ingress",
			taintFrom:  traceA,
			reach:      [][]string{{traceMain, traceB, traceHelper, traceHelper2, traceSink}},
			edges:      fullTraceEdges,
			wantFrames: chain,
			wantEntry:  "/a", wantGrade: report.GradeAttackerTainted,
		},
		{
			name:       "call-graph chain is the shortest",
			taintFrom:  traceA,
			reach:      [][]string{{traceMain, traceB, traceHelper, traceHelper2, traceSink}},
			edges:      append(slices.Clone(fullTraceEdges), traceEdges([2]string{traceA, traceHelper2})...),
			wantFrames: []string{traceA, traceHelper2, traceSink},
			wantEntry:  "/a", wantGrade: report.GradeAttackerTainted,
		},
		{
			name:       "no chain from the ingress in either leg: taint's own trace",
			taintFrom:  traceA,
			reach:      [][]string{{traceMain, traceB, traceHelper, traceHelper2, traceSink}},
			edges:      traceEdges([2]string{traceMain, traceB}, [2]string{traceB, traceHelper}, [2]string{traceHelper, traceHelper2}, [2]string{traceHelper2, traceSink}),
			wantFrames: []string{traceA, traceSink},
			wantEntry:  "/a", wantGrade: report.GradeAttackerTainted,
		},
		{
			name:       "control: no reachability path, taint's own trace unchanged",
			taintFrom:  traceA,
			wantFrames: []string{traceA, traceSink},
			wantEntry:  "/a", wantGrade: report.GradeAttackerTainted,
		},
		{
			// The call graph is searched even when no reachability path ends at the sink.
			name:       "reachability path ends at another sink: call-graph chain from the ingress",
			taintFrom:  traceA,
			reach:      [][]string{{traceA, traceHelper, traceOther}},
			edges:      fullTraceEdges,
			wantFrames: chain,
			wantEntry:  "/a", wantGrade: report.GradeAttackerTainted,
		},
		{
			name:       "reachability path ends at another sink, no chain in the call graph: taint's own trace",
			taintFrom:  traceA,
			reach:      [][]string{{traceA, traceHelper, traceOther}},
			edges:      traceEdges([2]string{traceA, traceHelper}, [2]string{traceHelper, traceOther}),
			wantFrames: []string{traceA, traceSink},
			wantEntry:  "/a", wantGrade: report.GradeAttackerTainted,
		},
		{
			name:       "two reachability paths hold the ingress: the shorter suffix",
			taintFrom:  traceA,
			reach:      [][]string{{traceMain, traceA, traceHelper, traceHelper2, traceSink}, {traceA, traceHelper2, traceSink}},
			edges:      append(slices.Clone(fullTraceEdges), traceEdges([2]string{traceA, traceHelper2})...),
			wantFrames: []string{traceA, traceHelper2, traceSink},
			wantEntry:  "/a", wantGrade: report.GradeAttackerTainted,
		},
		{
			// The frames now pass through handlerA, an attacker route, but the credit is
			// still main's: showing the chain moves neither the entry point nor the grade.
			name:       "frames never move the credit",
			taintFrom:  traceMain,
			reach:      [][]string{{traceMain, traceA, traceHelper, traceHelper2, traceSink}},
			edges:      fullTraceEdges,
			wantFrames: []string{traceMain, traceA, traceHelper, traceHelper2, traceSink},
			wantEntry:  traceMain, wantGrade: report.GradeControlFlowOnly,
		},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			const aid = "a"
			putJSON(t, store, aid, artifact.TypeIngressMap, plugin.IngressResult{Ingresses: []plugin.Ingress{
				{Kind: "http_route", Symbol: plugin.Symbol{SCIP: traceA}, Selector: "/a"},
				{Kind: "http_route", Symbol: plugin.Symbol{SCIP: traceB}, Selector: "/b"},
				{Kind: "main", Symbol: plugin.Symbol{SCIP: traceMain}},
			}})
			putJSON(t, store, aid, artifact.TypeTaint, struct {
				Result plugin.TaintResult `json:"result"`
			}{Result: plugin.TaintResult{Paths: []plugin.ReachPath{{
				Sink: plugin.Symbol{SCIP: traceSink}, Ingress: plugin.Symbol{SCIP: r.taintFrom}, Trace: traceSyms(r.taintFrom, traceSink),
			}}}})
			if r.reach != nil {
				var paths []plugin.ReachPath
				for _, tr := range r.reach {
					paths = append(paths, plugin.ReachPath{Sink: plugin.Symbol{SCIP: tr[len(tr)-1]}, Ingress: plugin.Symbol{SCIP: tr[0]}, Trace: traceSyms(tr...)})
				}
				putJSON(t, store, aid, artifact.TypeReachability, struct {
					Reachability plugin.ReachabilityResult `json:"reachability"`
					CallGraph    plugin.CallGraphResult    `json:"call_graph"`
				}{plugin.ReachabilityResult{Paths: paths}, plugin.CallGraphResult{Edges: r.edges}})
			}

			grade, entry, frames := reachabilityEvidence(store, aid)
			var got []string
			for _, f := range frames {
				got = append(got, f.Symbol)
			}
			if !slices.Equal(got, r.wantFrames) {
				t.Errorf("frames = %q, want %q", got, r.wantFrames)
			}
			if entry == nil || entry.Symbol != r.wantEntry {
				t.Errorf("entry = %+v, want %s", entry, r.wantEntry)
			}
			if grade != r.wantGrade {
				t.Errorf("grade = %q, want %q", grade, r.wantGrade)
			}
			// A chain longer than taint's own two frames shows only calls the graph has.
			if len(got) > 2 {
				for i := 1; i < len(got); i++ {
					if !slices.Contains(r.edges, plugin.CallEdge{Caller: plugin.Symbol{SCIP: got[i-1]}, Callee: plugin.Symbol{SCIP: got[i]}}) {
						t.Errorf("frames %q show the call %s → %s, which the call graph does not have", got, got[i-1], got[i])
					}
				}
			}
		})
	}
}

// TestTaintFrames_StoredOrderNeverMovesTheFrames feeds taintFrames the same paths and edges in
// every stored order. Each leg has a tie: two reachability paths whose suffixes from the
// ingress are the same length, and two call-graph chains of the same length. The frames must be
// the same in every order, and the tie must go to the symbols that sort first.
func TestTaintFrames_StoredOrderNeverMovesTheFrames(t *testing.T) {
	const (
		x = "scip-go gomod example.com/m . example.com/m/x()."
		y = "scip-go gomod example.com/m . example.com/m/y()."
	)
	tp := plugin.ReachPath{Ingress: plugin.Symbol{SCIP: traceA}, Sink: plugin.Symbol{SCIP: traceSink}, Trace: traceSyms(traceA, traceSink)}
	edges := traceEdges([2]string{traceA, y}, [2]string{y, traceSink}, [2]string{traceA, x}, [2]string{x, traceSink})
	paths := []plugin.ReachPath{
		{Trace: traceSyms(traceB, traceA, y, traceSink)},
		{Trace: traceSyms(traceMain, traceA, x, traceSink)},
	}
	want := []string{traceA, x, traceSink}
	check := func(what string, got []plugin.Symbol) {
		t.Helper()
		var ids []string
		for _, s := range got {
			ids = append(ids, s.SCIP)
		}
		if !slices.Equal(ids, want) {
			t.Errorf("%s: frames = %q, want %q", what, ids, want)
		}
	}
	for _, order := range permutations(len(edges)) {
		shuffled := make([]plugin.CallEdge, len(edges))
		for i, j := range order {
			shuffled[i] = edges[j]
		}
		check(fmt.Sprintf("call graph in order %v", order), taintFrames(tp, nil, func() []plugin.CallEdge { return shuffled }))
	}
	for _, order := range permutations(len(paths)) {
		shuffled := make([]plugin.ReachPath, len(paths))
		for i, j := range order {
			shuffled[i] = paths[j]
		}
		check(fmt.Sprintf("reachability paths in order %v", order), taintFrames(tp, shuffled, func() []plugin.CallEdge { return nil }))
	}
}

// permutations returns every ordering of the indexes 0..n-1.
func permutations(n int) [][]int {
	if n == 0 {
		return [][]int{{}}
	}
	var out [][]int
	for _, p := range permutations(n - 1) {
		for i := 0; i <= len(p); i++ {
			out = append(out, slices.Insert(slices.Clone(p), i, n-1))
		}
	}
	return out
}
