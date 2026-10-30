package pipeline

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// perCallReachPaths is firstPartyReachPaths as it was before the reverse-edge index moved onto the
// call graph view: every call rebuilds the index from the whole graph. It is the oracle for
// TestFirstPartyReachPathsMatchesPerCallIndex.
func perCallReachPaths(cg plugin.CallGraphResult, ingresses plugin.IngressResult, sink string) []plugin.ReachPath {
	if sink == "" || len(cg.Edges) == 0 {
		return nil
	}
	symBySCIP := make(map[string]plugin.Symbol)
	callers := make(map[string][]string, len(cg.Edges))
	for _, e := range cg.Edges {
		symBySCIP[e.Caller.SCIP] = e.Caller
		symBySCIP[e.Callee.SCIP] = e.Callee
		callers[e.Callee.SCIP] = append(callers[e.Callee.SCIP], e.Caller.SCIP)
	}
	ingressSyms := make(map[string]struct{}, len(ingresses.Ingresses))
	for _, in := range ingresses.Ingresses {
		if in.Symbol.SCIP != "" {
			symBySCIP[in.Symbol.SCIP] = in.Symbol
			ingressSyms[in.Symbol.SCIP] = struct{}{}
		}
	}
	roots := make(map[string]struct{})
	for _, r := range cg.Roots {
		symBySCIP[r.SCIP] = r
		roots[r.SCIP] = struct{}{}
	}
	type node struct {
		sym  string
		path []string
	}
	visited := map[string]struct{}{sink: {}}
	queue := []node{{sym: sink, path: []string{sink}}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		_, isIngress := ingressSyms[cur.sym]
		_, isRoot := roots[cur.sym]
		if isIngress || isRoot {
			trace := make([]plugin.Symbol, len(cur.path))
			for i := range cur.path {
				trace[i] = symBySCIP[cur.path[len(cur.path)-1-i]]
			}
			var ingress plugin.Symbol
			if isIngress {
				ingress = symBySCIP[cur.sym]
			}
			return []plugin.ReachPath{{Sink: symBySCIP[sink], Ingress: ingress, Trace: trace}}
		}
		for _, caller := range callers[cur.sym] {
			if _, seen := visited[caller]; seen {
				continue
			}
			visited[caller] = struct{}{}
			queue = append(queue, node{sym: caller, path: append(append([]string{}, cur.path...), caller)})
		}
	}
	return nil
}

// tagged is a Symbol whose non-SCIP fields say where it came from, so a test can tell which of
// several Symbols sharing a SCIP id a path carries.
func tagged(scip, tag string) plugin.Symbol {
	return plugin.Symbol{Kind: plugin.SymbolKindFunction, Name: scip, DisplayName: tag, SCIP: scip}
}

func edge(caller, callerTag, callee, calleeTag string) plugin.CallEdge {
	return plugin.CallEdge{Caller: tagged(caller, callerTag), Callee: tagged(callee, calleeTag)}
}

func ingressesOf(syms ...plugin.Symbol) plugin.IngressResult {
	var r plugin.IngressResult
	for _, s := range syms {
		r.Ingresses = append(r.Ingresses, plugin.Ingress{Kind: "http", Symbol: s})
	}
	return r
}

// randomReachGraph is a small graph with few ids and many Symbols per id, so precedence, cycles
// and several callers per callee all occur.
func randomReachGraph(r *rand.Rand) (plugin.CallGraphResult, plugin.IngressResult) {
	ids := []string{"a", "b", "c", "d", "e", "f", "s", ""}
	pick := func() plugin.Symbol {
		id := ids[r.Intn(len(ids))]
		return tagged(id, fmt.Sprintf("%s-%d", id, r.Intn(3)))
	}
	var cg plugin.CallGraphResult
	for i, n := 0, r.Intn(14); i < n; i++ {
		cg.Edges = append(cg.Edges, plugin.CallEdge{Caller: pick(), Callee: pick()})
	}
	for i, n := 0, r.Intn(3); i < n; i++ {
		cg.Roots = append(cg.Roots, pick())
	}
	var ing plugin.IngressResult
	for i, n := 0, r.Intn(4); i < n; i++ {
		ing.Ingresses = append(ing.Ingresses, plugin.Ingress{Kind: "http", Symbol: pick()})
	}
	return cg, ing
}

// TestFirstPartyReachPathsMatchesPerCallIndex pins that reading the reverse-edge index the call
// graph view builds once gives exactly the paths the per-call index gave: the same BFS order and,
// for a SCIP id several Symbols carry, the same Symbol (root over ingress over edge, later over
// earlier).
func TestFirstPartyReachPathsMatchesPerCallIndex(t *testing.T) {
	type graph struct {
		name string
		cg   plugin.CallGraphResult
		ing  plugin.IngressResult
	}
	graphs := []graph{
		{name: "empty"},
		{name: "empty with ingress sink", ing: ingressesOf(tagged("s", "i"))},
		{
			name: "duplicate ids across edges, ingresses and roots",
			cg: plugin.CallGraphResult{
				Edges: []plugin.CallEdge{
					edge("a", "e1", "s", "e1"),
					edge("r", "e1", "a", "e2"),
					edge("i", "e1", "a", "e3"),
					edge("a", "e4", "s", "e2"),
					edge("ri", "e1", "s", "e3"),
				},
				Roots: []plugin.Symbol{tagged("r", "r1"), tagged("ri", "r1"), tagged("r", "r2")},
			},
			ing: ingressesOf(tagged("i", "i1"), tagged("ri", "i1"), tagged("i", "i2"), tagged("a", "i1"), tagged("", "i-empty")),
		},
		{
			name: "several callers per callee",
			cg: plugin.CallGraphResult{
				Edges: []plugin.CallEdge{
					edge("c1", "e", "s", "e"),
					edge("c2", "e", "s", "e"),
					edge("c3", "e", "s", "e"),
					edge("h2", "e", "c2", "e"),
					edge("h3", "e", "c3", "e"),
					edge("main", "e", "c1", "e"),
				},
				Roots: []plugin.Symbol{tagged("main", "r")},
			},
			ing: ingressesOf(tagged("h3", "i"), tagged("h2", "i")),
		},
		{
			name: "cycles",
			cg: plugin.CallGraphResult{
				Edges: []plugin.CallEdge{
					edge("a", "e", "b", "e"),
					edge("b", "e", "a", "e"),
					edge("a", "e", "s", "e"),
					edge("s", "e", "s", "e"),
					edge("h", "e", "b", "e"),
					edge("x", "e", "y", "e"),
					edge("y", "e", "x", "e"),
					edge("x", "e", "t", "e"),
				},
			},
			ing: ingressesOf(tagged("h", "i")),
		},
		{
			name: "sink is a root and an ingress",
			cg: plugin.CallGraphResult{
				Edges: []plugin.CallEdge{edge("a", "e", "s", "e")},
				Roots: []plugin.Symbol{tagged("s", "r")},
			},
			ing: ingressesOf(tagged("s", "i"), tagged("a", "i")),
		},
		{
			name: "empty SCIP ids",
			cg: plugin.CallGraphResult{
				Edges: []plugin.CallEdge{edge("", "e1", "s", "e"), edge("", "e2", "t", "e")},
				Roots: []plugin.Symbol{tagged("", "r")},
			},
			ing: ingressesOf(tagged("", "i")),
		},
	}
	r := rand.New(rand.NewSource(615))
	for i := 0; i < 300; i++ {
		cg, ing := randomReachGraph(r)
		graphs = append(graphs, graph{name: fmt.Sprintf("random %d", i), cg: cg, ing: ing})
	}

	for _, g := range graphs {
		sinks := map[string]struct{}{"": {}, "absent": {}}
		for _, e := range g.cg.Edges {
			sinks[e.Caller.SCIP], sinks[e.Callee.SCIP] = struct{}{}, struct{}{}
		}
		for _, root := range g.cg.Roots {
			sinks[root.SCIP] = struct{}{}
		}
		for _, in := range g.ing.Ingresses {
			sinks[in.Symbol.SCIP] = struct{}{}
		}
		memo, err := plugin.SharedCallGraph(context.Background(), plugin.Memoize(payloadGraphPlugin{cg: g.cg}), plugin.CallGraphRequest{BuildDir: "/src"})
		if err != nil {
			t.Fatal(err)
		}
		views := map[string]plugin.CallGraphView{
			"memoized": memo,
			"wrapped":  plugin.NewCallGraphView(g.cg),
			"zero":     {},
		}
		for vname, v := range views {
			for sink := range sinks {
				want := perCallReachPaths(g.cg, g.ing, sink)
				if vname == "zero" {
					want = perCallReachPaths(plugin.CallGraphResult{}, g.ing, sink)
				}
				got := firstPartyReachPaths(v, g.ing, sink)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s, %s view, sink %q:\ngot  %+v\nwant %+v", g.name, vname, sink, got, want)
					continue
				}
				// The paths are the caller's own: editing them leaves the next walk's answer alone.
				for i := range got {
					got[i].Sink.DisplayName = "mutated"
					got[i].Ingress.DisplayName = "mutated"
					for j := range got[i].Trace {
						got[i].Trace[j].DisplayName = "mutated"
					}
				}
				if again := firstPartyReachPaths(v, g.ing, sink); !reflect.DeepEqual(again, want) {
					t.Errorf("%s, %s view, sink %q: after editing a result, got %+v, want %+v", g.name, vname, sink, again, want)
				}
			}
		}
	}
}
