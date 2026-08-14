package jsanalysis

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// taintPrecisionNote is the standing honesty note for the JS lexical taint op: it
// resolves source→sink PATH PRESENCE over the lexical call graph, NOT variable-level
// value flow. A pure lexical scanner has no SSA, no type information, and no def-use
// chains, so it cannot model whether a tainted value (an ingress parameter) actually
// flows into the sink's argument, nor whether a sanitizer intervenes. That precision gap
// is the DECLARED limit — the same honesty the Go path records.
const taintPrecisionNote = "lexical call-graph path-presence only: ingress→sink reachability over the source-level call graph, not variable-level value flow (no SSA/type info, no def-use or sanitizer modeling in a lexical scanner)"

// ComputeTaint reports, for each requested sink, whether a call path exists from a
// discovered ingress (an attacker-controllable source) to the sink over the EXISTING
// lexical call graph — minimal taint as PATH PRESENCE, not precise value flow. It builds
// the call graph (CallGraph), takes the discovered ingresses (FindIngresses) as sources,
// and walks graph edges source→sink (the same edge-set Reachability uses).
//
// ALWAYS declared Partial by construction (inv.5): a lexical scanner has no SSA or type
// information, so it can never prove that the tainted ingress VALUE reaches the sink
// ARGUMENT — only that a call path connects the two functions. PrecisionNote records this
// standing limit, and the result carries dynamic_dispatch so it can never be read as
// precise variable-level taint. The call graph's own partiality (dynamic dispatch for
// unresolved lexical callees) is also folded in, and a sink with no path from any ingress
// declares no_known_ingress (NEVER "safe"). A load failure is a hard error (inv.4).
func ComputeTaint(ctx context.Context, req plugin.ComputeTaintRequest) (plugin.TaintResult, error) {
	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.TaintResult{}, err
	}
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.TaintResult{}, err
	}

	adj := buildAdjacency(cg.Edges)
	sources := entrySymbols(ing.Ingresses, cg.Roots)

	reasons := map[string]bool{}
	for _, r := range cg.Partiality.Reasons {
		reasons[r] = true
	}
	if !cg.Partiality.Complete && len(cg.Partiality.Reasons) == 0 {
		reasons[plugin.PartialReasonDynamicDispatch] = true
	}

	var paths []plugin.ReachPath
	for _, s := range req.Sinks {
		sink := sym(s)
		trace := shortestPath(adj, sources, sink)
		if trace == nil {
			// A sink with no source path is UNKNOWN, never "safe" (inv.5).
			reasons[plugin.PartialReasonNoIngress] = true
			continue
		}
		paths = append(paths, plugin.ReachPath{
			Sink:    sink,
			Ingress: trace[0],
			Trace:   trace,
		})
	}

	// Path presence is not value-flow precision: the result is NEVER Complete, even for a
	// clean corroborated path. Carry the precision limit as a reason so the op cannot be
	// read as precise variable-level taint.
	reasons[plugin.PartialReasonDynamicDispatch] = true

	return plugin.TaintResult{
		Partiality:    plugin.Partial(sortedReasons(reasons)...),
		Paths:         paths,
		PrecisionNote: taintPrecisionNote,
	}, nil
}

// buildAdjacency builds caller→callees adjacency from the directed call edges. Keyed by
// the comparable plugin.Symbol directly: every edge endpoint is minted through sym(), so
// equal SCIP ids are byte-identical Symbols and adjacency lookups resolve correctly.
func buildAdjacency(edges []plugin.CallEdge) map[plugin.Symbol][]plugin.Symbol {
	adj := make(map[plugin.Symbol][]plugin.Symbol, len(edges))
	for _, e := range edges {
		adj[e.Caller] = append(adj[e.Caller], e.Callee)
	}
	return adj
}

// shortestPath returns the shortest ordered source→sink path over the call graph (BFS
// from all sources at once), or nil when no path exists. Determinism: CallGraph pre-sorts
// edges, so neighbour order is stable.
func shortestPath(adj map[plugin.Symbol][]plugin.Symbol, sources []plugin.Symbol, sink plugin.Symbol) []plugin.Symbol {
	prev := map[plugin.Symbol]plugin.Symbol{}
	visited := map[plugin.Symbol]bool{}
	var queue []plugin.Symbol
	for _, s := range sources {
		if s == sink {
			return []plugin.Symbol{s}
		}
		if !visited[s] {
			visited[s] = true
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range adj[cur] {
			if visited[next] {
				continue
			}
			visited[next] = true
			prev[next] = cur
			if next == sink {
				return reconstruct(prev, sources, sink)
			}
			queue = append(queue, next)
		}
	}
	return nil
}

// reconstruct walks the prev map back from sink to a source, returning the ordered
// source→sink trace.
func reconstruct(prev map[plugin.Symbol]plugin.Symbol, sources []plugin.Symbol, sink plugin.Symbol) []plugin.Symbol {
	srcSet := make(map[plugin.Symbol]bool, len(sources))
	for _, s := range sources {
		srcSet[s] = true
	}
	var rev []plugin.Symbol
	for cur := sink; ; {
		rev = append(rev, cur)
		if srcSet[cur] {
			break
		}
		p, ok := prev[cur]
		if !ok {
			break
		}
		cur = p
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

// sortedReasons returns the set's keys in sorted order for a deterministic Partiality.
func sortedReasons(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
