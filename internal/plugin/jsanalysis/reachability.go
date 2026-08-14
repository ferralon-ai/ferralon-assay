package jsanalysis

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Reachability derives reachable (ingress, sink, path) pairs for the requested vulnerable
// symbols over the EXISTING lexical call graph — the JS analog of the Go path's
// govulncheck-reconciled reachability, but built from this engine's own source-level CPG
// (CallGraph) and discovered ingresses (FindIngresses) rather than a vuln database.
//
// For each requested sink symbol it walks the call graph from every discovered ingress
// (and from call-graph roots, which the JS CallGraph records for ingress handlers) to the
// sink, emitting one ReachPath per reachable sink with the ordered ingress→sink trace —
// the SAME ReachPath evidence shape the Go path emits, in the SAME SCIP identity space
// (CallGraph, FindIngresses, and ResolveDependencySymbols all use scipSymbol).
//
// Partiality is declared, never overclaimed (inv.5):
//   - The call graph's own partiality (dynamic_dispatch for unresolved/ambiguous lexical
//     callees, tool_failure for read errors, unsupported for skipped constructs) is folded
//     in. Because the lexical scanner never resolves dynamic dispatch, dynamic
//     require()/import(), or computed member calls, a non-trivial program is honestly
//     declared-partial here — the lexer cannot SEE every edge, so it never claims it did.
//   - A requested sink that is NOT a node in the call graph, or that no ingress/root
//     reaches, declares no_known_ingress (NEVER "not reachable"/"safe"): the lexer's miss
//     is UNKNOWN, never a confident not-affected.
//
// A load failure is a hard error (inv.4).
func Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.ReachabilityResult{}, err
	}
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.ReachabilityResult{}, err
	}

	adj := buildAdjacency(cg.Edges)
	nodes := graphNodes(cg.Edges)
	sources := entrySymbols(ing.Ingresses, cg.Roots)

	reasons := map[string]bool{}
	for _, r := range cg.Partiality.Reasons {
		reasons[r] = true
	}
	if !cg.Partiality.Complete && len(cg.Partiality.Reasons) == 0 {
		reasons[plugin.PartialReasonDynamicDispatch] = true
	}

	var paths []plugin.ReachPath
	for _, s := range req.Symbols {
		sink := sym(s)
		trace := shortestPath(adj, sources, sink)
		if trace == nil {
			// A sink the lexical graph cannot connect to any ingress is UNKNOWN, never
			// "safe": the sink may be absent from the source graph (library/dynamic) or
			// reachable only through an edge the lexer could not resolve.
			if !nodes[sink] {
				reasons[plugin.PartialReasonDynamicDispatch] = true
			}
			reasons[plugin.PartialReasonNoIngress] = true
			continue
		}
		var ingress plugin.Symbol
		if len(trace) > 0 {
			ingress = trace[0]
		}
		paths = append(paths, plugin.ReachPath{
			Sink:    sink,
			Ingress: ingress,
			Trace:   trace,
		})
	}

	if len(reasons) == 0 {
		return plugin.ReachabilityResult{Partiality: plugin.Complete(), Paths: paths}, nil
	}
	return plugin.ReachabilityResult{Partiality: plugin.Partial(sortedReasons(reasons)...), Paths: paths}, nil
}

// entrySymbols is the set of static-reachability entry points: every discovered ingress
// handler symbol plus every call-graph root (which the JS CallGraph populates with
// resolved ingress handlers). Empty symbols are dropped.
func entrySymbols(ingresses []plugin.Ingress, roots []plugin.Symbol) []plugin.Symbol {
	seen := map[plugin.Symbol]bool{}
	var out []plugin.Symbol
	add := func(s plugin.Symbol) {
		if s == (plugin.Symbol{}) || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, in := range ingresses {
		add(in.Symbol)
	}
	for _, r := range roots {
		add(r)
	}
	return out
}

// graphNodes returns the set of symbols that appear as a caller or callee in the graph —
// the symbols the lexical analysis actually resolved.
func graphNodes(edges []plugin.CallEdge) map[plugin.Symbol]bool {
	nodes := make(map[plugin.Symbol]bool, len(edges))
	for _, e := range edges {
		nodes[e.Caller] = true
		nodes[e.Callee] = true
	}
	return nodes
}
