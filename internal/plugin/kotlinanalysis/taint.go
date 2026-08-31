package kotlinanalysis

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// taint.go — the Kotlin ComputeTaint op. It is a MIRROR of javaanalysis/taint.go's
// path-presence semantics onto the Kotlin lane's OWN infra, NOT a delegation: the graph it
// searches is the Kotlin/JVM bytecode call graph (CallGraph) over Kotlin's entry set
// (FindIngresses), which is source-graph-specific and cannot be borrowed from the Java lane
// the way the build-file-generic resolvers can. Only the reverse-BFS path walk is added
// here; everything it consumes (the call graph, the ingress set, their declared partiality)
// is produced by the Kotlin lane's existing ops.
//
// The honest baseline is call-graph PATH PRESENCE — an ingress→sink path exists over the
// directed call graph — NOT variable-level dataflow. This deliberately differs from the
// Kotlin Reachability op's depreach two-trace: Reachability admits a sound NotExploitable
// negative (a hazard-free empty search rendered Complete/empty), whereas taint must never
// render "no path" as "not tainted" (inv.5). Here a requested sink with no reaching ingress
// is declared no_known_ingress — UNKNOWN — exactly as the Java taint template does.

// kotlinTaintPrecisionNote records the precision of the Kotlin taint op: call-graph PATH
// PRESENCE over the Kotlin/JVM bytecode call graph, NOT variable-level dataflow. Kotlin is
// analyzed as bytecode with no SSA value-flow at Assess tier, so path presence is the honest
// baseline the plugin contract defines for minimal taint. The note travels with every result
// so a consumer never mistakes a structural candidate for a value-flow proof.
const kotlinTaintPrecisionNote = "call-graph path presence: an ingress→sink path exists over the Kotlin/JVM bytecode call graph (framework ingress ∪ program-root frontier); NOT variable-level dataflow or a sanitizer-aware value-flow model. A path is a structural candidate, not proof that attacker input flows to the sink."

// ComputeTaint reports, for each resolved sink in req.Sinks, whether attacker input can
// reach it, approximated by call-graph PATH PRESENCE from a framework ingress (or program
// root) to the sink. It builds on the Kotlin lane's EXISTING CallGraph/FindIngresses infra
// over the compiled build output — so it needs no analyzer of its own and inherits their
// zero-egress pure-Go/lexical path unchanged.
//
// Partiality is honest (inv.5): a requested sink with no reaching ingress is declared
// no_known_ingress — UNKNOWN, never a false "not tainted" — and the call-graph/ingress
// partiality is folded in. A load failure is a hard error (inv.4), surfaced by the
// underlying CallGraph/FindIngresses ops. PrecisionNote is always set so the path-presence
// limit is explicit.
func ComputeTaint(ctx context.Context, req plugin.ComputeTaintRequest) (plugin.TaintResult, error) {
	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.TaintResult{}, err
	}
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.TaintResult{}, err
	}

	paths, reasons := taintPaths(cg, ing, req.Sinks)

	return plugin.TaintResult{
		Partiality:    taintPartiality(reasons),
		Paths:         paths,
		PrecisionNote: kotlinTaintPrecisionNote,
	}, nil
}

// taintPaths derives one representative ingress→sink ReachPath per requested sink by walking
// the Kotlin call graph backward, and returns the union of partiality reasons the derivation
// must declare: the folded call-graph + ingress reasons, plus no_known_ingress for every
// requested sink with no reaching ingress (an unknown, never a "safe"). It mirrors
// javaanalysis.firstPartyPaths, adapted to carry the Kotlin lane's full canonical Symbols
// (from CallGraph edges) through the walk rather than reconstructing them from ids.
func taintPaths(cg plugin.CallGraphResult, ing plugin.IngressResult, sinks []string) ([]plugin.ReachPath, map[string]bool) {
	reasons := map[string]bool{}
	for _, r := range cg.Partiality.Reasons {
		reasons[r] = true
	}
	for _, r := range ing.Partiality.Reasons {
		reasons[r] = true
	}

	// Caller adjacency keyed by callee SCIP; the edge list is pre-sorted by CallGraph, so
	// each caller slice is deterministic and no map is an iteration source on the result path.
	callers := make(map[string][]plugin.Symbol, len(cg.Edges))
	calleeSym := make(map[string]plugin.Symbol, len(cg.Edges))
	for _, e := range cg.Edges {
		callers[e.Callee.SCIP] = append(callers[e.Callee.SCIP], e.Caller)
		calleeSym[e.Callee.SCIP] = e.Callee
	}
	ingressSyms := make(map[string]plugin.Symbol, len(ing.Ingresses))
	for _, in := range ing.Ingresses {
		if in.Symbol.SCIP != "" {
			ingressSyms[in.Symbol.SCIP] = in.Symbol
		}
	}
	roots := make(map[string]bool, len(cg.Roots))
	for _, r := range cg.Roots {
		roots[r.SCIP] = true
	}

	var paths []plugin.ReachPath
	for _, sink := range sinks {
		if sink == "" {
			continue
		}
		p, ok := taintPathToSink(callers, ingressSyms, roots, calleeSym, sink)
		if !ok {
			// No static path from any ingress/root to this sink over the (possibly
			// partial) graph: UNKNOWN, never "safe" (inv.5).
			reasons[plugin.PartialReasonNoIngress] = true
			continue
		}
		if p.Ingress.SCIP == "" {
			// Reached a program root but no attacker-facing ingress on the path.
			reasons[plugin.PartialReasonNoIngress] = true
		}
		paths = append(paths, p)
	}
	return paths, reasons
}

// taintPathToSink is the reverse BFS from a single sink to the nearest ingress or root,
// returning one representative ingress→sink ReachPath. It terminates at the ingress∪root
// frontier over the directed call-graph edges — the same walk shape javaanalysis uses — and
// carries the Kotlin lane's canonical Symbols end to end. A root-only path leaves Ingress the
// zero Symbol, the contract's "unknown ingress" case.
func taintPathToSink(callers map[string][]plugin.Symbol, ingressSyms map[string]plugin.Symbol, roots map[string]bool, calleeSym map[string]plugin.Symbol, sink string) (plugin.ReachPath, bool) {
	if sink == "" || len(callers) == 0 {
		return plugin.ReachPath{}, false
	}
	// Seed the walk with the sink's canonical Symbol. When a path exists the sink is a
	// callee on it (so calleeSym has it); the id-only fallback is harmless since it is
	// emitted only on a found path.
	seed, ok := calleeSym[sink]
	if !ok {
		seed = plugin.Symbol{SCIP: sink, DisplayName: sink}
	}
	type node struct {
		sym  plugin.Symbol
		path []plugin.Symbol
	}
	visited := map[string]bool{sink: true}
	queue := []node{{sym: seed, path: []plugin.Symbol{seed}}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		ingSym, isIngress := ingressSyms[cur.sym.SCIP]
		isRoot := roots[cur.sym.SCIP]
		if isIngress || isRoot {
			trace := make([]plugin.Symbol, len(cur.path))
			for i := range cur.path {
				trace[i] = cur.path[len(cur.path)-1-i]
			}
			var ingress plugin.Symbol
			if isIngress {
				ingress = ingSym
			}
			return plugin.ReachPath{Sink: seed, Ingress: ingress, Trace: trace}, true
		}

		for _, caller := range callers[cur.sym.SCIP] {
			if visited[caller.SCIP] {
				continue
			}
			visited[caller.SCIP] = true
			next := append(append([]plugin.Symbol{}, cur.path...), caller)
			queue = append(queue, node{sym: caller, path: next})
		}
	}
	return plugin.ReachPath{}, false
}

// taintPartiality collapses the accumulated reason set into a Partiality: Complete when
// empty, else Partial with the reasons sorted (via the package sortedKeys) for a stable,
// deterministic payload. Mirror of javaanalysis.reachabilityPartiality.
func taintPartiality(reasons map[string]bool) plugin.Partiality {
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(sortedKeys(reasons)...)
}
