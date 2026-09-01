package javaanalysis

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Reachability reports, for each resolved sink symbol in req.Symbols, whether a
// static call-graph path connects a framework ingress (or program entry root) to
// that sink in the Java module at req.BuildDir. Java has no govulncheck-style
// advisory DB, so — unlike the Go plugin — the reachability signal IS the
// first-party call-graph BFS: it walks the directed CallGraph backward from each
// sink toward the nearest ingress/root, mirroring the pipeline's
// firstPartyReachPaths exactly, but computed inside the plugin so the reachability
// op is real rather than a declared stub.
//
// It builds on the EXISTING infra: CallGraph and FindIngresses (both already
// Prove-path enriched when TEGRON_JAVA_ANALYZER_IMAGE is set; pure-Go lexical in
// the Assess path). Because it consumes their results, reachability is
// automatically enriched by the container when present and degrades gracefully to
// the lexical graph when it is not.
//
// Partiality is honest (inv.5): a sink with no backward path to any ingress is
// declared no_known_ingress — UNKNOWN, never a false "not reachable"; and the
// call-graph/ingress partiality (dynamic_dispatch from an unresolved callee, etc.)
// is folded in, so a path the partial graph could not corroborate is never
// rendered as clean reachability. A path that reaches only a root (not a
// recognized attacker-facing ingress) also declares no_known_ingress. A load
// failure in CallGraph/FindIngresses is a hard error (inv.4).
func Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.ReachabilityResult{}, err
	}
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.ReachabilityResult{}, err
	}

	paths, reasons := firstPartyPaths(cg, ing, req.Symbols)

	return plugin.ReachabilityResult{
		Partiality: reachabilityPartiality(reasons),
		Paths:      paths,
	}, nil
}

// sinkClassifiers is the H3 registry (edge-seam.md §5): each overlay (#3 repository
// sinks, #4 SpEL, #5 filter/security guards) appends a classifier from its OWN file's
// init() via registerSinkClassifier, rather than editing the firstPartyPaths BFS core
// and colliding. firstPartyPaths invokes every registered classifier once per requested
// sink and unions the extra partiality reasons they return. Empty by default, so the
// default behavior is byte-identical to today. Shared by Reachability and ComputeTaint
// (both derive their paths through firstPartyPaths).
var sinkClassifiers []func(symbolID string) []string

// registerSinkClassifier appends a sink classifier to the H3 registry. An overlay
// calls it from init(); a classifier returns the extra partiality reasons a sink
// warrants (nil for a sink it does not recognize), never fabricating reachability.
func registerSinkClassifier(fn func(symbolID string) []string) {
	sinkClassifiers = append(sinkClassifiers, fn)
}

// firstPartyPaths derives one representative ingress→sink ReachPath per requested
// sink by walking the call graph backward, and returns the union of partiality
// reasons the derivation must declare: the folded call-graph + ingress reasons,
// plus no_known_ingress for every requested sink with no reaching ingress (an
// unknown, never a "safe"). Shared by Reachability and ComputeTaint — the two ops
// differ only in their precision note and which request field names the sinks.
func firstPartyPaths(cg plugin.CallGraphResult, ing plugin.IngressResult, sinks []string) ([]plugin.ReachPath, map[string]bool) {
	reasons := map[string]bool{}
	for _, r := range cg.Partiality.Reasons {
		reasons[r] = true
	}
	for _, r := range ing.Partiality.Reasons {
		reasons[r] = true
	}

	callers := make(map[string][]string, len(cg.Edges))
	for _, e := range cg.Edges {
		callers[e.Callee.SCIP] = append(callers[e.Callee.SCIP], e.Caller.SCIP)
	}
	ingressSyms := make(map[string]bool, len(ing.Ingresses))
	for _, in := range ing.Ingresses {
		if in.Symbol.SCIP != "" {
			ingressSyms[in.Symbol.SCIP] = true
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
		// H3 seam (edge-seam.md §5): let each registered sink classifier declare extra
		// partiality on this sink (a repo synthesized sink, a SpEL-guarded sink, an
		// unknown guard) independent of whether a path reaches it. Empty registry ⇒ no
		// extra reasons ⇒ byte-identical to today.
		for _, classify := range sinkClassifiers {
			for _, r := range classify(sink) {
				reasons[r] = true
			}
		}
		p, ok := reachPathToSink(callers, ingressSyms, roots, sink)
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

// reachPathToSink is the reverse BFS from a single sink to the nearest ingress or
// root, returning one representative ingress→sink ReachPath. It is byte-for-byte
// the pipeline's firstPartyReachPaths walk, terminating at the same ingress∪root
// frontier over the same directed edges, so the plugin-computed path is identical
// to the fallback the pipeline used while this op was a stub.
func reachPathToSink(callers map[string][]string, ingressSyms, roots map[string]bool, sink string) (plugin.ReachPath, bool) {
	if sink == "" || len(callers) == 0 {
		return plugin.ReachPath{}, false
	}
	type node struct {
		sym  string
		path []string
	}
	visited := map[string]bool{sink: true}
	queue := []node{{sym: sink, path: []string{sink}}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		isIngress := ingressSyms[cur.sym]
		isRoot := roots[cur.sym]
		if isIngress || isRoot {
			trace := make([]string, len(cur.path))
			for i := range cur.path {
				trace[i] = cur.path[len(cur.path)-1-i]
			}
			ingress := ""
			if isIngress {
				ingress = cur.sym
			}
			// Sink/Ingress/Trace are now Symbol/[]Symbol; the BFS carries id strings,
			// so wrap each via sym at the mint. A root-only path leaves ingress "",
			// so sym("") is the zero Symbol the contract's "unknown ingress" case.
			traceSyms := make([]plugin.Symbol, len(trace))
			for i := range trace {
				traceSyms[i] = sym(trace[i])
			}
			return plugin.ReachPath{Sink: sym(sink), Ingress: sym(ingress), Trace: traceSyms}, true
		}

		for _, caller := range callers[cur.sym] {
			if visited[caller] {
				continue
			}
			visited[caller] = true
			queue = append(queue, node{sym: caller, path: append(append([]string{}, cur.path...), caller)})
		}
	}
	return plugin.ReachPath{}, false
}

// reachabilityPartiality collapses the accumulated reason set into a Partiality:
// Complete when empty, else Partial with the reasons sorted for a stable payload.
func reachabilityPartiality(reasons map[string]bool) plugin.Partiality {
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(sortedKeys(reasons)...)
}

// sortedKeys returns the set's keys in sorted order, for deterministic partiality
// reason lists (mirrors goanalysis.sortedKeys).
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
