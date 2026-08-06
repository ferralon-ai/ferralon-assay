package pythonanalysis

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Reachability reports, for each resolved sink symbol in req.Symbols, whether a static
// call-graph path connects a framework ingress (or program-entry root) to that sink in the
// Python module at req.BuildDir. Python has no govulncheck-style advisory DB, so — like the
// Java/JS plugins — the reachability signal IS the first-party call-graph reverse BFS: it
// walks the directed CallGraph backward from each sink toward the nearest ingress/root,
// mirroring the pipeline's firstPartyReachPaths, but computed inside the plugin so the op
// is real rather than a declared stub. It reuses the EXISTING CallGraph and FindIngresses.
//
// LOAD-BEARING honesty posture (inv.5): Python static reachability is STRUCTURALLY WEAK
// (dynamic dispatch, getattr, monkeypatching, decorator rewriting), so this op ALWAYS
// declares Partial(dynamic_dispatch) — even when a path IS found. It is a candidate
// NARROWER, not an adjudicator: the effect trial adjudicates. "Not reached" is UNKNOWN
// (no_known_ingress), NEVER a confident "safe"/not-affected. A load failure in
// CallGraph/FindIngresses is a hard error (inv.4).
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

// firstPartyPaths derives one representative ingress→sink ReachPath per requested sink by
// walking the call graph backward, and returns the union of partiality reasons the
// derivation must declare: the folded call-graph + ingress reasons, plus no_known_ingress
// for every requested sink with no reaching ingress (UNKNOWN, never "safe"), plus the
// STANDING dynamic_dispatch reason that makes Python reachability/taint ALWAYS Partial —
// a found path is a structural candidate, never proof, because a lexical scanner cannot
// see Python's dynamic edges. Shared by Reachability and ComputeTaint.
func firstPartyPaths(cg plugin.CallGraphResult, ing plugin.IngressResult, sinks []string) ([]plugin.ReachPath, map[string]bool) {
	// Python is structurally weak: reachability/taint are NEVER Complete. Seed the
	// standing partiality reason unconditionally (inv.5).
	reasons := map[string]bool{plugin.PartialReasonDynamicDispatch: true}
	for _, r := range cg.Partiality.Reasons {
		reasons[r] = true
	}
	for _, r := range ing.Partiality.Reasons {
		reasons[r] = true
	}

	callers := make(map[string][]string, len(cg.Edges))
	for _, e := range cg.Edges {
		callers[e.Callee] = append(callers[e.Callee], e.Caller)
	}
	ingressSyms := make(map[string]bool, len(ing.Ingresses))
	for _, in := range ing.Ingresses {
		if in.Symbol != "" {
			ingressSyms[in.Symbol] = true
		}
	}
	roots := make(map[string]bool, len(cg.Roots))
	for _, r := range cg.Roots {
		roots[r] = true
	}

	var paths []plugin.ReachPath
	for _, sink := range sinks {
		if sink == "" {
			continue
		}
		p, ok := reachPathToSink(callers, ingressSyms, roots, sink)
		if !ok {
			// No static path from any ingress/root to this sink over the (partial)
			// graph: UNKNOWN, never "safe" (inv.5).
			reasons[plugin.PartialReasonNoIngress] = true
			continue
		}
		if p.Ingress == "" {
			// Reached a program root but no attacker-facing ingress on the path.
			reasons[plugin.PartialReasonNoIngress] = true
		}
		paths = append(paths, p)
	}
	return paths, reasons
}

// reachPathToSink is the reverse BFS from a single sink to the nearest ingress or root,
// returning one representative ingress→sink ReachPath. It terminates at the ingress∪root
// frontier over the directed edges, identical to the pipeline's firstPartyReachPaths walk.
func reachPathToSink(callers map[string][]string, ingressSyms, roots map[string]bool, sink string) (plugin.ReachPath, bool) {
	if sink == "" {
		return plugin.ReachPath{}, false
	}
	// A sink that is itself an ingress/root is trivially reachable.
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
			return plugin.ReachPath{Sink: sink, Ingress: ingress, Trace: trace}, true
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

// reachabilityPartiality collapses the accumulated reason set into a Partiality. For
// Python it is NEVER Complete: firstPartyPaths always seeds dynamic_dispatch, so the set
// is non-empty by construction. reasons are sorted for a stable payload.
func reachabilityPartiality(reasons map[string]bool) plugin.Partiality {
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(sortedKeys(reasons)...)
}

// sortedKeys returns the set's keys in sorted order, for deterministic partiality lists.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
