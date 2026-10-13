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
// is real rather than a declared stub. It reuses the EXISTING call graph and FindIngresses.
//
// LOAD-BEARING honesty posture (inv.5): Python static reachability is STRUCTURALLY WEAK
// (dynamic dispatch, getattr, monkeypatching, decorator rewriting), so this op ALWAYS
// declares Partial(dynamic_dispatch) — even when a path IS found. It is a candidate
// NARROWER, not an adjudicator: the effect trial adjudicates. "Not reached" is UNKNOWN
// (no_known_ingress), NEVER a confident "safe"/not-affected. A load failure in
// CallGraph/FindIngresses is a hard error (inv.4).
//
// The runtime load set (loadset.go) bounds dynamic loads: when every dynamic load in runtime
// code is scoped to the packages it could reach, the run-wide dynamic_import reason gives way
// to those scoped limits. When req.Package names a locked distribution the load set proves is
// never loaded, the result carries a package_not_loaded Refutation.
func Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.ReachabilityResult{}, err
	}
	cg := callGraphOf(prog)
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.ReachabilityResult{}, err
	}

	paths, reasons := firstPartyPaths(cg, ing, req.Symbols)
	ls := computeLoadSet(req.BuildDir, prog)
	if len(ls.unscoped) == 0 {
		delete(reasons, plugin.PartialReasonDynamicImportSpecifier)
	}
	part := reachabilityPartiality(reasons)
	part.Scoped = append(part.Scoped, ls.scoped...)

	res := plugin.ReachabilityResult{Partiality: part, Paths: paths}
	if name, version, ok := pypiPackageRef(req.Package); ok {
		res.Refutation = ls.refute(name, version)
	}
	return res, nil
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

	// The BFS matches sinks (given as raw SCIP-id strings, req.Symbols) against the graph, so
	// it keys on the SCIP id: every now-Symbol graph field contributes its .SCIP.
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
		p, ok := reachPathToSink(callers, ingressSyms, roots, sink)
		if !ok {
			// No static path from any ingress/root to this sink over the (partial)
			// graph: UNKNOWN, never "safe" (inv.5).
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

// reachPathToSink is the reverse BFS from a single sink to the nearest ingress, falling
// back to the nearest root, returning one representative ingress→sink ReachPath. An
// ingress is preferred over a closer root because module-init roots sit one hop above any
// helper module-level code also calls, and a root-only path drops the attacker-facing entry
// the trace would otherwise carry.
func reachPathToSink(callers map[string][]string, ingressSyms, roots map[string]bool, sink string) (plugin.ReachPath, bool) {
	if sink == "" {
		return plugin.ReachPath{}, false
	}
	// A sink that is itself an ingress/root is trivially reachable. The BFS travels in
	// SCIP-id space (id); the resulting endpoints are wrapped into plugin.Symbol at return.
	type node struct {
		id   string
		path []string
	}
	toPath := func(cur node, ingress bool) plugin.ReachPath {
		trace := make([]plugin.Symbol, len(cur.path))
		for i := range cur.path {
			trace[i] = sym(cur.path[len(cur.path)-1-i])
		}
		var in plugin.Symbol
		if ingress {
			in = sym(cur.id)
		}
		return plugin.ReachPath{Sink: sym(sink), Ingress: in, Trace: trace}
	}
	var rootPath *plugin.ReachPath
	visited := map[string]bool{sink: true}
	queue := []node{{id: sink, path: []string{sink}}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		if ingressSyms[cur.id] {
			return toPath(cur, true), true
		}
		if roots[cur.id] && rootPath == nil {
			p := toPath(cur, false)
			rootPath = &p
		}

		for _, caller := range callers[cur.id] {
			if visited[caller] {
				continue
			}
			visited[caller] = true
			queue = append(queue, node{id: caller, path: append(append([]string{}, cur.path...), caller)})
		}
	}
	if rootPath != nil {
		return *rootPath, true
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
