package dotnetanalysis

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Reachability reports, for each resolved sink symbol in req.Symbols, whether a static
// call-graph path connects a framework ingress (or program-entry root) to that sink in the
// module at req.BuildDir.
//
// It has TWO tiers, chosen by whether the first-party COMPILED IL is present in the build
// output (PLAN-350 barrier-4b):
//
//   - STRONG (IL): when the first-party assembly locates+reads out of bin/publish, the op
//     runs the whole-program two-trace PoNE engine (depreach) over the spanning assembly
//     set. Because it resolves virtual/interface dispatch over real IL and tracks
//     completeness hazards, it CAN soundly emit a confident-safe (a clean, undetermined-free
//     result) — the EXCEED-Go capability a genuine NotExploitable earns. See ilReachability.
//   - LEXICAL (degrade): when the first-party IL is absent or a reader parse-hazard, the op
//     degrades to the source-lexical reverse-BFS below and declares tool_failure so the
//     caller never mistakes the fallback for the IL confident-safe. It NEVER emits an empty
//     IL graph and NEVER a not_exploitable-equivalent from the degrade (reachability.go).
//
// LOAD-BEARING honesty posture of the LEXICAL tier (inv.5): C# static reachability is
// STRUCTURALLY WEAK under a lexical scan (interface dispatch, virtual/override methods,
// dependency injection, and reflection are all invisible to a pure-Go call graph — scope §5
// R1, which need scip-dotnet at Prove-tier that Assess does NOT have), so it ALWAYS declares
// Partial(dynamic_dispatch) — even when a path IS found. It is a candidate NARROWER, not an
// adjudicator: the effect trial adjudicates. "Not reached" is UNKNOWN (no_known_ingress),
// NEVER a confident "safe"/not-affected. A load failure in the lexical fallback stays a hard
// error (inv.4).
func Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	// STRONG tier: use the IL whole-program engine when the first-party compiled IL is
	// present. It returns handled=false to DEGRADE (no first-party IL / a reader hazard).
	if res, handled := ilReachability(req); handled {
		return res, nil
	}
	res, err := lexicalReachability(ctx, req)
	if err != nil {
		return plugin.ReachabilityResult{}, err // load failure of the fallback stays hard (inv.4)
	}
	// The degrade is DECLARED: tool_failure marks that the IL confident-safe path did not
	// run, so the caller never reads the lexical candidate-narrower as a proven result.
	res.Partiality = withReason(res.Partiality, plugin.PartialReasonToolFailure)
	return res, nil
}

// lexicalReachability is the source-lexical candidate-narrower — the DEGRADE target when the
// first-party compiled IL is not present. It reuses the EXISTING CallGraph and FindIngresses
// and reverse-BFSes each sink toward the nearest ingress/root.
func lexicalReachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
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
// STANDING dynamic_dispatch reason that makes C# reachability/taint ALWAYS Partial — a found
// path is a structural candidate, never proof, because a lexical scanner cannot see C#'s
// interface/virtual/DI/reflection edges. Shared by Reachability and ComputeTaint.
func firstPartyPaths(cg plugin.CallGraphResult, ing plugin.IngressResult, sinks []string) ([]plugin.ReachPath, map[string]bool) {
	// C# is structurally weak: reachability/taint are NEVER Complete. Seed the standing
	// partiality reason unconditionally (inv.5).
	reasons := map[string]bool{plugin.PartialReasonDynamicDispatch: true}
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
		p, ok := reachPathToSink(callers, ingressSyms, roots, sink)
		if !ok {
			// No static path from any ingress/root to this sink over the (partial) graph:
			// UNKNOWN, never "safe" (inv.5).
			reasons[plugin.PartialReasonNoIngress] = true
			continue
		}
		if p.Ingress == (plugin.Symbol{}) {
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
			// Mint Symbols at the output boundary; sym("") == plugin.Symbol{}, so a
			// root-only path carries the zero Ingress the contract's omitempty expects.
			return plugin.ReachPath{Sink: sym(sink), Ingress: sym(ingress), Trace: symbols(trace)}, true
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

// reachabilityPartiality collapses the accumulated reason set into a Partiality. For C# it
// is NEVER Complete: firstPartyPaths always seeds dynamic_dispatch, so the set is non-empty
// by construction. reasons are sorted for a stable payload.
func reachabilityPartiality(reasons map[string]bool) plugin.Partiality {
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(sortedKeys(reasons)...)
}

// symbols mints a Symbol for each SCIP id in order, converting an internal string trace to
// the contract's []plugin.Symbol at the output boundary via the one per-package mint site.
func symbols(ss []string) []plugin.Symbol {
	out := make([]plugin.Symbol, len(ss))
	for i, s := range ss {
		out[i] = sym(s)
	}
	return out
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
