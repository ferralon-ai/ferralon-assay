package pythonanalysis

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// pyTaintPrecisionNote records the precision of the Python taint op: it is call-graph PATH
// PRESENCE (an ingress→sink path exists over the source call graph), NOT variable-level
// dataflow. A pure lexical Python scanner has no SSA, no type information, and no def-use
// chains, so it cannot model whether a tainted value (an ingress parameter) actually flows
// into the sink's argument, nor whether a sanitizer intervenes. The note travels with
// every result so a consumer never mistakes it for value flow.
const pyTaintPrecisionNote = "call-graph path presence: an ingress→sink path exists over the source-level Python call graph (ingress ∪ program-root frontier); NOT variable-level dataflow or a sanitizer-aware value-flow model. A path is a structural candidate, not proof that attacker input flows to the sink — and Python's dynamic dispatch makes even the path graph an under-approximation."

// ComputeTaint reports, for each resolved sink in req.Sinks, whether attacker input can
// reach it, approximated by call-graph PATH PRESENCE from a framework ingress (or program
// root) to the sink — the same reverse BFS Reachability uses. It reuses the EXISTING
// CallGraph/FindIngresses, so it needs no container of its own.
//
// ALWAYS declared Partial by construction (inv.5): firstPartyPaths seeds dynamic_dispatch
// unconditionally, so the result is NEVER Complete — a lexical Python scanner can neither
// prove the tainted ingress VALUE reaches the sink ARGUMENT nor see Python's dynamic
// edges. PrecisionNote records the standing value-flow limit. A requested sink with no
// reaching ingress declares no_known_ingress (UNKNOWN, never "not tainted"). A load
// failure is a hard error (inv.4).
func ComputeTaint(ctx context.Context, req plugin.ComputeTaintRequest) (plugin.TaintResult, error) {
	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.TaintResult{}, err
	}
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.TaintResult{}, err
	}

	paths, reasons := firstPartyPaths(cg, ing, req.Sinks)

	return plugin.TaintResult{
		Partiality:    reachabilityPartiality(reasons),
		Paths:         paths,
		PrecisionNote: pyTaintPrecisionNote,
	}, nil
}
