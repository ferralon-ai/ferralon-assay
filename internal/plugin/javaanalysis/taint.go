package javaanalysis

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// javaTaintPrecisionNote records the precision of the Java taint op: it is
// call-graph PATH PRESENCE (an ingress→sink path exists over the source call
// graph), NOT variable-level dataflow. The Go plugin upgrades to SSA value-flow;
// Java has no SSA in the pure-Go/Assess path, so path presence is the honest
// baseline the plugin contract defines for minimal taint. The note travels with
// every result so a consumer never mistakes it for dataflow.
const javaTaintPrecisionNote = "call-graph path presence: an ingress→sink path exists over the source-level Java call graph (ingress ∪ program-root frontier); NOT variable-level dataflow or a sanitizer-aware value-flow model. A path is a structural candidate, not proof that attacker input flows to the sink."

// ComputeTaint reports, for each resolved sink in req.Sinks, whether attacker
// input can reach it, approximated by call-graph PATH PRESENCE from a framework
// ingress (or program root) to the sink — the same reverse BFS Reachability uses.
// It builds on the EXISTING CallGraph/FindIngresses infra (Prove-path enriched
// when the analyzer container is present; pure-Go lexical otherwise), so it needs
// no container of its own and degrades gracefully.
//
// Partiality is honest (inv.5): a requested sink with no reaching ingress is
// declared no_known_ingress — UNKNOWN, never a false "not tainted" — and the
// call-graph/ingress partiality is folded in. A load failure is a hard error
// (inv.4). PrecisionNote is always set so the path-presence limit is explicit.
func ComputeTaint(ctx context.Context, req plugin.ComputeTaintRequest) (plugin.TaintResult, error) {
	// TODO(perf): this reparses the tree independently of CallGraph's internal
	// loadProgram — acceptable for pass 1 (zero-egress, deterministic); CallGraph
	// could instead return its program to avoid the second parse.
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.TaintResult{}, err
	}
	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.TaintResult{}, err
	}
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.TaintResult{}, err
	}

	paths, reasons := firstPartyPaths(prog, cg, ing, req.Sinks)

	return plugin.TaintResult{
		Partiality:    reachabilityPartiality(reasons),
		Paths:         paths,
		PrecisionNote: javaTaintPrecisionNote,
	}, nil
}
