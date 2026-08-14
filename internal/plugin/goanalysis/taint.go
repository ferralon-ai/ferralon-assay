package goanalysis

import (
	"context"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// taintPrecisionNote records that this op is variable-level SSA value-flow taint
// with a membership-based sanitizer model — not symbolic/constraint reasoning. It
// is set on every result so the precision/limits of the analysis travel with it.
const taintPrecisionNote = "variable-level SSA value-flow: source (ingress parameter) -> sink argument over def-use + inter-procedural arg->param forwarding, with a membership-based sanitizer model (sanitizers.go); not symbolic/value-range reasoning"

// ComputeTaint reports, for each resolved sink, whether attacker-controllable
// ingress input reaches a tainted argument of the sink via VARIABLE-LEVEL SSA
// value flow (not call-graph path presence). Sources are the parameters of the
// discovered ingress functions; taint propagates over SSA def-use edges
// (assignment, phi, field/element access, extract, conversions, tainted-operand
// binops) and inter-procedurally from actual arg to callee formal param. A
// modeled sanitizer (sanitizers.go) clears taint on its result, so a value that
// reaches a sink only through a sanitizer is a true negative and is NOT reported.
//
// Precision (the upgrade over path-presence): the result is non-Partial when the
// source->sink flow is fully resolved in SSA AND no partiality trigger
// (reflection / cgo / unresolved dynamic dispatch) lies on the tainted path. It
// degrades to Partial WITH a reason when any trigger is on the path, or when a
// requested sink has no resolved tainted flow from any ingress
// (no_known_ingress). It NEVER renders an unknown as "safe" (inv.5). A load/SSA
// failure is a hard error (inv.4).
func ComputeTaint(ctx context.Context, req plugin.ComputeTaintRequest) (plugin.TaintResult, error) {
	sp, res, err := loadSSA(ctx, req.BuildDir)
	if err != nil {
		return plugin.TaintResult{}, err
	}

	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.TaintResult{}, err
	}
	ingresses := sp.resolveIngressFuncs(ing.Ingresses)

	sinks := make(map[string]bool, len(req.Sinks))
	for _, s := range req.Sinks {
		if s != "" {
			sinks[s] = true
		}
	}

	paths, pathReasons := runTaint(sp, ingresses, sinks)

	reasons := map[string]bool{}
	// Fold in load-level partiality (a degraded load is never hidden, inv.5).
	for _, r := range res.Partiality.Reasons {
		reasons[r] = true
	}
	// Fold in the triggers found on the tainted flow paths.
	for r := range pathReasons {
		reasons[r] = true
	}

	// A requested sink with no resolved tainted flow from any ingress is UNKNOWN,
	// never "safe" (inv.5): declare no_known_ingress.
	hit := make(map[string]bool, len(paths))
	for _, p := range paths {
		hit[p.Sink.SCIP] = true
	}
	for s := range sinks {
		if !hit[s] {
			reasons[plugin.PartialReasonNoIngress] = true
		}
	}

	part := plugin.Complete()
	if len(reasons) > 0 {
		part = plugin.Partial(sortedKeys(reasons)...)
	}

	return plugin.TaintResult{
		Partiality:    part,
		Paths:         paths,
		PrecisionNote: taintPrecisionNote,
	}, nil
}

// resolveIngressFuncs maps each ingress symbol (by SCIP id) to its SSA function
// by indexing every built function's SCIP id once. Ingresses whose function is
// not in the SSA program (e.g. a handler value with no static body) are dropped:
// absence of a source is honestly no source, never a fabricated one.
func (s *ssaProgram) resolveIngressFuncs(ingresses []plugin.Ingress) map[string]*ssa.Function {
	bySymbol := map[string]*ssa.Function{}
	for fn := range ssautil.AllFunctions(s.prog) {
		if fn.Blocks == nil {
			continue
		}
		bySymbol[s.scipFunc(fn)] = fn
	}

	out := map[string]*ssa.Function{}
	for _, in := range ingresses {
		if in.Symbol.SCIP == "" {
			continue
		}
		if fn, ok := bySymbol[in.Symbol.SCIP]; ok {
			out[in.Symbol.SCIP] = fn
		}
	}
	return out
}
