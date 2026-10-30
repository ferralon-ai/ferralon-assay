package goanalysis

import (
	"context"
	"encoding/json"
	"fmt"

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
	c, err := taintClosureOf(ctx, req.BuildDir)
	if err != nil {
		return plugin.TaintResult{}, err
	}
	return c.result(req.Sinks), nil
}

// taintClosure is one taint pass over a tree, from every ingress, with a hit recorded at every
// static callee a tainted value reaches as an argument. The sinks a run asks about never change the
// pass, only which of its hits that run reports, so every advisory's result is a filter of the one
// closure and the run cache keeps it once per tree.
type taintClosure struct {
	// Hits maps each callee a tainted argument reaches to the ingress attributed to it.
	Hits map[string]string `json:"hits,omitempty"`
	// Reasons is the partiality no sink changes: the load's, with its scoped limits counted
	// run-wide, and the triggers on the tainted flow.
	Reasons []string `json:"reasons,omitempty"`
}

// taintClosureOf returns buildDir's taint closure, computed once per tree per scan through the run
// cache. A failed load is never cached, so it fails every run that asks (inv.4).
func taintClosureOf(ctx context.Context, buildDir string) (taintClosure, error) {
	b, err := runCached(ctx, "taint", loadCacheKey(buildDir), func() ([]byte, error) {
		c, err := computeTaintClosure(ctx, buildDir)
		if err != nil {
			return nil, err
		}
		return json.Marshal(c)
	})
	if err != nil {
		return taintClosure{}, err
	}
	var c taintClosure
	if err := json.Unmarshal(b, &c); err != nil {
		return taintClosure{}, fmt.Errorf("decode cached taint: %w", err)
	}
	return c, nil
}

func computeTaintClosure(ctx context.Context, buildDir string) (taintClosure, error) {
	sp, res, err := loadSSA(ctx, buildDir)
	if err != nil {
		return taintClosure{}, err
	}
	hits, pathReasons := runTaint(sp, sp.resolveIngressFuncs(ingressesOf(sp, res).Ingresses), nil)

	reasons := map[string]bool{}
	// Fold in load-level partiality (a degraded load is never hidden, inv.5).
	for _, r := range res.Partiality.Reasons {
		reasons[r] = true
	}
	// Taint results carry no scoped limits; a bounded one counts run-wide here.
	for _, r := range res.Partiality.Scoped {
		reasons[r.Reason] = true
	}
	// Fold in the triggers found on the tainted flow paths.
	for r := range pathReasons {
		reasons[r] = true
	}
	return taintClosure{Hits: hits, Reasons: sortedKeys(reasons)}, nil
}

// result is the taint result for sinks: a path for each sink the closure reached, attributed to its
// ingress, and the closure's partiality.
func (c taintClosure) result(sinks []string) plugin.TaintResult {
	reasons := make(map[string]bool, len(c.Reasons))
	for _, r := range c.Reasons {
		reasons[r] = true
	}
	want := map[string]bool{}
	for _, s := range sinks {
		if s != "" {
			want[s] = true
		}
	}
	var paths []plugin.ReachPath
	for _, s := range sortedKeys(want) {
		ingress, ok := c.Hits[s]
		if !ok {
			// A requested sink with no resolved tainted flow from any ingress is UNKNOWN,
			// never "safe" (inv.5): declare no_known_ingress.
			reasons[plugin.PartialReasonNoIngress] = true
			continue
		}
		paths = append(paths, plugin.ReachPath{
			Sink:    sym(s),
			Ingress: sym(ingress),
			Trace:   []plugin.Symbol{sym(ingress), sym(s)},
		})
	}

	part := plugin.Complete()
	if len(reasons) > 0 {
		part = plugin.Partial(sortedKeys(reasons)...)
	}
	return plugin.TaintResult{
		Partiality:    part,
		Paths:         paths,
		PrecisionNote: taintPrecisionNote,
	}
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
		id := s.scipFunc(fn)
		if prev, ok := bySymbol[id]; ok && !resolvesBefore(fn, prev) {
			continue
		}
		bySymbol[id] = fn
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

// resolvesBefore reports whether a, rather than b, is the function their shared SCIP id names. A
// method's bound wrapper and thunk, and each instance of a generic function, carry the declared
// function's id. The id names the declared function, so it wins; among synthetic functions alone
// the lowest name does, so the choice never follows map order.
func resolvesBefore(a, b *ssa.Function) bool {
	if (a.Synthetic == "") != (b.Synthetic == "") {
		return a.Synthetic == ""
	}
	return a.String() < b.String()
}
