package goanalysis

import (
	"sort"

	"golang.org/x/tools/go/ssa"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// taintAnalysis is a variable-level, inter-procedural value-flow taint engine
// over SSA. Sources are the parameters of ingress functions (the attacker-
// controllable entry args); a finding is a value-flow path from a source Value to
// a tainted argument of a resolved sink call. Sanitizers clear taint on their
// result (sanitizers.go). Partiality triggers (reflection / cgo / unresolved
// dynamic dispatch) encountered on a tainted path are recorded so the result is
// only ever non-Partial on a fully-resolved, clean flow (inv.5).
type taintAnalysis struct {
	sp    *ssaProgram
	sinks map[string]bool // sink SCIP id -> wanted

	tainted map[ssa.Value]bool // values reached by taint
	// origin records, for a tainted value, the source ingress SCIP id and the
	// SSA function that introduced it, so a sink hit can name its ingress.
	origin map[ssa.Value]taintOrigin
	// onPath holds every SSA function a tainted value flowed through; the
	// path-scoped partiality check runs over exactly these.
	onPath map[*ssa.Function]bool
	// hits maps a sink SCIP id to the ingress SCIP id that reached it.
	hits map[string]string
}

type taintOrigin struct {
	ingress string
	enclFn  *ssa.Function
}

// runTaint seeds sources from ingress functions and propagates taint to a
// fixpoint, returning the discovered source->sink paths and the path-scoped
// partiality. ingresses maps an ingress SCIP id to its SSA function.
func runTaint(sp *ssaProgram, ingresses map[string]*ssa.Function, sinks map[string]bool) ([]plugin.ReachPath, map[string]bool) {
	ta := &taintAnalysis{
		sp:      sp,
		sinks:   sinks,
		tainted: map[ssa.Value]bool{},
		origin:  map[ssa.Value]taintOrigin{},
		onPath:  map[*ssa.Function]bool{},
		hits:    map[string]string{},
	}

	var work []ssa.Value
	seed := func(v ssa.Value, o taintOrigin) {
		if v == nil || ta.tainted[v] {
			return
		}
		ta.tainted[v] = true
		ta.origin[v] = o
		if o.enclFn != nil {
			ta.onPath[o.enclFn] = true
		}
		work = append(work, v)
	}

	// Sources: every parameter of every ingress function is attacker-controllable.
	for sym, fn := range ingresses {
		if fn == nil {
			continue
		}
		o := taintOrigin{ingress: sym, enclFn: fn}
		for _, p := range fn.Params {
			seed(p, o)
		}
		// Method ingresses also expose free vars / the receiver is generally not
		// attacker-controlled, so only parameters are seeded.
	}

	for len(work) > 0 {
		v := work[len(work)-1]
		work = work[:len(work)-1]
		ta.propagate(v, seed)
	}

	reasons := map[string]bool{}
	for fn := range ta.onPath {
		classifyFuncPartiality(fn, reasons)
	}

	var paths []plugin.ReachPath
	for sink, ingress := range ta.hits {
		paths = append(paths, plugin.ReachPath{
			Sink:    sym(sink),
			Ingress: sym(ingress),
			Trace:   []plugin.Symbol{sym(ingress), sym(sink)},
		})
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Sink.SCIP != paths[j].Sink.SCIP {
			return paths[i].Sink.SCIP < paths[j].Sink.SCIP
		}
		return paths[i].Ingress.SCIP < paths[j].Ingress.SCIP
	})
	return paths, reasons
}

// propagate pushes taint from a tainted value v to the values its referrers
// derive from it, forwarding through assignments, phi, field/element access,
// extract, conversions, tainted-operand binops, and (inter-procedurally) from a
// call's actual arg to the callee's formal param. Sanitizer results are NOT
// tainted. A tainted arg to a resolved sink records a finding.
func (ta *taintAnalysis) propagate(v ssa.Value, seed func(ssa.Value, taintOrigin)) {
	o := ta.origin[v]
	refs := v.Referrers()
	if refs == nil {
		return
	}
	for _, instr := range *refs {
		switch in := instr.(type) {
		case *ssa.Phi:
			seed(in, o)
		case *ssa.UnOp:
			// Loads (*x) and other unary ops carry taint forward.
			seed(in, o)
		case *ssa.BinOp:
			// A binary op with a tainted operand yields a tainted result.
			seed(in, o)
		case *ssa.ChangeType:
			seed(in, o)
		case *ssa.Convert:
			seed(in, o)
		case *ssa.ChangeInterface:
			seed(in, o)
		case *ssa.MakeInterface:
			seed(in, o)
		case *ssa.Slice:
			seed(in, o)
		case *ssa.FieldAddr:
			seed(in, o)
		case *ssa.IndexAddr:
			seed(in, o)
		case *ssa.Field:
			seed(in, o)
		case *ssa.Index:
			seed(in, o)
		case *ssa.Extract:
			seed(in, o)
		case *ssa.Store:
			// Storing a tainted value into an address taints that address, so
			// later loads of the address observe taint.
			if in.Val == v {
				seed(in.Addr, o)
			}
		case *ssa.MapUpdate:
			if in.Value == v {
				seed(in.Map, o)
			}
		case ssa.CallInstruction:
			ta.propagateCall(in, v, o, seed)
		}
	}
}

// propagateCall handles taint at a call site where v is a tainted argument:
// records a sink finding, forwards taint into a static callee's matching formal
// parameter (clearing it for sanitizers), and marks the enclosing/called
// functions on the taint path.
func (ta *taintAnalysis) propagateCall(in ssa.CallInstruction, v ssa.Value, o taintOrigin, seed func(ssa.Value, taintOrigin)) {
	common := in.Common()
	if fn := in.Parent(); fn != nil {
		ta.onPath[fn] = true
	}

	callee := common.StaticCallee()

	// Sink check: a tainted value used as an argument to a resolved sink call is
	// a finding. The sink identity is the callee's SCIP id.
	if callee != nil {
		sym := ta.sp.scipFunc(callee)
		if ta.sinks[sym] && argContains(common.Args, v) {
			if _, seen := ta.hits[sym]; !seen {
				ta.hits[sym] = o.ingress
			}
		}
	}

	// Inter-procedural forwarding: taint flows from the actual arg to the callee's
	// formal parameter. A sanitizer call clears taint — its result is not seeded,
	// and we do not forward into its body for sink purposes.
	if callee == nil || callee.Blocks == nil {
		return
	}
	if isSanitizer(callee) {
		return
	}
	ta.onPath[callee] = true
	forwardArgs(common, callee, v, o, seed)

	// The call result carries taint when a tainted value flows in and the callee
	// is not a sanitizer (conservative: an unmodeled transform forwards taint).
	if val, ok := in.(ssa.Value); ok {
		seed(val, o)
	}
}

// forwardArgs seeds the callee's formal parameters that correspond to the tainted
// actual argument v, accounting for the receiver offset on method calls.
func forwardArgs(common *ssa.CallCommon, callee *ssa.Function, v ssa.Value, o taintOrigin, seed func(ssa.Value, taintOrigin)) {
	for i, a := range common.Args {
		if a != v {
			continue
		}
		if i < len(callee.Params) {
			seed(callee.Params[i], taintOrigin{ingress: o.ingress, enclFn: callee})
		}
	}
}

func argContains(args []ssa.Value, v ssa.Value) bool {
	for _, a := range args {
		if a == v {
			return true
		}
	}
	return false
}
