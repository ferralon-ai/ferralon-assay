package goanalysis

import (
	"sort"

	"golang.org/x/tools/go/ssa"
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
	sinks map[string]bool // sink SCIP id -> wanted; nil wants every callee

	tainted map[ssa.Value]bool // values reached by taint
	// origin records, for a tainted value, the source ingress SCIP id and the
	// SSA function that introduced it, so a sink hit can name its ingress.
	origin map[ssa.Value]taintOrigin
	// onPath holds every SSA function a tainted value flowed through; the
	// path-scoped partiality check runs over exactly these.
	onPath map[*ssa.Function]bool
	// hits maps a sink SCIP id to the ingress SCIP id that reached it.
	hits map[string]string
	// clearing marks the pass that follows sanitized values rather than tainted ones: a
	// sanitizer's result stays in the flow instead of leaving it.
	clearing bool
	// cleared holds the result of every sanitizer call a tainted value reached; the clearing
	// pass is seeded from them.
	cleared []ssa.Value
	work    []ssa.Value
}

type taintOrigin struct {
	ingress string
	enclFn  *ssa.Function
}

// runTaint seeds sources from ingress functions and propagates taint to a
// fixpoint, returning each sink reached mapped to its attributed ingress, the
// path-scoped partiality, and the sinks a sanitized value was observed reaching as
// an argument. ingresses maps an ingress SCIP id to its SSA function; a nil sinks
// records every static callee a tainted (or sanitized) argument reaches.
func runTaint(sp *ssaProgram, ingresses map[string]*ssa.Function, sinks map[string]bool) (map[string]string, map[string]bool, map[string]bool) {
	ta := newTaintAnalysis(sp, sinks)

	// Sources: every parameter of every ingress function is attacker-controllable. A sink keeps the
	// first ingress that reaches it, so seeding in map order would attribute a sink reached by two
	// ingresses to either one from run to run. Each ingress is seeded and drained to a fixpoint in
	// ascending symbol order, so a lower ingress's flow claims everything it reaches, the parameters of
	// any ingress it calls included, before a higher one is seeded: every sink is attributed to the
	// lowest ingress symbol that reaches it.
	syms := make([]string, 0, len(ingresses))
	for sym := range ingresses {
		syms = append(syms, sym)
	}
	sort.Strings(syms)
	for _, sym := range syms {
		fn := ingresses[sym]
		if fn == nil {
			continue
		}
		o := taintOrigin{ingress: sym, enclFn: fn}
		// Method ingresses also expose free vars / the receiver is generally not
		// attacker-controlled, so only parameters are seeded.
		for _, p := range fn.Params {
			ta.seed(p, o)
		}
		ta.drain()
	}

	reasons := map[string]bool{}
	for fn := range ta.onPath {
		classifyFuncPartiality(fn, reasons)
	}

	// The clearing pass follows each sanitizer result the tainted flow produced, over the same
	// propagation, and records the sinks it reaches. Its path carries no partiality of its own: a
	// trigger that could hide an unsanitized flow lies on the tainted flow, already counted above.
	cl := newTaintAnalysis(sp, sinks)
	cl.clearing = true
	for _, v := range ta.cleared {
		cl.seed(v, taintOrigin{})
	}
	cl.drain()
	sanitized := make(map[string]bool, len(cl.hits))
	for s := range cl.hits {
		sanitized[s] = true
	}

	return ta.hits, reasons, sanitized
}

func newTaintAnalysis(sp *ssaProgram, sinks map[string]bool) *taintAnalysis {
	return &taintAnalysis{
		sp:      sp,
		sinks:   sinks,
		tainted: map[ssa.Value]bool{},
		origin:  map[ssa.Value]taintOrigin{},
		onPath:  map[*ssa.Function]bool{},
		hits:    map[string]string{},
	}
}

func (ta *taintAnalysis) seed(v ssa.Value, o taintOrigin) {
	if v == nil || ta.tainted[v] {
		return
	}
	ta.tainted[v] = true
	ta.origin[v] = o
	if o.enclFn != nil {
		ta.onPath[o.enclFn] = true
	}
	ta.work = append(ta.work, v)
}

func (ta *taintAnalysis) drain() {
	for len(ta.work) > 0 {
		v := ta.work[len(ta.work)-1]
		ta.work = ta.work[:len(ta.work)-1]
		ta.propagate(v, ta.seed)
	}
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
		if (ta.sinks == nil || ta.sinks[sym]) && argContains(common.Args, v) {
			if _, seen := ta.hits[sym]; !seen {
				ta.hits[sym] = o.ingress
			}
		}
	}

	// A sanitizer call clears taint: its result is not seeded and its body is not
	// entered. The result is kept for the clearing pass, which carries it on.
	if isSanitizer(callee) {
		if val, ok := in.(ssa.Value); ok {
			if ta.clearing {
				seed(val, o)
			} else {
				ta.cleared = append(ta.cleared, val)
			}
		}
		return
	}

	// Inter-procedural forwarding: taint flows from the actual arg to the callee's
	// formal parameter.
	if callee == nil || callee.Blocks == nil {
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
