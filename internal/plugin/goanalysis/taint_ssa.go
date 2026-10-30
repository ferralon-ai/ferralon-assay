package goanalysis

import (
	"go/types"
	"sort"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
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
	idx   *taintIndex
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

	// ambient marks each function taint entered other than through the arguments of a call
	// the pass followed: an ingress, a closure's free variable, a global, a write through a
	// callee's parameter, or a returned value. Such a function's tainted return reaches callers
	// whose call results the pass has not seeded. returns marks each function that returns a
	// tainted value, backWrites each one a tainted value was written back through a parameter
	// of, and forwarded each one whose return has been carried to its callers.
	ambient    map[*ssa.Function]bool
	returns    map[*ssa.Function]bool
	backWrites map[*ssa.Function]bool
	forwarded  map[*ssa.Function]bool
	// lost records that the pass dropped a tainted value at an edge it cannot follow, so an
	// unsanitized flow may reach a sink unobserved. While it is set no sink counts as reached
	// only by sanitized flows.
	lost bool
}

type taintOrigin struct {
	ingress string
	enclFn  *ssa.Function
}

// taintIndex holds the program-wide facts the pass needs to carry taint against the def-use
// direction SSA records: each function's static call sites (a value it returns, or writes
// through a parameter, reaches the caller there), the closures built over each function (a free
// variable's binding), the instructions that use each package-level variable (SSA records no
// referrers for a global), and the functions used as values, whose callers it cannot enumerate.
type taintIndex struct {
	calls    map[*ssa.Function][]ssa.CallInstruction
	closures map[*ssa.Function][]*ssa.MakeClosure
	globals  map[*ssa.Global][]ssa.Instruction
	taken    map[*ssa.Function]bool
}

func buildTaintIndex(prog *ssa.Program) *taintIndex {
	idx := &taintIndex{
		calls:    map[*ssa.Function][]ssa.CallInstruction{},
		closures: map[*ssa.Function][]*ssa.MakeClosure{},
		globals:  map[*ssa.Global][]ssa.Instruction{},
		taken:    map[*ssa.Function]bool{},
	}
	var ops []*ssa.Value
	for fn := range ssautil.AllFunctions(prog) {
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				var callee *ssa.Value
				switch in := instr.(type) {
				case ssa.CallInstruction:
					c := in.Common()
					if f := c.StaticCallee(); f != nil && !c.IsInvoke() {
						idx.calls[f] = append(idx.calls[f], in)
						callee = &c.Value
					}
				case *ssa.MakeClosure:
					f := in.Fn.(*ssa.Function)
					idx.closures[f] = append(idx.closures[f], in)
					callee = &in.Fn
					if !onlyCalled(in) {
						idx.taken[f] = true
					}
				}
				ops = instr.Operands(ops[:0])
				for _, op := range ops {
					if op == nil || *op == nil {
						continue
					}
					switch x := (*op).(type) {
					case *ssa.Function:
						if op != callee {
							idx.taken[x] = true
						}
					case *ssa.Global:
						idx.globals[x] = append(idx.globals[x], instr)
					}
				}
			}
		}
	}
	return idx
}

// onlyCalled reports whether a closure value is only ever called directly, so every call of its
// function is a static call site.
func onlyCalled(mc *ssa.MakeClosure) bool {
	refs := mc.Referrers()
	if refs == nil {
		return true
	}
	for _, r := range *refs {
		call, ok := r.(ssa.CallInstruction)
		if !ok || call.Common().IsInvoke() || call.Common().Value != ssa.Value(mc) {
			return false
		}
	}
	return true
}

// runTaint seeds sources from ingress functions and propagates taint to a
// fixpoint, returning each sink reached mapped to its attributed ingress, the
// path-scoped partiality, and the sinks a sanitized value was observed reaching as
// an argument. ingresses maps an ingress SCIP id to its SSA function; a nil sinks
// records every static callee a tainted (or sanitized) argument reaches.
func runTaint(sp *ssaProgram, ingresses map[string]*ssa.Function, sinks map[string]bool) (map[string]string, map[string]bool, map[string]bool) {
	idx := buildTaintIndex(sp.prog)
	ta := newTaintAnalysis(sp, idx, sinks)

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
			ta.arrive(p, o)
		}
		ta.drain()
	}

	reasons := map[string]bool{}
	for fn := range ta.onPath {
		classifyFuncPartiality(fn, reasons)
	}

	// A sink counts as reached only by sanitized flows when no tainted value was dropped: a
	// dropped value is an unsanitized flow the pass did not observe, and it may reach that sink.
	if ta.lost {
		return ta.hits, reasons, nil
	}

	// The clearing pass follows each sanitizer result the tainted flow produced, over the same
	// propagation, and records the sinks it reaches. Its path carries no partiality of its own: a
	// trigger that could hide an unsanitized flow lies on the tainted flow, already counted above.
	cl := newTaintAnalysis(sp, idx, sinks)
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

func newTaintAnalysis(sp *ssaProgram, idx *taintIndex, sinks map[string]bool) *taintAnalysis {
	return &taintAnalysis{
		sp:         sp,
		idx:        idx,
		sinks:      sinks,
		tainted:    map[ssa.Value]bool{},
		origin:     map[ssa.Value]taintOrigin{},
		onPath:     map[*ssa.Function]bool{},
		hits:       map[string]string{},
		ambient:    map[*ssa.Function]bool{},
		returns:    map[*ssa.Function]bool{},
		backWrites: map[*ssa.Function]bool{},
		forwarded:  map[*ssa.Function]bool{},
	}
}

// seed taints v, reporting whether it was untainted.
func (ta *taintAnalysis) seed(v ssa.Value, o taintOrigin) bool {
	if v == nil || ta.tainted[v] {
		return false
	}
	ta.tainted[v] = true
	ta.origin[v] = o
	if o.enclFn != nil {
		ta.onPath[o.enclFn] = true
	}
	ta.work = append(ta.work, v)
	return true
}

// arrive taints v where taint enters its function from outside the call that the pass followed
// into it.
func (ta *taintAnalysis) arrive(v ssa.Value, o taintOrigin) {
	if v == nil {
		return
	}
	fn := v.Parent()
	if fn != nil {
		o = taintOrigin{ingress: o.ingress, enclFn: fn}
	}
	if ta.seed(v, o) {
		ta.enter(fn, o)
	}
}

// enter marks fn ambient: taint reached it other than through a followed call's arguments, so a
// tainted value it returns, or writes back through a parameter, reaches callers whose call results
// and arguments the pass has not seeded.
func (ta *taintAnalysis) enter(fn *ssa.Function, o taintOrigin) {
	if fn == nil || ta.ambient[fn] {
		return
	}
	ta.ambient[fn] = true
	if ta.returns[fn] {
		ta.forwardReturn(fn, o)
	}
	if ta.backWrites[fn] && dynamicallyCalled(fn, ta.idx) {
		ta.lost = true
	}
}

func (ta *taintAnalysis) drain() {
	for len(ta.work) > 0 {
		v := ta.work[len(ta.work)-1]
		ta.work = ta.work[:len(ta.work)-1]
		ta.propagate(v)
	}
}

// propagate pushes taint from a tainted value v to the values its referrers derive from it:
// every value an instruction computes from a tainted operand is tainted, inter-procedurally from
// a call's actual arg to the callee's formal param and back from a callee's return, a write of a
// tainted value taints the object written (taintObject), and a tainted closure binding taints the
// closure's free variable. Sanitizer results are NOT tainted. A tainted arg to a resolved sink
// records a finding. An edge the pass cannot follow sets lost.
func (ta *taintAnalysis) propagate(v ssa.Value) {
	o := ta.origin[v]
	seed := func(x ssa.Value) { ta.seed(x, o) }
	var refs []ssa.Instruction
	if g, ok := v.(*ssa.Global); ok {
		// A global has no referrers in SSA; every function that uses it gains taint from outside.
		for _, instr := range ta.idx.globals[g] {
			if val, ok := instr.(ssa.Value); ok {
				ta.arrive(val, o)
				continue
			}
			refs = append(refs, instr)
		}
	} else if r := v.Referrers(); r != nil {
		refs = *r
	}
	for _, instr := range refs {
		switch in := instr.(type) {
		case *ssa.Phi, *ssa.UnOp, *ssa.BinOp, *ssa.ChangeType, *ssa.Convert, *ssa.MultiConvert,
			*ssa.ChangeInterface, *ssa.MakeInterface, *ssa.SliceToArrayPointer, *ssa.TypeAssert,
			*ssa.Slice, *ssa.FieldAddr, *ssa.IndexAddr, *ssa.Field, *ssa.Index, *ssa.Lookup,
			*ssa.Extract, *ssa.Range, *ssa.Next, *ssa.MakeMap, *ssa.MakeChan, *ssa.MakeSlice:
			seed(in.(ssa.Value))
		case *ssa.Store:
			// A tainted value written into an address taints the object, so later loads
			// through any handle on it observe taint.
			if in.Val == v {
				ta.taintObject(in.Addr, o)
			}
		case *ssa.MapUpdate:
			if in.Value == v || in.Key == v {
				ta.taintObject(in.Map, o)
			}
		case *ssa.Send:
			if in.X == v {
				ta.taintObject(in.Chan, o)
			}
		case *ssa.Select:
			for _, st := range in.States {
				if st.Send == v {
					ta.taintObject(st.Chan, o)
				}
				if st.Chan == v && st.Dir == types.RecvOnly {
					seed(in)
				}
			}
		case *ssa.MakeClosure:
			// A captured tainted value taints the closure's free variable, and the closure.
			fn := in.Fn.(*ssa.Function)
			for i, b := range in.Bindings {
				if b == v && i < len(fn.FreeVars) {
					ta.arrive(fn.FreeVars[i], o)
				}
			}
			seed(in)
		case *ssa.Return:
			ta.returnTainted(in.Parent(), o)
		case *ssa.Panic:
			// recover() hands the value to whichever deferred call recovers it.
			ta.lost = true
		case ssa.CallInstruction:
			ta.propagateCall(in, v, o)
		}
		// If and DebugRef carry no data; Jump and RunDefers take no operands.
	}
}

// propagateCall handles taint at a call site where v is a tainted operand: records
// a sink finding, forwards taint into a static callee's matching formal parameter
// (clearing it for sanitizers), carries it to the call's result, and marks the
// enclosing/called functions on the taint path.
func (ta *taintAnalysis) propagateCall(in ssa.CallInstruction, v ssa.Value, o taintOrigin) {
	common := in.Common()
	if fn := in.Parent(); fn != nil {
		ta.onPath[fn] = true
	}
	val, _ := in.(ssa.Value) // a go or defer statement has no result

	if b, ok := common.Value.(*ssa.Builtin); ok {
		ta.propagateBuiltin(b, common, v, val, o)
		return
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
		if val != nil {
			if ta.clearing {
				ta.seed(val, o)
			} else {
				ta.cleared = append(ta.cleared, val)
			}
		}
		return
	}

	// A callee whose body the pass does not hold (a dependency, or a call through an interface
	// or a func value) is an unmodeled transform: its result carries the taint, and so does any
	// object it was handed, since it may write the tainted value there. A call through a value
	// may also run first-party code the pass cannot enter.
	if callee == nil || callee.Blocks == nil {
		if val != nil {
			ta.seed(val, o)
		}
		ta.writeArgs(common, o)
		if callee == nil {
			ta.lost = true
		}
		return
	}

	// Inter-procedural forwarding: taint flows from the actual arg to the callee's
	// formal parameter.
	ta.onPath[callee] = true
	forwardArgs(common, callee, v, o, ta.seed)

	// The call result carries taint when a tainted value flows in and the callee
	// is not a sanitizer (conservative: an unmodeled transform forwards taint).
	if val != nil {
		ta.seed(val, o)
	}
}

// propagateBuiltin carries taint across a builtin call. Every builtin with a result derives it
// from its operands, so the result is tainted (append, min, max, len, cap, complex, real, imag,
// recover-free unsafe conversions, and SSA's own wrapnilchk). append and copy also write their
// tainted operands into the destination's backing array. The rest (print, println, delete,
// close, clear) return nothing and write nothing a later read observes.
func (ta *taintAnalysis) propagateBuiltin(b *ssa.Builtin, common *ssa.CallCommon, v, val ssa.Value, o taintOrigin) {
	if val != nil {
		ta.seed(val, o)
	}
	switch b.Name() {
	case "append":
		if len(common.Args) > 0 && common.Args[0] != v {
			ta.taintObject(common.Args[0], o)
		}
	case "copy":
		if len(common.Args) == 2 && common.Args[1] == v {
			ta.taintObject(common.Args[0], o)
		}
	}
}

// writeArgs taints every object a call whose body the pass does not hold was handed, since it
// may write a tainted operand there. A func value handed to it may be called with the taint, in
// code the pass cannot follow.
func (ta *taintAnalysis) writeArgs(common *ssa.CallCommon, o taintOrigin) {
	args := common.Args
	if common.IsInvoke() {
		args = append([]ssa.Value{common.Value}, args...)
	}
	for _, a := range args {
		if _, ok := a.Type().Underlying().(*types.Signature); ok {
			ta.lost = true
			continue
		}
		ta.taintObject(a, o)
	}
}

// taintObject marks tainted the object x refers to, because a tainted value was written into it:
// x and every value it was derived from by address arithmetic, loads and conversions, up to the
// roots that name the object. A fresh allocation is the object itself. A parameter's object is
// the caller's, so the write reaches each static caller's argument; a free variable's is the
// enclosing function's binding; a global's uses all observe it. An object reached from a call's
// result may be held through another handle the pass does not relate to it: that sets lost. A
// value that holds no reference cannot be written through, and an already-tainted value's object
// already carries taint.
func (ta *taintAnalysis) taintObject(x ssa.Value, o taintOrigin) {
	if x == nil || ta.tainted[x] || !holdsRef(x.Type()) {
		return
	}
	ta.seed(x, taintOrigin{ingress: o.ingress, enclFn: x.Parent()})
	switch x := x.(type) {
	case *ssa.FieldAddr:
		ta.taintObject(x.X, o)
	case *ssa.IndexAddr:
		ta.taintObject(x.X, o)
	case *ssa.Field:
		ta.taintObject(x.X, o)
	case *ssa.Index:
		ta.taintObject(x.X, o)
	case *ssa.Slice:
		ta.taintObject(x.X, o)
	case *ssa.Lookup:
		ta.taintObject(x.X, o)
	case *ssa.UnOp:
		ta.taintObject(x.X, o)
	case *ssa.ChangeType:
		ta.taintObject(x.X, o)
	case *ssa.Convert:
		ta.taintObject(x.X, o)
	case *ssa.MultiConvert:
		ta.taintObject(x.X, o)
	case *ssa.ChangeInterface:
		ta.taintObject(x.X, o)
	case *ssa.MakeInterface:
		ta.taintObject(x.X, o)
	case *ssa.TypeAssert:
		ta.taintObject(x.X, o)
	case *ssa.SliceToArrayPointer:
		ta.taintObject(x.X, o)
	case *ssa.Extract:
		ta.taintObject(x.Tuple, o)
	case *ssa.Phi:
		for _, e := range x.Edges {
			ta.taintObject(e, o)
		}
	case *ssa.Parameter:
		ta.writeBack(x, o)
	case *ssa.FreeVar:
		fn := x.Parent()
		for i, fv := range fn.FreeVars {
			if fv != x {
				continue
			}
			for _, mc := range ta.idx.closures[fn] {
				if i < len(mc.Bindings) {
					ta.arriveObject(mc.Bindings[i], o)
				}
			}
		}
	case *ssa.Alloc, *ssa.MakeMap, *ssa.MakeSlice, *ssa.MakeChan, *ssa.MakeClosure, *ssa.Const,
		*ssa.Global, *ssa.Function:
		// The object itself; a global's uses are reached through the index when it propagates.
	default:
		// A call's result, a received or ranged value: the object may be shared with handles
		// the pass does not relate to this one.
		ta.lost = true
	}
}

// arriveObject taints the object x refers to, in a function taint entered from outside.
func (ta *taintAnalysis) arriveObject(x ssa.Value, o taintOrigin) {
	if x == nil || ta.tainted[x] || !holdsRef(x.Type()) {
		return
	}
	ta.taintObject(x, o)
	ta.enter(x.Parent(), o)
}

// writeBack carries a write through parameter p of fn to the argument each static caller passed
// for it. A caller the pass cannot enumerate (fn is a method, or used as a value) is lost once
// taint can enter fn from outside its callers' arguments.
func (ta *taintAnalysis) writeBack(p *ssa.Parameter, o taintOrigin) {
	fn := p.Parent()
	i := -1
	for j, q := range fn.Params {
		if q == p {
			i = j
		}
	}
	if i < 0 {
		return
	}
	for _, call := range ta.idx.calls[fn] {
		if args := call.Common().Args; i < len(args) {
			ta.arriveObject(args[i], o)
		}
	}
	ta.backWrites[fn] = true
	if ta.ambient[fn] && dynamicallyCalled(fn, ta.idx) {
		ta.lost = true
	}
}

// returnTainted records that fn returns a tainted value and, once taint can enter fn other than
// through a followed call's arguments, carries it to every caller.
func (ta *taintAnalysis) returnTainted(fn *ssa.Function, o taintOrigin) {
	if fn == nil {
		return
	}
	ta.returns[fn] = true
	if ta.ambient[fn] {
		ta.forwardReturn(fn, o)
	}
}

// forwardReturn taints the result of every static call of fn. A call the pass cannot enumerate
// (fn is a method, or used as a value) leaves the returned taint lost.
func (ta *taintAnalysis) forwardReturn(fn *ssa.Function, o taintOrigin) {
	if ta.forwarded[fn] {
		return
	}
	ta.forwarded[fn] = true
	for _, call := range ta.idx.calls[fn] {
		if val, ok := call.(ssa.Value); ok {
			ta.arrive(val, o)
		}
	}
	if dynamicallyCalled(fn, ta.idx) {
		ta.lost = true
	}
}

// dynamicallyCalled reports whether fn may be called from a site the index does not record: a
// method may be called through an interface, a function used as a value through that value.
func dynamicallyCalled(fn *ssa.Function, idx *taintIndex) bool {
	return fn.Signature.Recv() != nil || idx.taken[fn]
}

// holdsRef reports whether a value of type t refers to memory a write through it changes for
// other holders: a pointer, slice, map, channel or interface, or an aggregate holding one.
func holdsRef(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Pointer, *types.Slice, *types.Map, *types.Chan, *types.Interface:
		return true
	case *types.Struct:
		for i := range u.NumFields() {
			if holdsRef(u.Field(i).Type()) {
				return true
			}
		}
	case *types.Array:
		return holdsRef(u.Elem())
	case *types.Tuple:
		for i := range u.Len() {
			if holdsRef(u.At(i).Type()) {
				return true
			}
		}
	}
	return false
}

// forwardArgs seeds the callee's formal parameters that correspond to the tainted
// actual argument v, accounting for the receiver offset on method calls.
func forwardArgs(common *ssa.CallCommon, callee *ssa.Function, v ssa.Value, o taintOrigin, seed func(ssa.Value, taintOrigin) bool) {
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
