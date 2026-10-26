package goanalysis

import (
	"cmp"
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
	// Each ingress is seeded and drained to a fixpoint in turn, in ingressOrder, so a
	// value keeps the first ingress in that order that reaches it, and a sink is
	// credited to the first ingress in that order whose taint reaches it. The tainted
	// set is the same in any order; only the credit depends on it, which ranging over
	// the map left to its iteration order.
	for _, id := range sp.ingressOrder(ingresses) {
		fn := ingresses[id]
		o := taintOrigin{ingress: id, enclFn: fn}
		for _, p := range fn.Params {
			seed(p, o)
		}
		// Method ingresses also expose free vars / the receiver is generally not
		// attacker-controlled, so only parameters are seeded.
		// The receiver is not seeded directly, but a store of tainted data into
		// one of its fields taints it anyway (see the ssa.Store case in
		// propagate), so this choice is only partly honoured.
		for len(work) > 0 {
			v := work[len(work)-1]
			work = work[:len(work)-1]
			ta.propagate(v, seed)
		}
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

// ingressOrder returns the SCIP ids of the ingresses with a function, ordered by the
// function's package path, then its full name, then its source position, then the SCIP
// id, which the map keys make unique. Every part is the same from run to run; a
// token.Pos is not, since it depends on the order files were added to the file set,
// so the position compares as file, line and column.
func (s *ssaProgram) ingressOrder(ingresses map[string]*ssa.Function) []string {
	ids := make([]string, 0, len(ingresses))
	for id, fn := range ingresses {
		if fn != nil {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		if c := s.compareFuncs(ingresses[ids[i]], ingresses[ids[j]]); c != 0 {
			return c < 0
		}
		return ids[i] < ids[j]
	})
	return ids
}

// compareFuncs orders two SSA functions by package path, full name and source position
// (file, line, column).
func (s *ssaProgram) compareFuncs(a, b *ssa.Function) int {
	if c := cmp.Compare(funcPkgPath(a), funcPkgPath(b)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.String(), b.String()); c != 0 {
		return c
	}
	pa, pb := s.prog.Fset.Position(a.Pos()), s.prog.Fset.Position(b.Pos())
	if c := cmp.Compare(pa.Filename, pb.Filename); c != 0 {
		return c
	}
	if c := cmp.Compare(pa.Line, pb.Line); c != 0 {
		return c
	}
	return cmp.Compare(pa.Column, pb.Column)
}

func funcPkgPath(fn *ssa.Function) string {
	if p := funcTypePackage(fn); p != nil {
		return p.Path()
	}
	return ""
}

// propagate pushes taint from a tainted value v to the values its referrers
// derive from it, forwarding through assignments, phi, field/element access, map
// and string lookup, type assertion, extract, conversions, tainted-operand binops,
// and (inter-procedurally) from a call's actual arg to the callee's formal param.
// Sanitizer results are NOT tainted. A tainted arg to a resolved sink records a
// finding.
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
		case *ssa.Lookup:
			// m[k] on a tainted map (r.Header["X-A"]), or s[i] on a tainted string.
			seed(in, o)
		case *ssa.TypeAssert:
			// x.(T) yields the tainted interface's dynamic value; the comma-ok
			// form's tuple carries it to its Extract.
			seed(in, o)
		case *ssa.Extract:
			seed(in, o)
		case *ssa.Store:
			// Storing a tainted value into an address taints that address, so
			// later loads of the address observe taint.
			if in.Val == v {
				seed(in.Addr, o)
				// A store into a field also taints the struct base (&w{r: r}
				// stores through &t0.r), so a later read through another
				// FieldAddr of the same base observes taint. This is
				// field-insensitive by design: every field of the base reads
				// as tainted.
				//
				// This deliberately over-approximates, and it partly undoes the
				// choice not to seed receivers (see runTaint): in a method, s.last
				// = r.URL.Path taints s, so a call through another field of s
				// (s.db.Query(constQ)) counts as tainted and can be a sink hit. It
				// only affects which trace and entry point are picked, and the
				// grade can only rise; no verdict reads it.
				if fa, ok := in.Addr.(*ssa.FieldAddr); ok {
					seed(fa.X, o)
				}
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
		// Only the module's own packages get SSA bodies, so a stdlib or dependency
		// callee (r.Header.Get, url.Values.Get, strings.TrimSpace) has none: an
		// unmodeled transform forwards taint from a tainted argument, the receiver
		// included, to its result. A (T, error) result's tuple carries it to its
		// Extract. A dynamic call with no static callee forwards nothing.
		// This is also how a context.Context becomes tainted: r.Context() is such
		// a call on the tainted request, so its result is tainted, and every
		// callee then receiving that ctx is tainted too (exec.CommandContext(ctx,
		// "const") is a sink hit). Like the field-base seed, this only affects
		// trace and entry-point selection, never a verdict.
		if forwardsUnbuilt(common, callee, v) {
			if val, ok := in.(ssa.Value); ok {
				seed(val, o)
			}
		}
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

// forwardsUnbuilt reports whether a call to a callee with no built body taints its
// result: the callee is statically known, is not a modeled sanitizer, and takes
// the tainted value v as an argument (a static method call's receiver is Args[0]).
func forwardsUnbuilt(common *ssa.CallCommon, callee *ssa.Function, v ssa.Value) bool {
	return callee != nil && !isSanitizer(callee) && argContains(common.Args, v)
}

func argContains(args []ssa.Value, v ssa.Value) bool {
	for _, a := range args {
		if a == v {
			return true
		}
	}
	return false
}
