package goanalysis

import (
	"go/types"
	"maps"
	"slices"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/go/types/typeutil"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Run-time callees that let reflection call a method chosen by index or name, or a function value.
// A template's Execute does both: its text names methods and FuncMap functions.
var (
	reflectMethodCallees = map[string]bool{
		"(reflect.Value).Method":                    true,
		"(reflect.Value).MethodByName":              true,
		"(*reflect.rtype).Method":                   true,
		"(*reflect.rtype).MethodByName":             true,
		"(reflect.Type).Method":                     true,
		"(reflect.Type).MethodByName":               true,
		"(*text/template.Template).Execute":         true,
		"(*text/template.Template).ExecuteTemplate": true,
		"(*html/template.Template).Execute":         true,
		"(*html/template.Template).ExecuteTemplate": true,
	}
	reflectCallCallees = map[string]bool{
		"(reflect.Value).Call":                      true,
		"(reflect.Value).CallSlice":                 true,
		"(*text/template.Template).Execute":         true,
		"(*text/template.Template).ExecuteTemplate": true,
		"(*html/template.Template).Execute":         true,
		"(*html/template.Template).ExecuteTemplate": true,
	}
)

// reflectReachOf builds res's whole program, dependencies included, and returns its reflectReach. The
// call graph reconciliation reads holds code for the loaded module's own packages only, and the calls
// reflection makes are mostly in the standard library (encoding/json, text/template).
func reflectReachOf(res *LoadResult) (reasons []string, reach map[string][]string, err error) {
	sp, err := buildSSAWith(res, ssautil.AllPackages)
	if err != nil {
		return nil, nil, err
	}
	reasons, reach = sp.reflectReach()
	// AllPackages builds no bodies for a package that does not type-check, so what the fixpoint did not
	// see there is unknown: the reach is too.
	packages.Visit(res.Packages, nil, func(p *packages.Package) {
		if p.IllTyped {
			reach = nil
		}
	})
	return reasons, reach, nil
}

// reflectReach finds the functions the program can run through calls the call graph cannot follow
// because reflection made them, bounded by the rules the linker's dead-code pass keeps reflection's
// targets by (cmd/link/internal/ld/deadcode.go), narrowed to function values a call can reach.
// Starting from govulncheck's entry points and the methods those leave out, following static calls,
// the live functions give up:
//
//   - the types reflection can hand out: the dynamic types of their interface conversions, closed
//     over the types those are built from;
//   - the methods of those types whose name and signature match an interface method a live
//     function invokes, which a value reflection materialized (encoding/json's MarshalJSON on a
//     value it read with reflect) can be asserted to and called through;
//   - every exported method of those types, once reflect's Method or MethodByName, or a template's
//     Execute, is live;
//   - every function a live function uses as a value, once reflect's Call or CallSlice, or a
//     template's Execute, is live, and otherwise those whose signature matches a live dynamic call,
//     which a function value reflection materialized can reach, and those of the signature
//     reflect's MakeFunc wraps, which reflect calls itself.
//
// Each of those becomes live in turn, until nothing changes. It returns the reasons runTimeCallees
// declares for the live functions, and what the roots of those calls reach outside govulncheck's own
// entry points, by package path and vulnerability-database symbol name ("F", "T.M").
func (s *ssaProgram) reflectReach() (reasons []string, reach map[string][]string) {
	f := &reflectFixpoint{
		s:       s,
		live:    map[*ssa.Function]bool{},
		roots:   map[*ssa.Function]bool{},
		reasons: map[string]bool{},
	}
	entries := map[*ssa.Function]bool{}
	for _, fn := range s.govulncheckEntries() {
		entries[fn] = true
		f.visit(fn)
	}
	for _, m := range unsearchedMethods(slices.Collect(maps.Values(s.typePkg))) {
		f.visit(s.prog.FuncValue(m))
	}
	f.drain()

	var start []*ssa.Function
	for fn := range f.roots {
		if !entries[fn] {
			start = append(start, fn)
		}
	}
	return sortedKeys(f.reasons), s.reachedSymbols(start)
}

type reflectFixpoint struct {
	s     *ssaProgram
	queue []*ssa.Function
	live  map[*ssa.Function]bool
	// roots are the functions reflection may call: the calls into them are the ones the graph misses.
	roots   map[*ssa.Function]bool
	reasons map[string]bool

	types typeutil.Map // types reflection can hand out → true

	methodGate, callGate bool
	// invoked maps a method signature (receiver dropped) to the method Ids live code invokes with it;
	// methods maps it to the methods of the types reflection can hand out, by Id.
	invoked typeutil.Map // *types.Signature → map[string]bool
	methods typeutil.Map // *types.Signature → map[string][]*ssa.Function
	// exported holds every exported method of those types, for when the method gate opens.
	exported []*ssa.Function
	// valued holds the functions live code uses as values; dynamic holds the signatures live code
	// calls a function value with, mapped to whether it does.
	valued     []*ssa.Function
	valuedSigs typeutil.Map // *types.Signature → []*ssa.Function
	dynamic    typeutil.Map // *types.Signature → true
}

func (f *reflectFixpoint) visit(fn *ssa.Function) {
	if fn != nil && !f.live[fn] {
		f.live[fn] = true
		f.queue = append(f.queue, fn)
	}
}

func (f *reflectFixpoint) root(fn *ssa.Function) {
	if fn == nil || f.roots[fn] {
		return
	}
	f.roots[fn] = true
	f.visit(fn)
}

func (f *reflectFixpoint) drain() {
	for len(f.queue) > 0 {
		fn := f.queue[0]
		f.queue = f.queue[1:]
		f.scan(fn)
		for _, callee := range staticCallees(fn) {
			f.visit(callee)
		}
	}
}

// scan records what a live function tells the fixpoint: the run-time call it is, the types it
// converts to interfaces, the interface methods it invokes, the functions it uses as values, and the
// signatures it calls a function value with.
func (f *reflectFixpoint) scan(fn *ssa.Function) {
	if obj, ok := fn.Object().(*types.Func); ok {
		name := obj.FullName()
		if r, ok := runTimeCallees[name]; ok {
			f.reasons[r] = true
		}
		if reflectMethodCallees[name] {
			f.openMethodGate()
		}
		if reflectCallCallees[name] {
			f.openCallGate()
		}
		if name == "reflect.MakeFunc" {
			// reflect itself calls the function MakeFunc wraps, from no call site in Go code: it is
			// reached as a dynamic call of fn's signature would reach it.
			f.addDynamic(obj.Signature().Params().At(1).Type().Underlying().(*types.Signature))
		}
	}
	var ops []*ssa.Value
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			if mi, ok := instr.(*ssa.MakeInterface); ok {
				f.addType(mi.X.Type())
			}
			var callee *ssa.Value
			if call, ok := instr.(ssa.CallInstruction); ok {
				c := call.Common()
				switch {
				case c.IsInvoke():
					if reflectMethodCallees[c.Method.FullName()] {
						f.openMethodGate()
					}
					f.addInvoke(c.Method)
				case c.StaticCallee() != nil:
					callee = &c.Value
				default:
					if sig, ok := c.Value.Type().Underlying().(*types.Signature); ok {
						f.addDynamic(sig)
					}
				}
			}
			for _, op := range instr.Operands(ops[:0]) {
				if v, ok := (*op).(*ssa.Function); ok && op != callee {
					f.addValued(v)
				}
			}
		}
	}
}

func (f *reflectFixpoint) openMethodGate() {
	if !f.methodGate {
		f.methodGate = true
		for _, m := range f.exported {
			f.root(m)
			f.addSignatureTypes(m.Signature)
		}
	}
}

func (f *reflectFixpoint) openCallGate() {
	if !f.callGate {
		f.callGate = true
		for _, fn := range f.valued {
			f.root(fn)
		}
	}
}

// addType adds t, and the types it is built from, to the types reflection can hand out, and records
// their methods. A type that mentions a type parameter has no methods to call until instantiated.
func (f *reflectFixpoint) addType(t types.Type) {
	t = types.Unalias(t)
	if f.types.At(t) != nil {
		return
	}
	f.types.Set(t, true)
	switch t := t.(type) {
	case *types.Named:
		f.addMethods(t)
		f.addMethods(types.NewPointer(t))
		f.addType(t.Underlying())
	case *types.Pointer:
		f.addMethods(t)
		f.addType(t.Elem())
	case *types.Struct:
		f.addMethods(t)
		f.addMethods(types.NewPointer(t))
		for i := range t.NumFields() {
			f.addType(t.Field(i).Type())
		}
	case *types.Slice:
		f.addType(t.Elem())
	case *types.Array:
		f.addType(t.Elem())
	case *types.Chan:
		f.addType(t.Elem())
	case *types.Map:
		f.addType(t.Key())
		f.addType(t.Elem())
	case *types.Signature:
		f.addSignatureTypes(t)
	}
}

func (f *reflectFixpoint) addSignatureTypes(sig *types.Signature) {
	for _, tuple := range []*types.Tuple{sig.Params(), sig.Results()} {
		for i := range tuple.Len() {
			f.addType(tuple.At(i).Type())
		}
	}
}

func (f *reflectFixpoint) addMethods(t types.Type) {
	if types.IsInterface(t) || mentionsTypeParam(t) {
		return
	}
	mset := f.s.prog.MethodSets.MethodSet(t)
	for i := range mset.Len() {
		sel := mset.At(i)
		fn := f.s.prog.MethodValue(sel)
		obj, ok := sel.Obj().(*types.Func)
		if fn == nil || !ok {
			continue
		}
		sig := bare(sel.Type().(*types.Signature))
		byID, _ := f.methods.At(sig).(map[string][]*ssa.Function)
		if byID == nil {
			byID = map[string][]*ssa.Function{}
			f.methods.Set(sig, byID)
		}
		byID[obj.Id()] = append(byID[obj.Id()], fn)
		if ids, _ := f.invoked.At(sig).(map[string]bool); ids[obj.Id()] {
			f.root(fn)
		}
		if obj.Exported() {
			f.exported = append(f.exported, fn)
			if f.methodGate {
				f.root(fn)
				f.addSignatureTypes(fn.Signature)
			}
		}
	}
}

func (f *reflectFixpoint) addInvoke(m *types.Func) {
	sig := bare(m.Signature())
	ids, _ := f.invoked.At(sig).(map[string]bool)
	if ids == nil {
		ids = map[string]bool{}
		f.invoked.Set(sig, ids)
	}
	if ids[m.Id()] {
		return
	}
	ids[m.Id()] = true
	if byID, _ := f.methods.At(sig).(map[string][]*ssa.Function); byID != nil {
		for _, fn := range byID[m.Id()] {
			f.root(fn)
		}
	}
}

func (f *reflectFixpoint) addValued(fn *ssa.Function) {
	sig := bare(fn.Signature)
	fns, _ := f.valuedSigs.At(sig).([]*ssa.Function)
	if slices.Contains(fns, fn) {
		return
	}
	f.valuedSigs.Set(sig, append(fns, fn))
	f.valued = append(f.valued, fn)
	if f.callGate || f.dynamic.At(sig) != nil {
		f.root(fn)
	}
}

func (f *reflectFixpoint) addDynamic(sig *types.Signature) {
	sig = bare(sig)
	if f.dynamic.At(sig) != nil {
		return
	}
	f.dynamic.Set(sig, true)
	fns, _ := f.valuedSigs.At(sig).([]*ssa.Function)
	for _, fn := range fns {
		f.root(fn)
	}
}

// bare returns sig without its receiver, so a method and the function value or interface method it
// may stand for compare equal.
func bare(sig *types.Signature) *types.Signature {
	if sig.Recv() == nil {
		return sig
	}
	return types.NewSignatureType(nil, nil, nil, sig.Params(), sig.Results(), sig.Variadic())
}

// mentionsTypeParam reports whether t is built from a type parameter.
func mentionsTypeParam(t types.Type) bool {
	switch t := types.Unalias(t).(type) {
	case *types.TypeParam:
		return true
	case *types.Pointer:
		return mentionsTypeParam(t.Elem())
	case *types.Named:
		if t.TypeParams().Len() > 0 && t.TypeArgs().Len() == 0 {
			return true
		}
		for i := range t.TypeArgs().Len() {
			if mentionsTypeParam(t.TypeArgs().At(i)) {
				return true
			}
		}
	}
	return false
}

// staticCallees returns the functions fn calls directly and the functions it declares. A call through
// an interface or a function value is the fixpoint's to follow.
func staticCallees(fn *ssa.Function) []*ssa.Function {
	var out []*ssa.Function
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			if call, ok := instr.(ssa.CallInstruction); ok {
				if c := call.Common().StaticCallee(); c != nil {
					out = append(out, c)
				}
			}
		}
	}
	return append(out, fn.AnonFuncs...)
}

// reachedSymbols returns what start reaches, as vulnerability-database symbol names by package path.
// A function literal counts as the function that declares it.
func (s *ssaProgram) reachedSymbols(start []*ssa.Function) map[string][]string {
	seen := map[*ssa.Function]bool{}
	sets := map[string]map[string]bool{}
	queue := start
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		if fn == nil || seen[fn] {
			continue
		}
		seen[fn] = true
		if pkg, name := dbSymbol(fn); pkg != "" {
			if sets[pkg] == nil {
				sets[pkg] = map[string]bool{}
			}
			sets[pkg][name] = true
		}
		queue = append(queue, staticCallees(fn)...)
	}
	reach := make(map[string][]string, len(sets))
	for pkg, names := range sets {
		reach[pkg] = sortedKeys(names)
	}
	return reach
}

// dbSymbol names fn the way govulncheck matches it against a vulnerability database entry
// (x/vuln internal/vulncheck dbFuncName): its package path, and "F" or "T.M" with any pointer and
// type arguments dropped. A bound method or method expression wrapper is named for its method.
func dbSymbol(fn *ssa.Function) (pkg, name string) {
	for fn.Parent() != nil {
		fn = fn.Parent()
	}
	obj, ok := fn.Object().(*types.Func)
	if !ok || obj.Pkg() == nil {
		return "", ""
	}
	obj = obj.Origin()
	name = obj.Name()
	if recv := obj.Signature().Recv(); recv != nil {
		t := types.Unalias(recv.Type())
		if p, ok := t.(*types.Pointer); ok {
			t = types.Unalias(p.Elem())
		}
		if n, ok := t.(*types.Named); ok {
			name = n.Obj().Name() + "." + name
		}
	}
	return obj.Pkg().Path(), name
}

// reflectReaches reports whether reach holds one of module's vulnerable symbols: for each vulnerable
// package, a symbol the advisory lists, or any function when it lists none. With no vulnerable
// package known, any function in the module counts.
func reflectReaches(reach map[string][]string, module string, vulnerable map[string][]string) bool {
	if len(vulnerable) == 0 {
		for pkg := range reach {
			if inRefutedModule(pkg, module) {
				return true
			}
		}
		return false
	}
	for pkg, symbols := range vulnerable {
		reached := reach[pkg]
		if len(reached) == 0 {
			continue
		}
		if len(symbols) == 0 || slices.ContainsFunc(symbols, func(s string) bool { return slices.Contains(reached, s) }) {
			return true
		}
	}
	return false
}

// inRefutedModule reports whether the package path lies in module, ignoring case so that two
// spellings fail wide; for the standard library, whether its first element has no dot.
func inRefutedModule(pkg, module string) bool {
	if module == "stdlib" {
		return isStdlibPath(pkg, nil)
	}
	return pathHolds(module, pkg)
}

// reflectReasonOnReconcile reports whether a run-time call's reason is declared run-wide on the
// reconcile path: reflection's calls are bounded per advisory there (withholdForReflectReach).
func reflectReasonOnReconcile(reason string) bool {
	return reason != plugin.PartialReasonReflectiveCall
}
