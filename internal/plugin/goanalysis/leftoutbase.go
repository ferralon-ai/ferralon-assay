package goanalysis

import (
	"go/types"
	"maps"
	"slices"
	"strconv"

	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/go/types/typeutil"
)

// reachedBase is what the scanned build's whole program reaches: the declarations govulncheck's
// entry points, the exported methods it leaves out, and the roots of reflection's calls reach over a
// VTA call graph (Base), with what the left-out-file gate (leftOutReachesSymbols) needs to follow
// code the build left out back into them. A declaration is keyed "pkgpath\x00recv\x00name" (declKey),
// recv being the receiver's type name and empty for a function or variable.
type reachedBase struct {
	// Decls are the reached declarations; a function literal counts as the declaration enclosing it.
	Decls []string `json:"decls"`
	// Valued are the functions reached code uses as values and does not call.
	Valued []baseFunc `json:"valued"`
	// Invokes are the interface methods reached code calls, by name ("\x00\x00M") and arity.
	Invokes []baseFunc `json:"invokes"`
	// Types are the named types reached code mentions, closed over the types they are built from,
	// keyed "pkgpath\x00name".
	Types []string `json:"types"`
	// Methods are the methods of Types, promoted ones included, each keyed by the declaration.
	Methods []baseFunc `json:"methods"`
	// Escape are the unreached methods of Types whose name and signature match an interface method
	// reached code invokes, and the Valued functions whose signature matches a call of a function
	// value in reached code: a dispatch site the build traced can call one once code it left out
	// hands the value back. Owner is the package of the type, or of the function.
	Escape []baseFunc `json:"escape"`
}

// baseFunc is one function of a reachedBase with its arity. Pos locates a function literal
// ("file:line:column"), which has no declaration of its own.
type baseFunc struct {
	Key      string `json:"key,omitempty"`
	Pos      string `json:"pos,omitempty"`
	Owner    string `json:"owner,omitempty"`
	Params   int    `json:"params"`
	Results  int    `json:"results"`
	Variadic bool   `json:"variadic,omitempty"`
}

// declKey keys a declaration by package path, receiver type name and name.
func declKey(pkg, recv, name string) string {
	return pkg + "\x00" + recv + "\x00" + name
}

// funcDeclKey keys the declaration of fn, a function or method, by its generic origin.
func funcDeclKey(fn *types.Func) string {
	fn = fn.Origin()
	recv := ""
	if r := fn.Signature().Recv(); r != nil {
		recv = recvTypeName(r.Type())
	}
	return declKey(fn.Pkg().Path(), recv, fn.Name())
}

// recvTypeName names a receiver's type with any pointer, alias and type arguments dropped.
func recvTypeName(t types.Type) string {
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	if n, ok := t.(*types.Named); ok {
		return n.Obj().Name()
	}
	return ""
}

func arityOf(sig *types.Signature) (params, results int, variadic bool) {
	return sig.Params().Len(), sig.Results().Len(), sig.Variadic()
}

// reachedBase computes the program's reachedBase from govulncheck's entry points, the exported
// methods it leaves out (unsearchedMethods), and extra, following call edges only: a function
// literal reached code creates and never calls is a function value (Valued), not reached.
func (s *ssaProgram) reachedBase(extra []*ssa.Function) *reachedBase {
	graph := vta.CallGraph(ssautil.AllFunctions(s.prog), cha.CallGraph(s.prog))
	queue := append(s.govulncheckEntries(), extra...)
	for _, m := range unsearchedMethods(slices.Collect(maps.Values(s.typePkg))) {
		queue = append(queue, s.prog.FuncValue(m))
	}
	reached := map[*ssa.Function]bool{}
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		if fn == nil || reached[fn] {
			continue
		}
		reached[fn] = true
		if n := graph.Nodes[fn]; n != nil {
			for _, e := range n.Out {
				queue = append(queue, e.Callee.Func)
			}
		}
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				if call, ok := instr.(ssa.CallInstruction); ok {
					queue = append(queue, call.Common().StaticCallee())
				}
			}
		}
	}

	b := &baseBuilder{s: s, decls: map[string]bool{}, types: map[string]bool{}}
	for fn := range reached {
		if key := ssaDeclKey(fn); key != "" {
			b.decls[key] = true
		}
		b.scan(fn)
	}
	// A wrapper reached code takes as a value (a bound method, a method expression) is called only
	// where that value goes, so the calls it makes count as reached code's too.
	wrapped := map[*ssa.Function]bool{}
	for i := 0; i < len(b.valued); i++ {
		if fn := b.valued[i]; fn.Synthetic != "" && !reached[fn] && !wrapped[fn] {
			wrapped[fn] = true
			b.scan(fn)
		}
	}
	return b.result(reached)
}

// ssaDeclKey keys the declaration fn comes from: the enclosing declaration of a function literal,
// the method a bound-method or method-expression wrapper stands for. A function with no declaration
// (a package initializer) has none.
func ssaDeclKey(fn *ssa.Function) string {
	for fn.Parent() != nil {
		fn = fn.Parent()
	}
	obj, ok := fn.Object().(*types.Func)
	if !ok || obj.Pkg() == nil {
		return ""
	}
	return funcDeclKey(obj)
}

type baseBuilder struct {
	s     *ssaProgram
	decls map[string]bool
	types map[string]bool
	// concrete holds each mentioned type as the program uses it, for its method set.
	concrete typeutil.Map
	invokes  []*types.Func
	dynamic  []*types.Signature
	valued   []*ssa.Function
}

// scan records what reached fn mentions: the types of its parameters, results and every value it
// computes or uses, the interface methods it invokes, the signatures it calls function values
// with, and the functions it uses as values.
func (b *baseBuilder) scan(fn *ssa.Function) {
	b.addType(fn.Signature)
	var ops []*ssa.Value
	for _, blk := range fn.Blocks {
		for _, instr := range blk.Instrs {
			if v, ok := instr.(ssa.Value); ok {
				b.addType(v.Type())
			}
			if ta, ok := instr.(*ssa.TypeAssert); ok {
				b.addType(ta.AssertedType)
			}
			var callee *ssa.Value
			if call, ok := instr.(ssa.CallInstruction); ok {
				c := call.Common()
				switch {
				case c.IsInvoke():
					b.invokes = append(b.invokes, c.Method)
				case c.StaticCallee() != nil:
					callee = &c.Value
				default:
					if sig, ok := c.Value.Type().Underlying().(*types.Signature); ok {
						b.dynamic = append(b.dynamic, sig)
					}
				}
			}
			for _, op := range instr.Operands(ops[:0]) {
				if *op == nil {
					continue
				}
				b.addType((*op).Type())
				if v, ok := (*op).(*ssa.Function); ok && op != callee {
					b.valued = append(b.valued, v)
				}
			}
		}
	}
}

// addType records t and the types it is built from: a struct's fields, an element, a signature's
// parameters and results, an interface's method signatures, a tuple's members.
func (b *baseBuilder) addType(t types.Type) {
	if t == nil {
		return
	}
	t = types.Unalias(t)
	switch t := t.(type) {
	case *types.Tuple:
		for i := range t.Len() {
			b.addType(t.At(i).Type())
		}
		return
	case *types.Named, *types.Pointer, *types.Struct, *types.Slice, *types.Array, *types.Chan, *types.Map, *types.Signature, *types.Interface:
	default:
		// Basic types, type parameters and the SSA builder's own internal types have no methods
		// and are built from nothing.
		return
	}
	if b.concrete.At(t) != nil {
		return
	}
	b.concrete.Set(t, true)
	switch t := t.(type) {
	case *types.Named:
		if obj := t.Obj(); obj.Pkg() != nil {
			b.types[obj.Pkg().Path()+"\x00"+obj.Name()] = true
		}
		for i := range t.TypeArgs().Len() {
			b.addType(t.TypeArgs().At(i))
		}
		b.addType(t.Underlying())
	case *types.Pointer:
		b.addType(t.Elem())
	case *types.Struct:
		for i := range t.NumFields() {
			b.addType(t.Field(i).Type())
		}
	case *types.Slice:
		b.addType(t.Elem())
	case *types.Array:
		b.addType(t.Elem())
	case *types.Chan:
		b.addType(t.Elem())
	case *types.Map:
		b.addType(t.Key())
		b.addType(t.Elem())
	case *types.Signature:
		for _, tuple := range []*types.Tuple{t.Params(), t.Results()} {
			for i := range tuple.Len() {
				b.addType(tuple.At(i).Type())
			}
		}
	case *types.Interface:
		for i := range t.NumMethods() {
			b.addType(t.Method(i).Type())
		}
	}
}

func (b *baseBuilder) result(reached map[*ssa.Function]bool) *reachedBase {
	out := &reachedBase{Decls: sortedKeys(b.decls), Types: sortedKeys(b.types)}

	invokes := map[string]bool{}
	for _, m := range b.invokes {
		p, r, v := arityOf(m.Signature())
		key := declKey("", "", m.Name()) + "\x00" + strconv.Itoa(p) + "\x00" + strconv.Itoa(r) + "\x00" + strconv.FormatBool(v)
		if !invokes[key] {
			invokes[key] = true
			out.Invokes = append(out.Invokes, baseFunc{Key: declKey("", "", m.Name()), Params: p, Results: r, Variadic: v})
		}
	}
	invoked := func(name string, sig *types.Signature) bool {
		return slices.ContainsFunc(b.invokes, func(m *types.Func) bool {
			return m.Name() == name && types.Identical(bare(m.Signature()), bare(sig))
		})
	}
	called := func(sig *types.Signature) bool {
		return slices.ContainsFunc(b.dynamic, func(d *types.Signature) bool { return types.Identical(bare(d), bare(sig)) })
	}

	methods := map[string]bool{}
	escaped := map[string]bool{}
	b.concrete.Iterate(func(t types.Type, _ any) {
		n, ok := t.(*types.Named)
		if !ok || types.IsInterface(n) || n.Obj().Pkg() == nil {
			return
		}
		owner := n.Obj().Pkg().Path()
		for _, mt := range []types.Type{n, types.NewPointer(n)} {
			mset := b.s.prog.MethodSets.MethodSet(mt)
			for i := range mset.Len() {
				sel := mset.At(i)
				obj, ok := sel.Obj().(*types.Func)
				if !ok || obj.Pkg() == nil || types.IsInterface(obj.Signature().Recv().Type()) {
					// A method promoted from an embedded interface has no declaration; calls
					// through it are interface calls, which Invokes covers.
					continue
				}
				key := funcDeclKey(obj)
				p, r, v := arityOf(obj.Signature())
				if !methods[key] {
					methods[key] = true
					out.Methods = append(out.Methods, baseFunc{Key: key, Params: p, Results: r, Variadic: v})
				}
				sig, _ := sel.Type().(*types.Signature)
				if sig != nil && !b.decls[key] && !escaped[key+"\x00"+owner] && invoked(obj.Name(), sig) {
					escaped[key+"\x00"+owner] = true
					out.Escape = append(out.Escape, baseFunc{Key: key, Owner: owner, Params: p, Results: r, Variadic: v})
				}
			}
		}
	})

	valued := map[*ssa.Function]bool{}
	for _, fn := range b.valued {
		if reached[fn] || valued[fn] {
			continue
		}
		valued[fn] = true
		f := b.funcOf(fn)
		if f.Key == "" && f.Pos == "" {
			continue
		}
		out.Valued = append(out.Valued, f)
		if called(fn.Signature) {
			out.Escape = append(out.Escape, f)
		}
	}
	return out
}

// funcOf describes fn, a function used as a value: a declared function or method (a wrapper
// counting as the method it wraps) by its declaration, a function literal by its position.
func (b *baseBuilder) funcOf(fn *ssa.Function) baseFunc {
	p, r, v := arityOf(fn.Signature)
	f := baseFunc{Params: p, Results: r, Variadic: v}
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		f.Owner = fn.Pkg.Pkg.Path()
	}
	if fn.Parent() != nil {
		pos := b.s.prog.Fset.Position(fn.Pos())
		if pos.IsValid() {
			f.Pos = pos.Filename + ":" + strconv.Itoa(pos.Line) + ":" + strconv.Itoa(pos.Column)
		}
		return f
	}
	if obj, ok := fn.Object().(*types.Func); ok && obj.Pkg() != nil {
		f.Key = funcDeclKey(obj)
		if f.Owner == "" {
			f.Owner = obj.Pkg().Path()
		}
	}
	return f
}
