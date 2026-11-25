package goanalysis

import (
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// handlerResolver resolves a pathRouter registrar's handler argument to the one
// function it can hold. Beyond staticHandler's shapes (a function reference, a
// closure, a conversion or boxing of one), it follows a handler that is bound before
// it reaches the registrar, statically and nowhere else:
//
//   - a load of a first-party package var (e.GET("/x", h)) is the value its single
//     store holds, when that store is in the var's package initialization and its
//     address is used for nothing but that store and its loads;
//   - a load of a struct field (e.GET("/x", s.h)) is the value every store to that
//     field holds, when the field is a first-party named struct's, every store to it
//     anywhere in the program holds the same function, and no address of it is used
//     but to store to or load from it;
//   - a call to a first-party func (e.GET("/x", makeHandler())) is the value every
//     one of its non-nil return statements returns, when they all return the same
//     function (a closure's body, or a function reference).
//
// Each step resolves recursively, so a factory returning a package var, or a field
// holding a factory's result, resolves too. Anything else — a var stored twice or
// outside its initializer, a field holding two different handlers or a parameter, a
// factory returning a phi, a parameter or a dependency's value, an address taken and
// passed on — is unresolved and registers no ingress: a missed handler only removes
// a root, a guessed one adds a false one. Writes made through reflect or unsafe are
// not seen.
type handlerResolver struct {
	s *ssaProgram
	// indexed is set once stores, escaped and the program scan behind them are built;
	// they are built on the first load the resolver meets.
	indexed bool
	// stores maps a func-typed first-party package var (*ssa.Global) or named-struct
	// field (*types.Var, its generic origin) to every store into it.
	stores map[any][]*ssa.Store
	// escaped holds the vars and fields whose address is used other than to store to
	// or load from it, so a write through it may be unseen.
	escaped  map[any]bool
	memo     map[ssa.Value]*ssa.Function
	visiting map[ssa.Value]bool
}

func newHandlerResolver(s *ssaProgram) *handlerResolver {
	return &handlerResolver{s: s, memo: map[ssa.Value]*ssa.Function{}, visiting: map[ssa.Value]bool{}}
}

// handler returns the function the handler value v statically holds, nil when it is
// not one function.
func (hr *handlerResolver) handler(v ssa.Value) *ssa.Function {
	if fn, ok := hr.memo[v]; ok {
		return fn
	}
	if hr.visiting[v] {
		return nil
	}
	hr.visiting[v] = true
	fn := hr.resolve(v)
	delete(hr.visiting, v)
	hr.memo[v] = fn
	return fn
}

func (hr *handlerResolver) resolve(v ssa.Value) *ssa.Function {
	switch h := v.(type) {
	case *ssa.Function, *ssa.MakeClosure:
		return staticHandler(h)
	case *ssa.ChangeType:
		return hr.handler(h.X)
	case *ssa.MakeInterface:
		return hr.handler(h.X)
	case *ssa.UnOp:
		if h.Op != token.MUL {
			return nil
		}
		switch addr := h.X.(type) {
		case *ssa.Global:
			return hr.global(addr)
		case *ssa.FieldAddr:
			return hr.field(fieldKey(addr.X.Type(), addr.Field))
		}
	case *ssa.Field:
		return hr.field(fieldKey(h.X.Type(), h.Field))
	case *ssa.Call:
		return hr.returned(h, 0)
	case *ssa.Extract:
		if call, ok := h.Tuple.(*ssa.Call); ok {
			return hr.returned(call, h.Index)
		}
	}
	return nil
}

// global resolves a load of the package var g through its single store, in g's own
// package initializer (its var declarations) or one of its init funcs (init#N).
func (hr *handlerResolver) global(g *ssa.Global) *ssa.Function {
	hr.index()
	sts := hr.stores[g]
	if hr.escaped[g] || len(sts) != 1 {
		return nil
	}
	if init := sts[0].Parent(); init == nil || init.Pkg != g.Pkg ||
		(init.Synthetic != "package initializer" && !strings.HasPrefix(init.Name(), "init#")) {
		return nil
	}
	return hr.handler(sts[0].Val)
}

// field resolves a load of the struct field f through every store to it, when they
// all hold the same function.
func (hr *handlerResolver) field(f *types.Var) *ssa.Function {
	if f == nil {
		return nil
	}
	hr.index()
	if hr.escaped[f] {
		return nil
	}
	var vals []ssa.Value
	for _, st := range hr.stores[f] {
		vals = append(vals, st.Val)
	}
	return hr.same(vals)
}

// returned resolves result i of a call to a first-party func through every return
// statement of its body, when they all return the same function. A nil returned on
// some path (a factory refusing to build its handler) registers nothing and is
// skipped.
func (hr *handlerResolver) returned(call *ssa.Call, i int) *ssa.Function {
	callee := call.Common().StaticCallee()
	if callee == nil || callee.Blocks == nil || !hr.firstParty(funcTypePackage(callee)) ||
		i >= callee.Signature.Results().Len() {
		return nil
	}
	var vals []ssa.Value
	for _, b := range callee.Blocks {
		if len(b.Instrs) == 0 {
			continue
		}
		ret, ok := b.Instrs[len(b.Instrs)-1].(*ssa.Return)
		if !ok || i >= len(ret.Results) {
			continue
		}
		if c, ok := ret.Results[i].(*ssa.Const); ok && c.IsNil() {
			continue
		}
		vals = append(vals, ret.Results[i])
	}
	return hr.same(vals)
}

// same returns the one function every value in vals holds, nil when vals is empty,
// any value resolves to none, or two resolve to different functions.
func (hr *handlerResolver) same(vals []ssa.Value) *ssa.Function {
	var fn *ssa.Function
	for _, v := range vals {
		got := hr.handler(v)
		if got == nil || (fn != nil && got != fn) {
			return nil
		}
		fn = got
	}
	return fn
}

func (hr *handlerResolver) firstParty(pkg *types.Package) bool {
	return pkg != nil && hr.s.typePkg[pkg] != nil
}

// index scans every instruction of the program once, recording each store into a
// func-typed first-party package var or named-struct field, and every such var or
// field whose address is used for anything else.
func (hr *handlerResolver) index() {
	if hr.indexed {
		return
	}
	hr.indexed = true
	hr.stores, hr.escaped = map[any][]*ssa.Store{}, map[any]bool{}
	var rands []*ssa.Value
	for fn := range ssautil.AllFunctions(hr.s.prog) {
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				if fa, ok := instr.(*ssa.FieldAddr); ok {
					hr.indexFieldAddr(fa)
				}
				if _, ok := instr.(*ssa.DebugRef); ok {
					continue
				}
				for _, op := range instr.Operands(rands[:0]) {
					g, ok := (*op).(*ssa.Global)
					if !ok || !hr.firstParty(g.Pkg.Pkg) || !isFuncTyped(deref(g.Type())) {
						continue
					}
					switch x := instr.(type) {
					case *ssa.Store:
						if x.Addr == g && x.Val != g {
							hr.stores[g] = append(hr.stores[g], x)
							continue
						}
					case *ssa.UnOp:
						if x.Op == token.MUL {
							continue
						}
					}
					hr.escaped[g] = true
				}
			}
		}
	}
}

// indexFieldAddr records what is done through the address of a func-typed
// first-party named-struct field: a store into it, a load, or anything else.
func (hr *handlerResolver) indexFieldAddr(fa *ssa.FieldAddr) {
	f := fieldKey(fa.X.Type(), fa.Field)
	if f == nil || !hr.firstParty(f.Pkg()) || !isFuncTyped(f.Type()) {
		return
	}
	for _, ref := range *fa.Referrers() {
		switch x := ref.(type) {
		case *ssa.Store:
			if x.Addr == fa && x.Val != fa {
				hr.stores[f] = append(hr.stores[f], x)
				continue
			}
		case *ssa.UnOp:
			if x.Op == token.MUL {
				continue
			}
		case *ssa.DebugRef:
			continue
		}
		hr.escaped[f] = true
	}
}

// fieldKey returns the generic origin of field i of the named struct t (or *t)
// declares, nil when t is no named struct: an unnamed struct's fields are not one
// object across the identical struct types a value may flow between.
func fieldKey(t types.Type, i int) *types.Var {
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return nil
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || i < 0 || i >= st.NumFields() {
		return nil
	}
	return st.Field(i).Origin()
}

func isFuncTyped(t types.Type) bool {
	_, ok := t.Underlying().(*types.Signature)
	return ok
}

func deref(t types.Type) types.Type {
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		return p.Elem()
	}
	return t
}
