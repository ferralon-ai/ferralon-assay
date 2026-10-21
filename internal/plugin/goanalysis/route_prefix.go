package goanalysis

import (
	"go/types"
	"sort"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// prefixResolver resolves the path prefixes a pathRouter router value is registered
// under, so a route's selector is its full composed pattern (/v1/users/:id), not only
// the pattern of its own registrar call. It follows the router value back through
// SSA, statically and nowhere else:
//
//   - a root router (a pathRouter's roots: chi.NewRouter, gin.New, echo.New) carries
//     the empty prefix;
//   - a group method's result (gin's and echo's Group, chi's Route) carries its
//     receiver's prefixes joined with its constant pattern, a pass-through's (chi's
//     With and Group, gin's Use) its receiver's own, and the router a promoted gin
//     method is called on (&engine.RouterGroup) its engine's;
//   - a first-party func's result carries what every return statement returns, and a
//     parameter what every caller passes it;
//   - the router parameter of a closure handed to a scope method (chi's Route and
//     Group) carries what that call's receiver does, joined with Route's pattern.
//
// Anything else — a non-constant group pattern, a router loaded from a variable,
// field or global, a phi, a func that is used as a value as well as called, a
// parameter no caller is seen passing — is unresolved: the caller keeps the local
// pattern and never guesses a prefix. A func called from several sites with
// different prefixes registers its routes under each of them.
type prefixResolver struct {
	s *ssaProgram
	// uses indexes, for every function, the instructions that name it as an operand
	// (a call site, a closure creation, a value use); built on the first need.
	uses map[*ssa.Function][]ssa.Instruction
	memo map[ssa.Value]prefixSet
	// visiting guards a recursion back into a value being resolved (a recursive
	// func), which resolves to unresolved.
	visiting map[ssa.Value]bool
}

type prefixSet struct {
	prefixes []string
	ok       bool
}

var unresolvedPrefix = prefixSet{}

func newPrefixResolver(s *ssaProgram) *prefixResolver {
	return &prefixResolver{s: s, memo: map[ssa.Value]prefixSet{}, visiting: map[ssa.Value]bool{}}
}

// prefixes returns the sorted, distinct prefixes the router value v carries, and
// false when any of them cannot be resolved statically.
func (pr *prefixResolver) prefixes(v ssa.Value) ([]string, bool) {
	ps := pr.resolve(v)
	return ps.prefixes, ps.ok
}

func (pr *prefixResolver) resolve(v ssa.Value) prefixSet {
	if v == nil {
		return unresolvedPrefix
	}
	if ps, ok := pr.memo[v]; ok {
		return ps
	}
	if pr.visiting[v] {
		return unresolvedPrefix
	}
	pr.visiting[v] = true
	ps := pr.resolveValue(v)
	delete(pr.visiting, v)
	pr.memo[v] = ps
	return ps
}

func (pr *prefixResolver) resolveValue(v ssa.Value) prefixSet {
	switch x := v.(type) {
	case *ssa.MakeInterface:
		return pr.resolve(x.X)
	case *ssa.ChangeInterface:
		return pr.resolve(x.X)
	case *ssa.ChangeType:
		return pr.resolve(x.X)
	case *ssa.FieldAddr:
		// A method promoted from an embedded router (gin's Engine embeds RouterGroup) is
		// called on the address of the embedded field: it is the engine's own router.
		if inRouterPkg(namedTypePkg(x.X.Type())) && embeddedField(x) {
			return pr.resolve(x.X)
		}
	case *ssa.Call:
		return pr.resolveCall(x)
	case *ssa.Parameter:
		return pr.resolveParam(x)
	}
	return unresolvedPrefix
}

// resolveCall resolves the router a call returns: a router package's root
// constructor, group method or pass-through, or a first-party func's results.
func (pr *prefixResolver) resolveCall(call *ssa.Call) prefixSet {
	if r, name, recv, args := routerCall(call.Common()); r != nil {
		switch {
		case recv == nil && r.roots[name]:
			return prefixSet{prefixes: []string{""}, ok: true}
		case recv != nil && r.groups[name]:
			if len(args) == 0 {
				return unresolvedPrefix
			}
			pattern, ok := constString(args[0])
			if !ok {
				return unresolvedPrefix
			}
			return joinPrefixes(r, pr.resolve(recv), pattern)
		case recv != nil && r.passes[name]:
			return pr.resolve(recv)
		}
		return unresolvedPrefix
	}
	callee := call.Common().StaticCallee()
	if callee == nil || callee.Blocks == nil || callee.Signature.Results().Len() != 1 {
		return unresolvedPrefix
	}
	var sets []prefixSet
	for _, b := range callee.Blocks {
		if len(b.Instrs) == 0 {
			continue
		}
		if ret, ok := b.Instrs[len(b.Instrs)-1].(*ssa.Return); ok && len(ret.Results) == 1 {
			sets = append(sets, pr.resolve(ret.Results[0]))
		}
	}
	return unionPrefixes(sets)
}

// resolveParam resolves a router parameter from every use of its function: each call
// site's argument in its position, and, for a closure, the scope call it is handed
// to. A func with no use seen, or one used as a value anywhere else, is unresolved.
func (pr *prefixResolver) resolveParam(p *ssa.Parameter) prefixSet {
	fn := p.Parent()
	idx := -1
	for i, q := range fn.Params {
		if q == p {
			idx = i
		}
	}
	if idx < 0 {
		return unresolvedPrefix
	}
	var sets []prefixSet
	for _, instr := range pr.usesOf(fn) {
		var val ssa.Value = fn
		if mc, ok := instr.(*ssa.MakeClosure); ok && mc.Fn == fn {
			// A closure: every use of the closure value it builds decides.
			refs := mc.Referrers()
			if refs == nil || len(*refs) == 0 {
				return unresolvedPrefix
			}
			for _, ref := range *refs {
				sets = append(sets, pr.resolveUse(ref, mc, idx))
			}
			continue
		}
		sets = append(sets, pr.resolveUse(instr, val, idx))
	}
	return unionPrefixes(sets)
}

// resolveUse resolves parameter idx of the function value val from one instruction
// using val: a call of val passes its argument in that position, and a scope call
// (chi's Route/Group) handed val as its closure passes the router it scopes.
func (pr *prefixResolver) resolveUse(instr ssa.Instruction, val ssa.Value, idx int) prefixSet {
	call, ok := instr.(ssa.CallInstruction)
	if !ok {
		return unresolvedPrefix
	}
	common := call.Common()
	if !common.IsInvoke() && common.Value == val {
		if idx < len(common.Args) {
			return pr.resolve(common.Args[idx])
		}
		return unresolvedPrefix
	}
	r, name, recv, args := routerCall(common)
	if r == nil || recv == nil || !r.scopes[name] || idx != 0 || len(args) == 0 || args[len(args)-1] != val {
		return unresolvedPrefix
	}
	recvSet := pr.resolve(recv)
	if !r.groups[name] {
		return recvSet
	}
	pattern, ok := constString(args[0])
	if !ok || len(args) < 2 {
		return unresolvedPrefix
	}
	return joinPrefixes(r, recvSet, pattern)
}

// usesOf returns the instructions naming fn as an operand, indexing every function's
// instructions once on the first call.
func (pr *prefixResolver) usesOf(fn *ssa.Function) []ssa.Instruction {
	if pr.uses == nil {
		pr.uses = map[*ssa.Function][]ssa.Instruction{}
		var ops []*ssa.Value
		for f := range ssautil.AllFunctions(pr.s.prog) {
			for _, b := range f.Blocks {
				for _, instr := range b.Instrs {
					ops = instr.Operands(ops[:0])
					for _, op := range ops {
						if op == nil {
							continue
						}
						if used, ok := (*op).(*ssa.Function); ok {
							pr.uses[used] = append(pr.uses[used], instr)
						}
					}
				}
			}
		}
	}
	return pr.uses[fn]
}

// joinPrefixes joins pattern onto every prefix of a resolved set.
func joinPrefixes(r *pathRouter, set prefixSet, pattern string) prefixSet {
	if !set.ok {
		return unresolvedPrefix
	}
	out := make([]string, 0, len(set.prefixes))
	for _, p := range set.prefixes {
		out = append(out, r.join(p, pattern))
	}
	return prefixSet{prefixes: out, ok: true}
}

// unionPrefixes merges the sets every use or return resolves to; none, or any one
// unresolved, is unresolved.
func unionPrefixes(sets []prefixSet) prefixSet {
	if len(sets) == 0 {
		return unresolvedPrefix
	}
	seen := map[string]bool{}
	var out []string
	for _, set := range sets {
		if !set.ok {
			return unresolvedPrefix
		}
		for _, p := range set.prefixes {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return prefixSet{prefixes: out, ok: true}
}

// inRouterPkg reports whether pkg is one of the pathRouters' packages.
func inRouterPkg(pkg *types.Package) bool {
	if pkg == nil {
		return false
	}
	for _, r := range pathRouters {
		if r.paths[pkg.Path()] {
			return true
		}
	}
	return false
}

// embeddedField reports whether the field x addresses is an embedded one.
func embeddedField(x *ssa.FieldAddr) bool {
	ptr, ok := x.X.Type().Underlying().(*types.Pointer)
	if !ok {
		return false
	}
	st, ok := ptr.Elem().Underlying().(*types.Struct)
	return ok && x.Field < st.NumFields() && st.Field(x.Field).Embedded()
}
