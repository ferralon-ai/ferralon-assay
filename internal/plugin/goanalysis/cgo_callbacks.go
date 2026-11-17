package goanalysis

import (
	"go/ast"
	"go/build"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// cgoCallbackTargets bounds the Go code a cgo boundary can call back into, for the cgo packages that
// can call back (cb: an //export, SWIG, a prebuilt object, or a cgo file the build dropped).
//
// C reaches Go through the package's exported functions, and from there anything its own Go code
// can call: the packages it imports, followed through the load. What else it can call is a Go value
// the build handed the package, which only the package's API takes. So when no code outside the cb
// packages names a member of their API that takes (or holds) a function or interface value, the
// hidden code is confined to the cb packages and their import closure, and ok is true with the
// modules (as modulePURL names them) of the import closure of roots: the cb packages and what their
// dropped files import. Otherwise ok is false and the caller keeps every module as the target.
// The standard library is always a target (the callback runs through runtime/cgo); the caller adds it.
//
// A value the build does hand over keeps the bound when the search already starts at everything C
// can call on it (handedType): its type is returned in handed, and its exported methods are entry
// roots of the call graph. top are the loaded packages (the load's roots).
//
// Every "cannot tell" is false: a package with no type information, a package that failed to
// type-check and reaches a cb package, a left-out file importing a cb package, a method that lets
// database/sql install its own value converter (driver.NamedValueChecker, driver.ColumnConverter),
// an interface that re-declares an API method, a string constant naming one (a reflective call), or
// a hand-off that is not a plain call passing a value of such a type.
//
// A cb package whose cgo files the build dropped is loaded as its pure-Go variant, so its API is
// what that variant declares. A call that type-checks against it cannot pass a function value to a
// parameter the variant types without one, whatever the dropped file's signature; a call the variant
// does not declare fails to type-check, which is a "cannot tell" above.
func cgoCallbackTargets(top, cb, roots []*packages.Package, droppedFiles map[string][]string, tags []string) (mods map[string]bool, handed []*types.Named, ok bool) {
	handed, ok = handedValues(top, cb, cbReflects(roots, droppedFiles), droppedFiles, tags)
	if !ok {
		return nil, nil, false
	}
	mods = map[string]bool{}
	packages.Visit(roots, nil, func(p *packages.Package) { mods[modulePURL(p)] = true })
	return mods, handed, true
}

// cbReflects reports whether Go code on the C side of the boundary (a package of roots' import
// closure outside the standard library, or a dropped file) imports reflect, and so can call a
// function held in a field of a value it is handed. An unreadable dropped file counts.
func cbReflects(roots []*packages.Package, droppedFiles map[string][]string) bool {
	reflects := false
	packages.Visit(roots, nil, func(p *packages.Package) {
		if _, imports := p.Imports["reflect"]; imports && modulePURL(p) != stdlibPURL {
			reflects = true
		}
	})
	for _, files := range droppedFiles {
		for _, f := range files {
			_, imps, _, err := fileImports(f)
			if err != nil || slices.Contains(imps, "reflect") {
				reflects = true
			}
		}
	}
	return reflects
}

// handedType classifies a value of static type t passed where a cb package takes an interface.
// ok with a nil type: the value has no method and holds no function (a basic type), so C can call
// nothing on it. ok with a type: C can call only its exported methods, and the search starts at
// each of them: it is a non-generic type declared at package level in a loaded non-main package, so
// its own methods are govulncheck entries and the ones it promotes are unsearchedMethods. Anything
// else is not ok: a function value (its origin is unknown), a type of a main package or a
// dependency (nothing searches from its methods), a type declared in a function, a generic type,
// an interface or a type promoting the methods of an embedded one (the dynamic type is unknown),
// an unnamed composite, or, when the C side reflects, a type holding a function or interface in a
// field.
func handedType(t types.Type, top map[*types.Package]bool, reflects bool) (*types.Named, bool) {
	t = types.Unalias(t)
	if b, isBasic := t.(*types.Basic); isBasic {
		return nil, b.Kind() != types.Invalid && b.Kind() != types.UnsafePointer
	}
	if ptr, isPtr := t.(*types.Pointer); isPtr {
		t = types.Unalias(ptr.Elem())
	}
	named, isNamed := t.(*types.Named)
	if !isNamed {
		return nil, false
	}
	obj := named.Obj()
	if obj.Pkg() == nil || !top[obj.Pkg()] || obj.Parent() != obj.Pkg().Scope() {
		return nil, false
	}
	if named.TypeParams().Len() > 0 || named.TypeArgs().Len() > 0 {
		return nil, false
	}
	if _, isFunc := named.Underlying().(*types.Signature); isFunc {
		return nil, false
	}
	if reflects && carries(named.Underlying(), map[types.Type]bool{}) {
		return nil, false
	}
	for _, mt := range []types.Type{named, types.NewPointer(named)} {
		ms := types.NewMethodSet(mt)
		for i := range ms.Len() {
			fn, isFunc := ms.At(i).Obj().(*types.Func)
			if isFunc && fn.Exported() && types.IsInterface(fn.Signature().Recv().Type()) {
				return nil, false
			}
		}
	}
	return named, true
}

// handedAt returns the types (handedType) of the values call passes to the parameters of the cb
// member fn that carry a function. ok is false when a value cannot be classified (one call's
// results spread over the parameters among them), the parameter is not a plain interface (a
// function, or a composite holding one), or fn is generic: its parameters are then whatever the
// call instantiates them with.
func handedAt(info *types.Info, fn *types.Func, call *ast.CallExpr, top map[*types.Package]bool, reflects bool) (handed []*types.Named, ok bool) {
	if decl := fn.Signature(); decl.TypeParams().Len() > 0 || decl.RecvTypeParams().Len() > 0 {
		return nil, false
	}
	ft := info.TypeOf(call.Fun)
	if ft == nil {
		return nil, false
	}
	sig, isSig := ft.Underlying().(*types.Signature)
	if !isSig {
		return nil, false
	}
	n := sig.Params().Len()
	for i, arg := range call.Args {
		var pt types.Type
		switch {
		case sig.Variadic() && i >= n-1:
			pt = sig.Params().At(n - 1).Type()
			if slice, isSlice := pt.(*types.Slice); isSlice && !call.Ellipsis.IsValid() {
				pt = slice.Elem()
			}
		case i < n:
			pt = sig.Params().At(i).Type()
		default:
			return nil, false
		}
		if !carries(pt, map[types.Type]bool{}) {
			continue
		}
		if _, isIface := pt.Underlying().(*types.Interface); !isIface {
			return nil, false
		}
		tv, known := info.Types[arg]
		if !known || tv.Type == nil {
			return nil, false
		}
		if tv.IsNil() {
			continue
		}
		named, classified := handedType(tv.Type, top, reflects)
		if !classified {
			return nil, false
		}
		if named != nil {
			handed = append(handed, named)
		}
	}
	return handed, true
}

// calleeIdent returns the identifier a call names its callee by: f(...), x.f(...), with parentheses
// removed. Any other callee has none.
func calleeIdent(fun ast.Expr) *ast.Ident {
	switch f := ast.Unparen(fun).(type) {
	case *ast.Ident:
		return f
	case *ast.SelectorExpr:
		return f.Sel
	}
	return nil
}

type memberKey struct{ pkg, owner, name string }

func keyOf(obj types.Object) (memberKey, bool) {
	if obj == nil || obj.Pkg() == nil {
		return memberKey{}, false
	}
	switch o := obj.(type) {
	case *types.Func:
		obj = o.Origin()
	case *types.Var:
		obj = o.Origin()
	}
	k := memberKey{pkg: obj.Pkg().Path(), name: obj.Name()}
	if f, ok := obj.(*types.Func); ok {
		if recv := f.Type().(*types.Signature).Recv(); recv != nil {
			k.owner = typeName(recv.Type())
		}
	}
	if v, ok := obj.(*types.Var); ok && v.IsField() {
		// A field is keyed by its name and the struct it is selected from, found by the caller.
		k.owner = "\x00field"
	}
	return k, true
}

func typeName(t types.Type) string {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := types.Unalias(t).(*types.Named); ok {
		return n.Obj().Name()
	}
	return t.String()
}

// carries reports whether a value of type t may hold a function: it is one, an interface, a type
// parameter, or a composite of those. database/sql's driver.Value and driver.NamedValue are exempt:
// database/sql's default converter admits no function there, and a driver that installs its own
// converter is refused separately.
func carries(t types.Type, seen map[types.Type]bool) bool {
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	switch t := t.(type) {
	case *types.Signature, *types.Interface, *types.TypeParam:
		return true
	case *types.Basic:
		// A type that failed to check may be anything.
		return t.Kind() == types.Invalid
	case *types.Named:
		if o := t.Obj(); o.Pkg() != nil && o.Pkg().Path() == "database/sql/driver" && (o.Name() == "Value" || o.Name() == "NamedValue") {
			return false
		}
		return carries(t.Underlying(), seen)
	case *types.Pointer:
		return carries(t.Elem(), seen)
	case *types.Slice:
		return carries(t.Elem(), seen)
	case *types.Array:
		return carries(t.Elem(), seen)
	case *types.Chan:
		return carries(t.Elem(), seen)
	case *types.Map:
		return carries(t.Key(), seen) || carries(t.Elem(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if carries(t.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func sigCarries(s *types.Signature) bool {
	for i := 0; i < s.Params().Len(); i++ {
		if carries(s.Params().At(i).Type(), map[types.Type]bool{}) {
			return true
		}
	}
	return false
}

// callbackAPI lists the members of the packages' API that take or hold a function or interface
// value: exported functions and methods (of any type, exported or not, and of interfaces the package
// declares) with such a parameter, and exported variables and struct fields of such a type. It
// reports false when a package has no type information or declares a method that installs a
// value converter.
func callbackAPI(cb []*packages.Package) (members map[memberKey]bool, sigs map[string][]*types.Signature, ok bool) {
	members = map[memberKey]bool{}
	sigs = map[string][]*types.Signature{}
	addFunc := func(f *types.Func) {
		if !f.Exported() {
			return
		}
		s := f.Type().(*types.Signature)
		if !sigCarries(s) {
			return
		}
		if k, kok := keyOf(f); kok {
			members[k] = true
			sigs[f.Name()] = append(sigs[f.Name()], s)
		}
	}
	for _, p := range cb {
		if p.Types == nil {
			return nil, nil, false
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			switch o := scope.Lookup(name).(type) {
			case *types.Func:
				addFunc(o)
			case *types.Var:
				if o.Exported() && carries(o.Type(), map[types.Type]bool{}) {
					members[memberKey{pkg: p.PkgPath, name: o.Name()}] = true
				}
			case *types.TypeName:
				named, isNamed := types.Unalias(o.Type()).(*types.Named)
				if !isNamed {
					continue
				}
				for i := 0; i < named.NumMethods(); i++ {
					m := named.Method(i)
					if m.Name() == "CheckNamedValue" || m.Name() == "ColumnConverter" {
						return nil, nil, false
					}
					addFunc(m)
				}
				switch u := named.Underlying().(type) {
				case *types.Interface:
					for i := 0; i < u.NumExplicitMethods(); i++ {
						addFunc(u.ExplicitMethod(i))
					}
				case *types.Struct:
					for i := 0; i < u.NumFields(); i++ {
						if f := u.Field(i); f.Exported() && carries(f.Type(), map[types.Type]bool{}) {
							members[memberKey{pkg: p.PkgPath, owner: "\x00field", name: f.Name()}] = true
						}
					}
				}
			}
		}
	}
	return members, sigs, true
}

// handedValues returns the types (handedType) of the values the build hands the cb packages, by
// plain calls passing one where the package takes an interface. ok is false when the build may hand
// them a function or interface value any other way, or cannot be shown not to.
func handedValues(top, cb []*packages.Package, reflects bool, droppedFiles map[string][]string, tags []string) (handed []*types.Named, ok bool) {
	members, sigs, ok := callbackAPI(cb)
	if !ok {
		return nil, false
	}
	for _, files := range droppedFiles {
		for _, f := range files {
			if declaresConverter(f) {
				return nil, false
			}
		}
	}
	isCb := map[string]bool{}
	for _, p := range cb {
		isCb[p.PkgPath] = true
	}
	searched := map[*types.Package]bool{}
	for _, p := range top {
		if p.Types != nil && !isMain(p) {
			searched[p.Types] = true
		}
	}
	names := map[string]bool{}
	for k := range members {
		names[k.name] = true
	}
	reaches := map[*packages.Package]bool{}
	var reach func(p *packages.Package) bool
	reach = func(p *packages.Package) bool {
		if v, seen := reaches[p]; seen {
			return v
		}
		reaches[p] = false
		v := isCb[p.PkgPath]
		for _, imp := range p.Imports {
			v = reach(imp) || v
		}
		reaches[p] = v
		return v
	}
	ctx := build.Default
	ctx.CgoEnabled = true
	ctx.BuildTags = tags
	failed := false
	set := map[*types.Named]bool{}
	packages.Visit(top, nil, func(p *packages.Package) {
		if failed || isCb[p.PkgPath] || p.PkgPath == "unsafe" {
			return
		}
		if len(p.GoFiles) > 0 && (p.TypesInfo == nil || len(p.Syntax) == 0) {
			failed = true
			return
		}
		if len(p.Errors) > 0 && reach(p) {
			failed = true
			return
		}
		for _, path := range p.IgnoredFiles {
			if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") && importsCb(path, isCb, ctx) {
				failed = true
				return
			}
		}
		if p.TypesInfo == nil {
			return
		}
		isMember := func(obj types.Object) bool {
			k, kok := keyOf(obj)
			return kok && members[k]
		}
		// A member named as the callee of a plain call is classified by what the call passes.
		classified := map[*ast.Ident]bool{}
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				id := calleeIdent(call.Fun)
				if id == nil {
					return true
				}
				fn, isFunc := p.TypesInfo.Uses[id].(*types.Func)
				if !isFunc || !isMember(fn) {
					return true
				}
				if ts, cok := handedAt(p.TypesInfo, fn, call, searched, reflects); cok {
					classified[id] = true
					for _, t := range ts {
						set[t] = true
					}
				}
				return true
			})
		}
		for id, obj := range p.TypesInfo.Uses {
			if isMember(obj) && !classified[id] {
				failed = true
				return
			}
		}
		for id, obj := range p.TypesInfo.Defs {
			// An interface re-declaring an API method lets the value travel under another name.
			f, isFunc := obj.(*types.Func)
			if !isFunc || id == nil || !names[f.Name()] {
				continue
			}
			s := f.Type().(*types.Signature)
			if s.Recv() == nil {
				continue
			}
			if _, isIface := s.Recv().Type().Underlying().(*types.Interface); !isIface {
				continue
			}
			for _, api := range sigs[f.Name()] {
				if types.Identical(s, api) {
					failed = true
					return
				}
			}
		}
		for _, tv := range p.TypesInfo.Types {
			if tv.Value != nil && tv.Value.Kind() == constant.String && names[constant.StringVal(tv.Value)] {
				failed = true
				return
			}
		}
	})
	if failed {
		return nil, false
	}
	for t := range set {
		handed = append(handed, t)
	}
	sort.Slice(handed, func(i, j int) bool { return handedName(handed[i]) < handedName(handed[j]) })
	return handed, true
}

// handedName names a handed type as the limit discloses it.
func handedName(t *types.Named) string {
	return t.Obj().Pkg().Path() + "." + t.Obj().Name()
}

// importsCb reports whether the Go file at path, which the build left out, would be compiled with
// cgo enabled and imports a cb package. A file that cannot be read counts.
func importsCb(path string, isCb map[string]bool, ctx build.Context) bool {
	if ok, err := ctx.MatchFile(filepath.Dir(path), filepath.Base(path)); err == nil && !ok {
		return false
	}
	_, imps, _, err := fileImports(path)
	if err != nil {
		return true
	}
	for _, imp := range imps {
		if isCb[imp] {
			return true
		}
	}
	return false
}

// declaresConverter reports whether the Go file declares a method that installs a value converter
// for database/sql. An unreadable file counts.
func declaresConverter(path string) bool {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return true
	}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv != nil && (fn.Name.Name == "CheckNamedValue" || fn.Name.Name == "ColumnConverter") {
			return true
		}
	}
	return false
}
