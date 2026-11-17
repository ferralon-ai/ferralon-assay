package goanalysis

import (
	"go/ast"
	"go/build"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
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
// Every "cannot tell" is false: a package with no type information, a package that failed to
// type-check and reaches a cb package, a left-out file importing a cb package, a method that lets
// database/sql install its own value converter (driver.NamedValueChecker, driver.ColumnConverter),
// an interface that re-declares an API method, or a string constant naming one (a reflective call).
//
// A cb package whose cgo files the build dropped is loaded as its pure-Go variant, so its API is
// what that variant declares. A call that type-checks against it cannot pass a function value to a
// parameter the variant types without one, whatever the dropped file's signature; a call the variant
// does not declare fails to type-check, which is a "cannot tell" above.
func cgoCallbackTargets(pkgs, cb, roots []*packages.Package, droppedFiles map[string][]string, tags []string) (mods map[string]bool, ok bool) {
	if handsGoValue(pkgs, cb, droppedFiles, tags) {
		return nil, false
	}
	mods = map[string]bool{}
	packages.Visit(roots, nil, func(p *packages.Package) { mods[modulePURL(p)] = true })
	return mods, true
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

// handsGoValue reports whether the build may hand a cb package a function or interface value, or
// cannot be shown not to.
func handsGoValue(pkgs, cb []*packages.Package, droppedFiles map[string][]string, tags []string) bool {
	members, sigs, ok := callbackAPI(cb)
	if !ok {
		return true
	}
	for _, files := range droppedFiles {
		for _, f := range files {
			if declaresConverter(f) {
				return true
			}
		}
	}
	isCb := map[string]bool{}
	for _, p := range cb {
		isCb[p.PkgPath] = true
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
	packages.Visit(pkgs, nil, func(p *packages.Package) {
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
		for _, obj := range p.TypesInfo.Uses {
			if k, kok := keyOf(obj); kok && members[k] {
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
	return failed
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
