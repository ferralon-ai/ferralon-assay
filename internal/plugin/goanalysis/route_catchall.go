package goanalysis

import (
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// catchAllStoreRoutes returns the catch-all route a store installs: a first-party
// func assigned to one of a pathRouter's catch-all package vars (echo's
// NotFoundHandler and MethodNotAllowedHandler) or catch-all struct fields (echo's
// HTTPErrorHandler). These handlers are installed by assignment rather than by a
// registrar call, and answer requests no route matches, so each ingresses under
// catchAllSelector, like gin's NoRoute.
//
// A store made inside the router's own package is never one: echo initialises its
// defaults there, and those are the router's code, no first-party handler. Its
// bodies are in the program only when echo is one of the build's own packages (a
// workspace member, or echo's own repository under analysis), so only then does this
// check decide anything. The stored value resolves as a registered handler does
// (routerHandler); a value that is no static func resolves to nothing and is
// skipped, and so is a func declared outside the build's own packages (ownCode):
// first-party code that stores a dependency's func (e.HTTPErrorHandler =
// e.DefaultHTTPErrorHandler) installs the dependency's code, no first-party handler.
func (s *ssaProgram) catchAllStoreRoutes(handlers *handlerResolver, fn *ssa.Function, st *ssa.Store) []route {
	r, ok := catchAllStoreRouter(st.Addr)
	if !ok || fn.Pkg == nil || fn.Pkg.Pkg == nil || r.paths[fn.Pkg.Pkg.Path()] {
		return nil
	}
	resolve := func(v ssa.Value) *ssa.Function {
		if h := s.routerHandler(handlers, r, v); h != nil && s.ownCode(h) {
			return h
		}
		return nil
	}
	var routes []route
	for _, h := range s.collectHandlers([]ssa.Value{st.Val}, resolve) {
		routes = append(routes, route{selector: catchAllSelector, symbol: h})
	}
	return routes
}

// ownCode reports whether fn is declared in one of the build's own packages: a
// package the load loaded or a workspace member (typePkg), never a dependency's. A
// bound method value (e.DefaultHTTPErrorHandler) has no package of its own and is
// judged by its method's.
func (s *ssaProgram) ownCode(fn *ssa.Function) bool {
	pkg := funcTypePackage(fn)
	return pkg != nil && s.typePkg[pkg] != nil
}

// catchAllStoreRouter reports the pathRouter whose catch-all var or field addr is.
func catchAllStoreRouter(addr ssa.Value) (*pathRouter, bool) {
	switch a := addr.(type) {
	case *ssa.Global:
		if a.Pkg == nil || a.Pkg.Pkg == nil {
			return nil, false
		}
		for _, r := range pathRouters {
			if r.paths[a.Pkg.Pkg.Path()] && r.catchAllVars[a.Name()] {
				return r, true
			}
		}
	case *ssa.FieldAddr:
		ptr, ok := a.X.Type().Underlying().(*types.Pointer)
		if !ok {
			return nil, false
		}
		st, ok := ptr.Elem().Underlying().(*types.Struct)
		if !ok || a.Field >= st.NumFields() {
			return nil, false
		}
		pkg := namedTypePkg(a.X.Type())
		if pkg == nil {
			return nil, false
		}
		for _, r := range pathRouters {
			if r.paths[pkg.Path()] && r.catchAllFields[st.Field(a.Field).Name()] {
				return r, true
			}
		}
	}
	return nil, false
}
