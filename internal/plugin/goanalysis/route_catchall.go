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
// defaults there, and those are the router's code, no first-party handler. The
// stored value resolves as a registered handler does (routerHandler); a value that
// is no static func resolves to nothing and is skipped.
func (s *ssaProgram) catchAllStoreRoutes(fn *ssa.Function, st *ssa.Store) []route {
	r, ok := catchAllStoreRouter(st.Addr)
	if !ok || fn.Pkg == nil || fn.Pkg.Pkg == nil || r.paths[fn.Pkg.Pkg.Path()] {
		return nil
	}
	var routes []route
	for _, h := range s.collectHandlers([]ssa.Value{st.Val}, func(v ssa.Value) *ssa.Function { return s.routerHandler(r, v) }) {
		routes = append(routes, route{selector: catchAllSelector, symbol: h})
	}
	return routes
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
