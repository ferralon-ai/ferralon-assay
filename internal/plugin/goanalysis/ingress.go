package goanalysis

import (
	"context"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// FindIngresses identifies framework-idiomatic entry points in the module at
// req.BuildDir: the program main(s) and net/http handler shapes
// (func(http.ResponseWriter, *http.Request) / http.HandlerFunc), plus
// statically-discoverable registered routes (http.HandleFunc / ServeMux). It
// never guesses arbitrary exported funcs as ingresses — an unrecognized func is
// simply not an ingress (absence is declared at the reachability layer, not
// fabricated here). A load/SSA-build failure is a hard error (inv.4).
func FindIngresses(ctx context.Context, req plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	sp, res, err := loadSSA(ctx, req.BuildDir)
	if err != nil {
		return plugin.IngressResult{}, err
	}

	seen := map[string]bool{}
	var ingresses []plugin.Ingress
	add := func(in plugin.Ingress) {
		key := in.Kind + "\x00" + in.Symbol.SCIP + "\x00" + in.Selector
		if seen[key] {
			return
		}
		seen[key] = true
		ingresses = append(ingresses, in)
	}

	for _, p := range res.Packages {
		if p.Types == nil {
			continue
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			fn, ok := obj.(*types.Func)
			if !ok {
				continue
			}
			sig, _ := fn.Type().(*types.Signature)
			if sig == nil {
				continue
			}
			if fn.Name() == "main" && p.Name == "main" && sig.Recv() == nil {
				add(plugin.Ingress{Kind: "main", Symbol: sym(scipFromPackage(p, fn))})
				continue
			}
			if isHTTPHandlerSig(sig) {
				add(plugin.Ingress{Kind: "handler", Symbol: sym(scipFromPackage(p, fn))})
			}
		}
	}

	for _, route := range sp.discoverRoutes() {
		add(plugin.Ingress{Kind: "http_route", Symbol: sym(route.symbol), Selector: route.selector})
	}

	sort.Slice(ingresses, func(i, j int) bool {
		if ingresses[i].Kind != ingresses[j].Kind {
			return ingresses[i].Kind < ingresses[j].Kind
		}
		if ingresses[i].Symbol.SCIP != ingresses[j].Symbol.SCIP {
			return ingresses[i].Symbol.SCIP < ingresses[j].Symbol.SCIP
		}
		return ingresses[i].Selector < ingresses[j].Selector
	})

	return plugin.IngressResult{Partiality: plugin.Complete(), Ingresses: ingresses}, nil
}

// isHTTPHandlerSig reports whether sig is the net/http handler shape
// func(http.ResponseWriter, *http.Request) with no results.
func isHTTPHandlerSig(sig *types.Signature) bool {
	if sig.Recv() != nil {
		return false
	}
	params := sig.Params()
	if params.Len() != 2 || sig.Results().Len() != 0 {
		return false
	}
	return isNamed(params.At(0).Type(), "net/http", "ResponseWriter") &&
		isPointerToNamed(params.At(1).Type(), "net/http", "Request")
}

func isNamed(t types.Type, pkgPath, name string) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == name && obj.Pkg() != nil && obj.Pkg().Path() == pkgPath
}

func isPointerToNamed(t types.Type, pkgPath, name string) bool {
	ptr, ok := t.(*types.Pointer)
	if !ok {
		return false
	}
	return isNamed(ptr.Elem(), pkgPath, name)
}

type route struct {
	selector string
	symbol   string // SCIP of the registered handler func, when statically known
}

// discoverRoutes scans the SSA for static calls registering an http handler on a
// route and pulls the constant route pattern (when present) and every statically-
// known handler func out of the call arguments. Two registrar families are
// recognized, both framework-idiomatic (never arbitrary exported funcs):
//
//   - net/http: HandleFunc / (*ServeMux).HandleFunc / Handle — pattern then handler.
//   - gopkg.in/macaron.v1: the verb methods (Get/Post/Put/Patch/Delete/Options/
//     Head/Any) and Combo on the router / ComboRouter. Macaron handlers are passed
//     as a variadic ...Handler (Handler = interface{}), so each handler func is
//     boxed (MakeInterface) and packed into the call's variadic slice; a route may
//     carry several handlers (middleware + the leaf handler). We extract EVERY
//     statically-resolved handler func, not just the second arg — middleware that
//     is a call result (bind(...)/bindIgnErr(...)) resolves to no static function
//     and is conservatively skipped.
//
// A registrar whose pattern is not a constant (or, for Combo's chained verbs, is
// carried on the Combo call rather than the verb call) still contributes its
// handlers with an empty selector — the handler is the attacker-reachable entry,
// the selector is convenience metadata.
func (s *ssaProgram) discoverRoutes() []route {
	var routes []route
	for fn := range ssautil.AllFunctions(s.prog) {
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				call, ok := instr.(ssa.CallInstruction)
				if !ok {
					continue
				}
				callee := call.Common().StaticCallee()
				if callee == nil || !isHTTPRouteRegistrar(callee) {
					continue
				}
				args := call.Common().Args
				// Skip the receiver for method registrars so arg[0] is the pattern.
				if call.Common().Signature().Recv() != nil && len(args) > 0 {
					args = args[1:]
				}
				if len(args) == 0 {
					continue
				}
				// The leading arg is the route pattern when it is a constant string;
				// otherwise (e.g. a macaron Combo verb that inherits the Combo pattern)
				// there is no selector and every arg is a candidate handler.
				selector, hasPattern := constString(args[0])
				handlerArgs := args
				if hasPattern {
					handlerArgs = args[1:]
				}
				for _, h := range s.collectHandlers(handlerArgs) {
					routes = append(routes, route{selector: selector, symbol: h})
				}
			}
		}
	}
	return routes
}

// collectHandlers returns the SCIP ids of every statically-resolved handler func
// among args, unwrapping the variadic slice that a ...Handler registrar packs its
// handlers into. A non-handler arg (a constant, a middleware call result) resolves
// to nothing and is skipped — honesty over reach (inv.5).
func (s *ssaProgram) collectHandlers(args []ssa.Value) []string {
	var out []string
	seen := map[*ssa.Function]bool{}
	emit := func(fn *ssa.Function) {
		if fn == nil || seen[fn] {
			return
		}
		seen[fn] = true
		out = append(out, s.scipFunc(fn))
	}
	for _, a := range args {
		if sl, ok := a.(*ssa.Slice); ok {
			for _, v := range variadicSliceValues(sl) {
				emit(staticHandler(v))
			}
			continue
		}
		emit(staticHandler(a))
	}
	return out
}

// variadicSliceValues recovers the element values a variadic call packed into the
// slice sl. The SSA lowering of f(a, b, c) into f(pattern, []Handler{a,b,c}) allocs
// a backing array, Stores each element through an IndexAddr, then Slices it; we walk
// that backing alloc's IndexAddr/Store referrers to recover the stored values.
func variadicSliceValues(sl *ssa.Slice) []ssa.Value {
	alloc, ok := sl.X.(*ssa.Alloc)
	if !ok {
		return nil
	}
	var vals []ssa.Value
	for _, ref := range *alloc.Referrers() {
		idx, ok := ref.(*ssa.IndexAddr)
		if !ok {
			continue
		}
		for _, iref := range *idx.Referrers() {
			if st, ok := iref.(*ssa.Store); ok {
				vals = append(vals, st.Val)
			}
		}
	}
	return vals
}

// macaronRegistrarMethods are the gopkg.in/macaron.v1 router methods that register a
// handler against a route. Combo registers a multi-verb route; the verb methods set
// the handler for one method. Group is intentionally excluded: its argument is a
// route-grouping closure, not an attacker-facing handler.
var macaronRegistrarMethods = map[string]bool{
	"Get": true, "Post": true, "Put": true, "Patch": true,
	"Delete": true, "Options": true, "Head": true, "Any": true, "Combo": true,
}

func isHTTPRouteRegistrar(fn *ssa.Function) bool {
	if fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	switch fn.Pkg.Pkg.Path() {
	case "net/http":
		switch fn.Name() {
		case "HandleFunc", "Handle":
			return true
		}
	case "gopkg.in/macaron.v1":
		return macaronRegistrarMethods[fn.Name()]
	}
	return false
}

func constString(v ssa.Value) (string, bool) {
	c, ok := v.(*ssa.Const)
	if !ok || c.Value == nil {
		return "", false
	}
	s := c.Value.String()
	return strings.Trim(s, `"`), true
}

// staticHandler unwraps the handler argument to the underlying *ssa.Function when
// it is a direct function reference or an http.HandlerFunc conversion of one.
func staticHandler(v ssa.Value) *ssa.Function {
	switch h := v.(type) {
	case *ssa.Function:
		return h
	case *ssa.MakeClosure:
		if fn, ok := h.Fn.(*ssa.Function); ok {
			return fn
		}
	case *ssa.ChangeType:
		return staticHandler(h.X)
	case *ssa.MakeInterface:
		return staticHandler(h.X)
	}
	return nil
}
