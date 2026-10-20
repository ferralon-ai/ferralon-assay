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
			if isSSHServerHandlerSig(sig) {
				add(plugin.Ingress{Kind: "ssh", Symbol: sym(scipFromPackage(p, fn))})
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

// sshAttackerTypes are the golang.org/x/crypto/ssh types that carry untrusted,
// attacker-supplied server-side connection data post-handshake: the live
// connection (ServerConn / ConnMetadata), an offered channel (NewChannel /
// Channel), and out-of-band requests (Request). A function that takes any of
// these as a parameter sits on the SSH attacker-input boundary — the analogue of
// a net/http handler's *http.Request. Deliberately excluded: ssh.PublicKey and
// ssh.ServerConfig, which also appear in trusted contexts (authorized-keys
// parsing, server setup), so matching them would over-flag non-ingress helpers.
var sshAttackerTypes = map[string]bool{
	"ServerConn": true, "ConnMetadata": true,
	"NewChannel": true, "Channel": true, "Request": true,
}

// isSSHServerHandlerSig reports whether sig takes at least one attacker-controlled
// golang.org/x/crypto/ssh value as a parameter. Unlike net/http there is no single
// registered handler signature — an SSH server threads the accepted connection,
// channels, and requests as arguments into ordinary funcs (e.g.
// handleSSHConn(sconn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request)),
// so the boundary is recognized by the presence of an attacker-controlled ssh param.
// Method receivers are not seeded (consistent with the handler/main detectors, which
// only classify package-scope funcs).
func isSSHServerHandlerSig(sig *types.Signature) bool {
	if sig.Recv() != nil {
		return false
	}
	params := sig.Params()
	for i := 0; i < params.Len(); i++ {
		if isSSHAttackerType(params.At(i).Type()) {
			return true
		}
	}
	return false
}

// isSSHAttackerType matches an sshAttackerTypes named type, unwrapping the pointer,
// channel, and pointer-in-channel shapes these values are threaded through
// (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request).
func isSSHAttackerType(t types.Type) bool {
	switch u := t.(type) {
	case *types.Chan:
		return isSSHAttackerType(u.Elem())
	case *types.Pointer:
		return isSSHNamedAttacker(u.Elem())
	default:
		return isSSHNamedAttacker(t)
	}
}

func isSSHNamedAttacker(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Pkg() != nil &&
		obj.Pkg().Path() == "golang.org/x/crypto/ssh" && sshAttackerTypes[obj.Name()]
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

// discoverRoutes scans the SSA for calls registering an http handler on a
// route and pulls the constant route pattern (when present) and every statically-
// known handler func out of the call arguments. Three registrar families are
// recognized, all framework-idiomatic (never arbitrary exported funcs):
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
//   - github.com/go-chi/chi and github.com/go-chi/chi/v5: see chiRegistrar. The
//     router is identified by the import path of the package DECLARING the called
//     method, never by a type or method name alone.
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
				common := call.Common()
				chiName, isChi := chiRegistrar(common)
				if !isChi {
					callee := common.StaticCallee()
					if callee == nil || !isHTTPRouteRegistrar(callee) {
						continue
					}
				}
				args := common.Args
				// Skip the receiver for method registrars so arg[0] is the pattern. An
				// interface (invoke) call carries its receiver outside Args.
				if !common.IsInvoke() && common.Signature().Recv() != nil && len(args) > 0 {
					args = args[1:]
				}
				// chi's Method/MethodFunc take the HTTP method ahead of the pattern.
				if isChi && chiMethodRegistrars[chiName] && len(args) > 0 {
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
				resolve := staticHandler
				if isChi {
					resolve = s.chiHandler
				}
				for _, h := range s.collectHandlers(handlerArgs, resolve) {
					routes = append(routes, route{selector: selector, symbol: h})
				}
			}
		}
	}
	return routes
}

// collectHandlers returns the SCIP ids of every statically-resolved handler func
// among args, unwrapping the variadic slice that a ...Handler registrar packs its
// handlers into. resolve maps one arg to its handler func (staticHandler, or
// chiHandler for a chi registrar). A non-handler arg (a constant, a middleware call
// result) resolves to nothing and is skipped — honesty over reach (inv.5).
func (s *ssaProgram) collectHandlers(args []ssa.Value, resolve func(ssa.Value) *ssa.Function) []string {
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
				emit(resolve(v))
			}
			continue
		}
		emit(resolve(a))
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

// chiPkgPaths are the import paths of the go-chi router: the module root (v1–v4)
// and the /v5 module. A package with chi's name, types or methods under any other
// path is not chi.
var chiPkgPaths = map[string]bool{
	"github.com/go-chi/chi":    true,
	"github.com/go-chi/chi/v5": true,
}

// chiRegistrarMethods are the chi router methods that register a handler against a
// route: the verb methods and Handle/HandleFunc take (pattern, handler), Mount takes
// (pattern, http.Handler), and Method/MethodFunc take (method, pattern, handler).
// Route, Group and With are intentionally excluded: their arguments are a
// route-grouping closure or middleware, not an attacker-facing handler. The
// registrations made inside a Route/Group closure, or on the Router a With returns,
// are calls on the chi.Router INTERFACE and are recognized at their own call sites.
var chiRegistrarMethods = map[string]bool{
	"Get": true, "Post": true, "Put": true, "Patch": true, "Delete": true,
	"Head": true, "Options": true, "Connect": true, "Trace": true,
	"Method": true, "MethodFunc": true, "Handle": true, "HandleFunc": true,
	"Mount": true,
}

// chiMethodRegistrars are the chiRegistrarMethods whose leading argument is the HTTP
// method, ahead of the route pattern.
var chiMethodRegistrars = map[string]bool{"Method": true, "MethodFunc": true}

// chiRegistrar reports whether common calls a chi route registrar, returning the
// method name. Both call shapes are matched by the import path of the package that
// declares the called method: a static call on the concrete router ((*chi.Mux).Get)
// and an interface (invoke) call on chi.Router — the shape of every registration
// inside a Route/Group closure or on a With result, which has no static callee.
func chiRegistrar(common *ssa.CallCommon) (string, bool) {
	var pkg *types.Package
	var name string
	if common.IsInvoke() {
		if common.Method == nil {
			return "", false
		}
		pkg, name = common.Method.Pkg(), common.Method.Name()
	} else {
		callee := common.StaticCallee()
		if callee == nil || callee.Pkg == nil {
			return "", false
		}
		pkg, name = callee.Pkg.Pkg, callee.Name()
	}
	if pkg == nil || !chiPkgPaths[pkg.Path()] || !chiRegistrarMethods[name] {
		return "", false
	}
	return name, true
}

// chiHandler is staticHandler plus the http.Handler that chi's Handle, Method and
// Mount take: a concrete value boxed into the interface contributes its ServeHTTP
// method. A chi router mounted as a sub-router, or a net/http handler type (an
// http.HandlerFunc held in a variable), is skipped: the sub-router's own
// registrations are the ingresses, and net/http's ServeHTTP is no first-party handler.
func (s *ssaProgram) chiHandler(v ssa.Value) *ssa.Function {
	if fn := staticHandler(v); fn != nil {
		return fn
	}
	mi, ok := v.(*ssa.MakeInterface)
	if !ok {
		return nil
	}
	t := mi.X.Type()
	if pkg := namedTypePkg(t); pkg == nil || pkg.Path() == "net/http" || chiPkgPaths[pkg.Path()] {
		return nil
	}
	sel := s.prog.MethodSets.MethodSet(t).Lookup(nil, "ServeHTTP")
	if sel == nil {
		return nil
	}
	return s.prog.MethodValue(sel)
}

// namedTypePkg returns the package declaring t's named type, unwrapping one pointer.
func namedTypePkg(t types.Type) *types.Package {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil {
		return nil
	}
	return named.Obj().Pkg()
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
