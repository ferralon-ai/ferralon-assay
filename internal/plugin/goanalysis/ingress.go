package goanalysis

import (
	"context"
	"go/types"
	"path"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// FindIngresses identifies framework-idiomatic entry points in the module at
// req.BuildDir: the program main(s) and net/http handler shapes
// (func(http.ResponseWriter, *http.Request) / http.HandlerFunc), plus
// statically-discoverable registered routes (http.HandleFunc / ServeMux, macaron,
// chi, gin and echo). It never guesses arbitrary exported funcs as ingresses — an
// unrecognized func is simply not an ingress (absence is declared at the
// reachability layer, not fabricated here). A load/SSA-build failure is a hard error
// (inv.4).
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
//   - github.com/go-chi/chi, github.com/go-chi/chi/v5, github.com/gin-gonic/gin and
//     github.com/labstack/echo/v4: see pathRouter. The router is identified by the
//     import path of the package DECLARING the called method, never by a type or
//     method name alone, and a route's selector is its full composed pattern.
//
// A registrar whose pattern is not a constant (or, for Combo's chained verbs, is
// carried on the Combo call rather than the verb call) still contributes its
// handlers with an empty selector — the handler is the attacker-reachable entry,
// the selector is convenience metadata.
func (s *ssaProgram) discoverRoutes() []route {
	var routes []route
	prefixes := newPrefixResolver(s)
	for fn := range ssautil.AllFunctions(s.prog) {
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				call, ok := instr.(ssa.CallInstruction)
				if !ok {
					continue
				}
				common := call.Common()
				if router, name, recv, args := pathRegistrar(common); router != nil {
					routes = append(routes, s.pathRoutes(prefixes, router, name, recv, args)...)
					continue
				}
				callee := common.StaticCallee()
				if callee == nil || !isHTTPRouteRegistrar(callee) {
					continue
				}
				args := common.Args
				// Skip the receiver for method registrars so arg[0] is the pattern.
				if common.Signature().Recv() != nil && len(args) > 0 {
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
				for _, h := range s.collectHandlers(handlerArgs, staticHandler) {
					routes = append(routes, route{selector: selector, symbol: h})
				}
			}
		}
	}
	return routes
}

// pathRoutes returns the routes one pathRouter registrar call registers: name is the
// called method, recv the router it is called on and args its arguments after the
// receiver. A catch-all registrar (gin's NoRoute/NoMethod) takes no pattern and
// registers under catchAllSelector. Otherwise the HTTP method(s) a methodFirst
// registrar takes ahead of the pattern are skipped, and a constant pattern is
// composed under every prefix the receiver statically carries (prefixResolver); when
// a prefix above it cannot be resolved, the selector is the local pattern alone —
// never a guessed prefix.
//
// An unresolved prefix is not declared as a partiality reason on the ingress result.
// It hides no code and no edge: the handler is still found, and every path through it
// is resolved exactly as before; only the selector, which is display metadata, is
// shorter. A reason there is unioned into the exposure footprint, and every reason the
// report does not list as a method limit is classified did-not-run
// (report.ClassifyPartialityReason), which turns each no-path advisory on the service
// undetermined (trigger's analysisDidNotRun) — a claim the analysis did not run that
// is false here.
func (s *ssaProgram) pathRoutes(prefixes *prefixResolver, r *pathRouter, name string, recv ssa.Value, args []ssa.Value) []route {
	selectors := []string{""}
	switch {
	case r.catchAll[name]:
		selectors = []string{catchAllSelector}
	default:
		if r.methodFirst[name] && len(args) > 0 {
			args = args[1:]
		}
		if len(args) == 0 {
			return nil
		}
		// The leading argument is the pattern, a string and never a handler.
		pattern, hasPattern := constString(args[0])
		if hasPattern || isStringType(args[0].Type()) {
			args = args[1:]
		}
		if hasPattern {
			if ps, ok := prefixes.prefixes(recv); ok {
				selectors = selectors[:0]
				for _, p := range ps {
					selectors = append(selectors, r.join(p, pattern))
				}
			} else {
				selectors = []string{pattern}
			}
		}
		// echo takes one handler after the pattern; what follows is route middleware.
		if r.oneHandler && len(args) > 1 {
			args = args[:1]
		}
	}
	var routes []route
	for _, h := range s.collectHandlers(args, func(v ssa.Value) *ssa.Function { return s.routerHandler(r, v) }) {
		for _, sel := range selectors {
			routes = append(routes, route{selector: sel, symbol: h})
		}
	}
	return routes
}

// collectHandlers returns the SCIP ids of every statically-resolved handler func
// among args, unwrapping the variadic slice that a ...Handler registrar packs its
// handlers into. resolve maps one arg to its handler func (staticHandler, or
// routerHandler for a pathRouter registrar). A non-handler arg (a constant, a
// middleware call result) resolves to nothing and is skipped — honesty over reach
// (inv.5).
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

// joinChi composes a Route prefix and a pattern as chi mounts a sub-router: the
// prefix's trailing slash is dropped and the pattern appended.
func joinChi(prefix, pattern string) string { return strings.TrimSuffix(prefix, "/") + pattern }

// ginPkgPaths is the import path of the gin router. A package with gin's name, types
// or methods under any other path is not gin.
var ginPkgPaths = map[string]bool{"github.com/gin-gonic/gin": true}

// ginRegistrarMethods are the gin methods that register a handler chain against a
// route, declared on *gin.RouterGroup (and reached through *gin.Engine, which embeds
// it) and on the gin.IRoutes interface: the verb methods and Any take (pattern,
// ...HandlerFunc), Handle takes (method, pattern, ...HandlerFunc) and Match takes
// ([]method, pattern, ...HandlerFunc). Every handler in a route's chain is an
// ingress, as with macaron. Use and Group are intentionally excluded: Use's
// middleware runs for every route and is no route of its own, and Group's handler
// arguments are the group's middleware, the same; the routes registered on the
// *RouterGroup a Group returns are recognized at their own call sites, under the
// Group's prefix. Static, StaticFS, StaticFile and StaticFileFS are no registrar
// either: they serve files from a directory or file system and take no first-party
// handler, so there is nothing of the application's own for an attacker to reach.
var ginRegistrarMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
	"HEAD": true, "OPTIONS": true, "Any": true, "Handle": true, "Match": true,
}

// ginMethodRegistrars are the ginRegistrarMethods whose leading argument is the HTTP
// method (Handle) or methods (Match), ahead of the route pattern.
var ginMethodRegistrars = map[string]bool{"Handle": true, "Match": true}

// ginCatchAllRegistrars are *gin.Engine's NoRoute and NoMethod: they take a handler
// chain and no pattern, and run for every request no route matches (or none matches
// by method). Every handler in the chain is an ingress, under catchAllSelector.
var ginCatchAllRegistrars = map[string]bool{"NoRoute": true, "NoMethod": true}

// catchAllSelector is the selector of a route registered under no pattern of its own
// because it answers every unmatched path: gin's NoRoute and NoMethod.
const catchAllSelector = "*"

// ginWrappers are gin's adapters from a net/http handler to a gin.HandlerFunc. A
// registered WrapF(f) or WrapH(h) ingresses as the first-party f, or h's ServeHTTP,
// that it wraps; the closure gin builds around it is never a handler.
var ginWrappers = map[string]bool{"WrapF": true, "WrapH": true}

// joinGin composes a group prefix and a relative path as gin's joinPaths does:
// path.Join, keeping a trailing slash the relative path ends with.
func joinGin(prefix, pattern string) string {
	if prefix == "" || pattern == "" {
		return prefix + pattern
	}
	joined := path.Join(prefix, pattern)
	if strings.HasSuffix(pattern, "/") && !strings.HasSuffix(joined, "/") {
		joined += "/"
	}
	return joined
}

// echoPkgPaths is the import path of the echo router (v4). A package with echo's
// name, types or methods under any other path is not echo.
var echoPkgPaths = map[string]bool{"github.com/labstack/echo/v4": true}

// echoRegistrarMethods are the echo methods that register a handler against a route,
// declared on both *echo.Echo and *echo.Group: the verb methods and Any take
// (path, HandlerFunc, ...MiddlewareFunc), Add takes (method, path, HandlerFunc, ...)
// and Match takes ([]method, path, HandlerFunc, ...). Only the one HandlerFunc is an
// ingress; the trailing MiddlewareFunc arguments are route middleware. Use, Pre and
// Group are intentionally excluded: their arguments are middleware, which runs for
// every route under them and is no route of its own; the routes registered on the
// *echo.Group a Group returns are recognized at their own call sites, under the
// Group's prefix.
var echoRegistrarMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
	"HEAD": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
	"Any": true, "Add": true, "Match": true,
}

// echoMethodRegistrars are the echoRegistrarMethods whose leading argument is the
// HTTP method (Add) or methods (Match), ahead of the path.
var echoMethodRegistrars = map[string]bool{"Add": true, "Match": true}

// echoWrappers are echo's adapters from a net/http handler to an echo.HandlerFunc: a
// registered WrapHandler(h) ingresses as h's ServeHTTP (or the first-party func an
// http.HandlerFunc conversion wraps). WrapMiddleware adapts middleware, which is no
// route handler, and the closures echo builds inside either adapter are never one.
var echoWrappers = map[string]bool{"WrapHandler": true}

// joinEcho composes a group prefix and a path as echo does: plain concatenation.
func joinEcho(prefix, pattern string) string { return prefix + pattern }

// pathRouter is a third-party router recognized by import path — the rule chi set
// and gin and echo reuse:
//
//   - the router is identified by the import path of the package DECLARING the
//     called method (paths), never by a type or method name alone;
//   - the registrar methods (registrars) are recognized as a static call on the
//     concrete router and as an interface (invoke) call on the package's router
//     interface;
//   - the registrars in methodFirst take the HTTP method(s) ahead of the route
//     pattern, and that argument is skipped so the selector is the pattern;
//   - the catch-all registrars (catchAll) take no pattern and register under
//     catchAllSelector;
//   - a router whose registrars take exactly one handler after the pattern
//     (oneHandler, echo) treats the arguments after it as route middleware, never a
//     handler; otherwise every handler in the chain is one (gin, macaron);
//   - grouping closures and middleware (chi's Route/Group/With, gin's Use/Group,
//     echo's Use/Pre/Group) are no registrar: their arguments are not route handlers;
//   - a route's selector is its full pattern, composed from the prefixes of the
//     groups it is registered under (prefixResolver): a root router (roots) carries
//     none, a group method (groups: gin's and echo's Group, chi's Route) adds its
//     constant pattern to its receiver's, a scope method (scopes: chi's Route and
//     Group) hands its closure's router parameter the same, and a pass-through
//     (passes: chi's With and Group, gin's Use) returns its receiver's; join composes
//     as the router does. A prefix that cannot be resolved statically leaves the
//     local pattern alone, never a guess;
//   - adapter and router ServeHTTP methods are excluded, deriving the adapter
//     package from the http.Handler interface the value is boxed into (routerHandler);
//   - the package's own net/http adapters (wrappers) resolve to the handler they wrap;
//   - the handler's context parameter, a pointer to a struct (gin) or an interface
//     (echo), is seeded like every ingress parameter, and its request accessors are
//     modeled in the taint engine (contextAccess) as static or invoke calls.
type pathRouter struct {
	paths, registrars, methodFirst, catchAll, wrappers map[string]bool
	oneHandler                                         bool
	roots, groups, scopes, passes                      map[string]bool
	join                                               func(prefix, pattern string) string
}

var (
	chiRouter = &pathRouter{paths: chiPkgPaths, registrars: chiRegistrarMethods, methodFirst: chiMethodRegistrars,
		roots:  map[string]bool{"NewRouter": true, "NewMux": true},
		groups: map[string]bool{"Route": true}, scopes: map[string]bool{"Route": true, "Group": true},
		passes: map[string]bool{"With": true, "Group": true}, join: joinChi}
	ginRouter = &pathRouter{paths: ginPkgPaths, registrars: ginRegistrarMethods,
		methodFirst: ginMethodRegistrars, catchAll: ginCatchAllRegistrars, wrappers: ginWrappers,
		roots: map[string]bool{"New": true, "Default": true}, groups: map[string]bool{"Group": true},
		passes: map[string]bool{"Use": true}, join: joinGin}
	echoRouter = &pathRouter{paths: echoPkgPaths, registrars: echoRegistrarMethods,
		methodFirst: echoMethodRegistrars, wrappers: echoWrappers, oneHandler: true,
		roots: map[string]bool{"New": true}, groups: map[string]bool{"Group": true}, join: joinEcho}
	pathRouters = []*pathRouter{chiRouter, ginRouter, echoRouter}
)

// routerCall reports the pathRouter whose package declares the function or method
// common calls, with its name, the receiver (nil for a package func) and the
// arguments after it; nil when the callee is in no router package. Both call shapes
// are matched by the import path of the package that declares the callee: a static
// call ((*chi.Mux).Get, (*gin.RouterGroup).GET, (*echo.Group).GET, gin.New) and an
// interface (invoke) call on the router interface (chi.Router, gin.IRoutes) — the
// shape of every chi registration inside a Route/Group closure or on a With result,
// which has no static callee, and which carries its receiver outside Args.
func routerCall(common *ssa.CallCommon) (r *pathRouter, name string, recv ssa.Value, args []ssa.Value) {
	var pkg *types.Package
	args = common.Args
	if common.IsInvoke() {
		if common.Method == nil {
			return nil, "", nil, nil
		}
		pkg, name, recv = common.Method.Pkg(), common.Method.Name(), common.Value
	} else {
		callee := common.StaticCallee()
		if callee == nil || callee.Pkg == nil {
			return nil, "", nil, nil
		}
		pkg, name = callee.Pkg.Pkg, callee.Name()
		if callee.Signature.Recv() != nil && len(args) > 0 {
			recv, args = args[0], args[1:]
		}
	}
	if pkg == nil {
		return nil, "", nil, nil
	}
	for _, r := range pathRouters {
		if r.paths[pkg.Path()] {
			return r, name, recv, args
		}
	}
	return nil, "", nil, nil
}

// pathRegistrar is routerCall narrowed to a route registrar (registrars or
// catchAll) called on a router: nil when common calls none.
func pathRegistrar(common *ssa.CallCommon) (r *pathRouter, name string, recv ssa.Value, args []ssa.Value) {
	r, name, recv, args = routerCall(common)
	if r == nil || recv == nil || !(r.registrars[name] || r.catchAll[name]) {
		return nil, "", nil, nil
	}
	return r, name, recv, args
}

// routerHandler is staticHandler plus two shapes a pathRouter registrar takes. A
// call to one of the router package's own wrappers (gin.WrapF / gin.WrapH,
// echo.WrapHandler) resolves to the handler it wraps. And an http.Handler (chi's
// Handle, Method and Mount, the value gin.WrapH and echo.WrapHandler take): a concrete
// value boxed into the interface contributes its ServeHTTP method. A router mounted as
// a sub-router (a chi Mux, a gin Engine, an echo Echo), or an adapter handler type (an
// http.HandlerFunc held in a variable), is skipped: the sub-router's own registrations
// are the ingresses, and the adapter's ServeHTTP is no first-party handler. The
// adapter package is the one declaring the http.Handler interface the value is boxed
// into — net/http in real code, named explicitly as well.
func (s *ssaProgram) routerHandler(r *pathRouter, v ssa.Value) *ssa.Function {
	if fn := staticHandler(v); fn != nil {
		return fn
	}
	if call, ok := v.(*ssa.Call); ok {
		w := call.Call.StaticCallee()
		if w == nil || w.Pkg == nil || !r.paths[w.Pkg.Pkg.Path()] || !r.wrappers[w.Name()] ||
			len(call.Call.Args) != 1 {
			return nil
		}
		return s.routerHandler(r, call.Call.Args[0])
	}
	mi, ok := v.(*ssa.MakeInterface)
	if !ok {
		return nil
	}
	t := mi.X.Type()
	adapter := namedTypePkg(mi.Type())
	if pkg := namedTypePkg(t); pkg == nil || pkg.Path() == "net/http" ||
		(adapter != nil && pkg.Path() == adapter.Path()) || r.paths[pkg.Path()] {
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

// isStringType reports whether t is a string type.
func isStringType(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsString != 0
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
