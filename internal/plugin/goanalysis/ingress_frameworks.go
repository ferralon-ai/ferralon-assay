package goanalysis

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// Framework registrations whose handler is not an argument of a route call with a
// pattern beside it, so they do not fit pathRouter: a beego controller is routed by
// method name, a go-restful route is assembled by a builder, a websocket endpoint is
// the function that upgrades the connection, and a gRPC service is registered as one
// value whose methods are the handlers. Like every router here, each is identified by
// the import path of the package DECLARING the called function, never by a name alone.

var (
	beegoPkgPaths = map[string]bool{
		"github.com/beego/beego/v2/server/web": true,
		"github.com/beego/beego":               true,
		"github.com/astaxie/beego":             true,
	}
	// beegoMappedRegistrars take a pattern, a controller and the mapping of HTTP
	// methods to controller methods ("get,post:Login;delete:Logout").
	beegoMappedRegistrars = map[string]bool{"Router": true, "NSRouter": true}
	// beegoAnnotatedRegistrars route the controller methods whose doc comment carries
	// an @router annotation, and no others.
	beegoAnnotatedRegistrars = map[string]bool{"Include": true, "NSInclude": true, "AddInclude": true}
	// beegoAutoRegistrars route every exported method the controller declares that
	// takes no parameter, by the method's own name.
	beegoAutoRegistrars = map[string]bool{
		"AutoRouter": true, "NSAutoRouter": true, "AddAuto": true,
		"AutoPrefix": true, "NSAutoPrefix": true, "AddAutoPrefix": true,
	}
	// beegoOptionRegistrars take a pattern, a controller and options. With no option
	// they route as a Router call with no mapping does; an option names the routed
	// methods in a value this reads no further, see handlerShaped.
	beegoOptionRegistrars = map[string]bool{"RouterWithOpts": true, "Add": true}
	// beegoFuncRegistrars take a pattern and a handler: a HandleFunc, a filter, an
	// http.Handler, or a controller method expression.
	beegoFuncRegistrars = map[string]bool{
		"Get": true, "Post": true, "Delete": true, "Put": true, "Head": true, "Options": true, "Patch": true, "Any": true,
		"NSGet": true, "NSPost": true, "NSDelete": true, "NSPut": true, "NSHead": true, "NSOptions": true, "NSPatch": true, "NSAny": true,
		"CtrlGet": true, "CtrlPost": true, "CtrlDelete": true, "CtrlPut": true, "CtrlHead": true, "CtrlOptions": true, "CtrlPatch": true, "CtrlAny": true,
		"NSCtrlGet": true, "NSCtrlPost": true, "NSCtrlDelete": true, "NSCtrlPut": true, "NSCtrlHead": true, "NSCtrlOptions": true, "NSCtrlPatch": true, "NSCtrlAny": true,
		"Handler": true, "NSHandler": true, "InsertFilter": true, "NSBefore": true, "NSAfter": true,
	}
	// beegoMethodFirstRegistrars take the HTTP method ahead of the pattern.
	beegoMethodFirstRegistrars = map[string]bool{"AddMethod": true, "AddRouterMethod": true}
	// beegoRESTMethods are the controller methods a route with no mapping dispatches
	// to, by the request's HTTP method.
	beegoRESTMethods = []string{"Get", "Post", "Delete", "Put", "Head", "Patch", "Options", "Trace"}
	// beegoLifecycleMethods are the controller methods beego runs around every request
	// it routes to the controller, whichever method the route names.
	beegoLifecycleMethods = []string{"Prepare", "Finish"}

	restfulPkgPaths = map[string]bool{
		"github.com/emicklei/go-restful":    true,
		"github.com/emicklei/go-restful/v3": true,
	}
	// restfulVerbs are the WebService methods that start a route at a sub-path.
	restfulVerbs = map[string]bool{
		"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true,
	}

	gorillaWebsocketPkgPaths = map[string]bool{"github.com/gorilla/websocket": true}

	grpcPkgPath = "google.golang.org/grpc"
)

// frameworkRoutes returns the routes the call common, made in fn, registers with
// beego, go-restful, gorilla/websocket or gRPC; nil when it registers none.
func (s *ssaProgram) frameworkRoutes(fn *ssa.Function, common *ssa.CallCommon) []route {
	callee := common.StaticCallee()
	if callee == nil || callee.Pkg == nil || callee.Pkg.Pkg == nil {
		return nil
	}
	pkgPath, name := callee.Pkg.Pkg.Path(), callee.Name()
	var recv ssa.Value
	args := common.Args
	if callee.Signature.Recv() != nil && len(args) > 0 {
		recv, args = args[0], args[1:]
	}
	switch {
	case beegoPkgPaths[pkgPath]:
		return s.beegoRoutes(name, args)
	case restfulPkgPaths[pkgPath]:
		return s.restfulRoutes(name, recv, args)
	case gorillaWebsocketPkgPaths[pkgPath]:
		return s.websocketRoutes(fn, name)
	}
	return s.grpcRoutes(callee, args)
}

// beegoRoutes returns the routes one beego registrar call registers: name is the
// called function or method and args its arguments after any receiver. A route's
// selector is the pattern the call carries, without the prefix of a namespace above
// it.
func (s *ssaProgram) beegoRoutes(name string, args []ssa.Value) []route {
	if beegoMethodFirstRegistrars[name] && len(args) > 0 {
		args = args[1:]
		name = "Any"
	}
	selector := ""
	if len(args) > 0 {
		if pattern, ok := constString(args[0]); ok {
			selector = pattern
		}
	}
	var routes []route
	emit := func(ctrl types.Type, fns []*ssa.Function) {
		if len(fns) == 0 {
			return
		}
		for _, fn := range fns {
			routes = append(routes, route{selector: selector, symbol: s.scipFunc(fn)})
		}
		// Prepare and Finish run on every route of the controller, so they carry no
		// one route's pattern.
		for _, fn := range s.declaredMethods(ctrl, beegoPkgPaths, beegoLifecycleMethods) {
			routes = append(routes, route{symbol: s.scipFunc(fn)})
		}
	}
	switch {
	case beegoMappedRegistrars[name]:
		if len(args) < 2 {
			return nil
		}
		ctrl := s.controllerType(args[1], beegoPkgPaths)
		if ctrl == nil {
			return nil
		}
		mapped, known := beegoMappedMethods(args[2:])
		switch {
		case !known:
			emit(ctrl, handlerShaped(s.declaredMethods(ctrl, beegoPkgPaths, nil)))
		case len(mapped) == 0:
			emit(ctrl, s.declaredMethods(ctrl, beegoPkgPaths, beegoRESTMethods))
		default:
			emit(ctrl, s.declaredMethods(ctrl, beegoPkgPaths, mapped))
		}
	case beegoOptionRegistrars[name]:
		if len(args) < 2 {
			return nil
		}
		ctrl := s.controllerType(args[1], beegoPkgPaths)
		if ctrl == nil {
			return nil
		}
		if noVariadic(args[2:]) || onlySessionOptions(args[2:]) {
			emit(ctrl, s.declaredMethods(ctrl, beegoPkgPaths, beegoRESTMethods))
		} else {
			emit(ctrl, handlerShaped(s.declaredMethods(ctrl, beegoPkgPaths, nil)))
		}
	case beegoAnnotatedRegistrars[name], beegoAutoRegistrars[name]:
		for _, a := range flattenVariadic(args) {
			ctrl := s.controllerType(a, beegoPkgPaths)
			if ctrl == nil {
				continue
			}
			methods := s.declaredMethods(ctrl, beegoPkgPaths, nil)
			if beegoAnnotatedRegistrars[name] {
				methods = routerAnnotated(methods)
			} else {
				methods = notNamed(handlerShaped(methods), s.frameworkMethodNames(ctrl, beegoPkgPaths))
			}
			emit(ctrl, methods)
		}
	case beegoFuncRegistrars[name]:
		for _, a := range flattenVariadic(args) {
			if fn := s.boxedHandler(a, beegoPkgPaths); fn != nil {
				routes = append(routes, route{selector: selector, symbol: s.scipFunc(fn)})
			}
		}
	}
	return routes
}

// routerAnnotated keeps the methods whose doc comment has a line starting "@router",
// the annotation beego's Include reads a controller's routes from.
func routerAnnotated(fns []*ssa.Function) []*ssa.Function {
	var out []*ssa.Function
	for _, fn := range fns {
		decl, ok := fn.Syntax().(*ast.FuncDecl)
		if !ok || decl.Doc == nil {
			continue
		}
		for _, c := range decl.Doc.List {
			if strings.HasPrefix(strings.TrimSpace(strings.TrimLeft(c.Text, "/")), "@router") {
				out = append(out, fn)
				break
			}
		}
	}
	return out
}

// handlerShaped keeps the methods beego can dispatch a request to without knowing
// more than the method's name: those with no parameter, since beego calls a routed
// method with no argument and discards what it returns. It stands in where the routed
// methods are named by a value this cannot read (a non-constant mapping, an option)
// or by the method's own name (an auto router), so a controller's helpers that take
// arguments are not taken as routed.
func handlerShaped(fns []*ssa.Function) []*ssa.Function {
	var out []*ssa.Function
	for _, fn := range fns {
		if fn.Signature.Params().Len() == 0 {
			out = append(out, fn)
		}
	}
	return out
}

// notNamed drops the methods whose name is in names. An auto router skips every
// method name the base controller has, so a controller's override of one is not
// routed by it.
func notNamed(fns []*ssa.Function, names map[string]bool) []*ssa.Function {
	var out []*ssa.Function
	for _, fn := range fns {
		if !names[fn.Name()] {
			out = append(out, fn)
		}
	}
	return out
}

// frameworkMethodNames returns the names of the methods t takes from the framework
// types it embeds, directly or through its own embedded types.
func (s *ssaProgram) frameworkMethodNames(t types.Type, framework map[string]bool) map[string]bool {
	names := map[string]bool{}
	seen := map[types.Type]bool{}
	var walk func(types.Type)
	walk = func(t types.Type) {
		if p, ok := t.Underlying().(*types.Pointer); ok {
			t = p.Elem()
		}
		if seen[t] {
			return
		}
		seen[t] = true
		if named, ok := t.(*types.Named); ok && named.Obj().Pkg() != nil && framework[named.Obj().Pkg().Path()] {
			mset := s.prog.MethodSets.MethodSet(types.NewPointer(named))
			for i := 0; i < mset.Len(); i++ {
				names[mset.At(i).Obj().Name()] = true
			}
			return
		}
		st, ok := t.Underlying().(*types.Struct)
		if !ok {
			return
		}
		for i := 0; i < st.NumFields(); i++ {
			if f := st.Field(i); f.Embedded() {
				walk(f.Type())
			}
		}
	}
	walk(t)
	return names
}

// onlySessionOptions reports whether every option a call passed is the result of
// beego's WithRouterSessionOn, which leaves the routed methods at the REST verbs.
func onlySessionOptions(args []ssa.Value) bool {
	vals := flattenVariadic(args)
	for _, v := range vals {
		call, ok := v.(*ssa.Call)
		if !ok {
			return false
		}
		callee := call.Call.StaticCallee()
		if callee == nil || callee.Pkg == nil || callee.Pkg.Pkg == nil ||
			!beegoPkgPaths[callee.Pkg.Pkg.Path()] || callee.Name() != "WithRouterSessionOn" {
			return false
		}
	}
	return len(vals) > 0
}

// beegoMappedMethods reads the controller method names out of a Router call's
// mapping arguments. beego reads the first mapping only: entries separated by ";",
// each "<http methods>:<controller method>". known is false when a mapping is given
// but is no constant, so the routed methods cannot be read.
func beegoMappedMethods(args []ssa.Value) (methods []string, known bool) {
	if noVariadic(args) {
		return nil, true
	}
	mapping, ok := constString(flattenVariadic(args)[0])
	if !ok {
		return nil, false
	}
	for _, entry := range strings.Split(mapping, ";") {
		_, method, found := strings.Cut(entry, ":")
		if method = strings.TrimSpace(method); found && method != "" {
			methods = append(methods, method)
		}
	}
	return methods, true
}

// noVariadic reports whether a call passed nothing for its variadic parameter, which
// SSA spells as no argument or as a nil slice constant.
func noVariadic(args []ssa.Value) bool {
	vals := flattenVariadic(args)
	if len(vals) == 0 {
		return true
	}
	c, ok := vals[0].(*ssa.Const)
	return ok && len(vals) == 1 && c.Value == nil
}

// restfulRoutes returns the routes one go-restful call registers. RouteBuilder.To
// binds a route's function; its selector is the sub-path of the verb (or Path) call
// the builder chain starts from, without the WebService's root path. Filter, on a
// container, a web service or a route, registers a function that runs on the
// requests it covers, and Container.Handle an http.Handler.
func (s *ssaProgram) restfulRoutes(name string, recv ssa.Value, args []ssa.Value) []route {
	if recv == nil || len(args) == 0 {
		return nil
	}
	switch name {
	case "To":
		if fn := staticHandler(args[0]); fn != nil {
			return []route{{selector: restfulSubPath(recv), symbol: s.scipFunc(fn)}}
		}
	case "Filter":
		if fn := staticHandler(args[0]); fn != nil {
			return []route{{symbol: s.scipFunc(fn)}}
		}
	case "Handle", "HandleWithFilter":
		if len(args) < 2 {
			return nil
		}
		if fn := s.boxedHandler(args[1], restfulPkgPaths); fn != nil {
			selector, _ := constString(args[0])
			return []route{{selector: selector, symbol: s.scipFunc(fn)}}
		}
	}
	return nil
}

// restfulSubPath walks a RouteBuilder chain back from v to the call that set the
// route's sub-path, a WebService verb or a Path call with a constant argument; ""
// when the chain does not lead to one.
func restfulSubPath(v ssa.Value) string {
	for {
		call, ok := v.(*ssa.Call)
		if !ok {
			return ""
		}
		callee := call.Call.StaticCallee()
		if callee == nil || callee.Pkg == nil || !restfulPkgPaths[callee.Pkg.Pkg.Path()] ||
			callee.Signature.Recv() == nil || len(call.Call.Args) == 0 {
			return ""
		}
		if (restfulVerbs[callee.Name()] || callee.Name() == "Path") && len(call.Call.Args) > 1 {
			if p, ok := constString(call.Call.Args[1]); ok {
				return p
			}
		}
		v = call.Call.Args[0]
	}
}

// websocketRoutes makes the function that upgrades a request to a websocket an
// ingress: whatever its shape, it is handed the inbound request and reads what the
// peer sends on the connection it gets back. The package's own callers of Upgrade
// are none.
func (s *ssaProgram) websocketRoutes(fn *ssa.Function, name string) []route {
	if name != "Upgrade" || fn == nil {
		return nil
	}
	if fn.Pkg != nil && fn.Pkg.Pkg != nil && gorillaWebsocketPkgPaths[fn.Pkg.Pkg.Path()] {
		return nil
	}
	return []route{{kind: "handler", symbol: s.scipFunc(fn)}}
}

// grpcRoutes returns the handlers a generated Register<Service>Server call registers:
// the methods of the service interface, on the concrete value passed as the
// implementation. The registrar is recognized by its shape — a function named
// Register…Server taking a grpc registrar and a service interface — so it needs no
// list of services. The methods the implementation only inherits from the generated
// package (the embedded Unimplemented…Server) are none: they answer Unimplemented.
// A route's selector is "<Service>/<Method>".
func (s *ssaProgram) grpcRoutes(callee *ssa.Function, args []ssa.Value) []route {
	name := callee.Name()
	if !strings.HasPrefix(name, "Register") || !strings.HasSuffix(name, "Server") {
		return nil
	}
	params := callee.Signature.Params()
	if callee.Signature.Recv() != nil || params.Len() != 2 || len(args) != 2 {
		return nil
	}
	registrar := params.At(0).Type()
	if !isNamed(registrar, grpcPkgPath, "ServiceRegistrar") && !isPointerToNamed(registrar, grpcPkgPath, "Server") {
		return nil
	}
	service, ok := params.At(1).Type().(*types.Named)
	if !ok {
		return nil
	}
	iface, ok := service.Underlying().(*types.Interface)
	if !ok {
		return nil
	}
	mi, ok := args[1].(*ssa.MakeInterface)
	if !ok || types.IsInterface(mi.X.Type()) {
		return nil
	}
	generated := map[string]bool{callee.Pkg.Pkg.Path(): true}
	serviceName := strings.TrimSuffix(service.Obj().Name(), "Server")
	var routes []route
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if !m.Exported() {
			continue
		}
		for _, fn := range s.declaredMethods(mi.X.Type(), generated, []string{m.Name()}) {
			routes = append(routes, route{kind: "grpc", selector: serviceName + "/" + m.Name(), symbol: s.scipFunc(fn)})
		}
	}
	return routes
}

// controllerType returns the concrete type of a controller value boxed into an
// interface argument, a named type or a pointer to one declared outside framework;
// nil when v is not such a value.
func (s *ssaProgram) controllerType(v ssa.Value, framework map[string]bool) types.Type {
	mi, ok := v.(*ssa.MakeInterface)
	if !ok {
		return nil
	}
	t := mi.X.Type()
	if pkg := namedTypePkg(t); pkg == nil || framework[pkg.Path()] {
		return nil
	}
	return t
}

// declaredMethods returns the exported methods in t's method set that are declared
// outside framework, so a method the type only inherits from the framework's base
// type is none. names limits the result to methods of those names; nil takes all.
func (s *ssaProgram) declaredMethods(t types.Type, framework map[string]bool, names []string) []*ssa.Function {
	mset := s.prog.MethodSets.MethodSet(t)
	var out []*ssa.Function
	take := func(sel *types.Selection) {
		if sel == nil || !token.IsExported(sel.Obj().Name()) {
			return
		}
		if pkg := sel.Obj().Pkg(); pkg == nil || framework[pkg.Path()] {
			return
		}
		if fn := s.prog.MethodValue(sel); fn != nil {
			out = append(out, fn)
		}
	}
	if names == nil {
		for i := 0; i < mset.Len(); i++ {
			take(mset.At(i))
		}
		return out
	}
	for _, name := range names {
		take(mset.Lookup(nil, name))
	}
	return out
}

// boxedHandler resolves a handler argument: a function reference (staticHandler),
// itself or boxed into an interface (a controller method expression), or a concrete
// value boxed into an http.Handler, which contributes its ServeHTTP method unless its
// type is net/http's or the framework's own.
func (s *ssaProgram) boxedHandler(v ssa.Value, framework map[string]bool) *ssa.Function {
	if fn := staticHandler(v); fn != nil {
		return fn
	}
	mi, ok := v.(*ssa.MakeInterface)
	if !ok {
		return nil
	}
	if fn := staticHandler(mi.X); fn != nil {
		return fn
	}
	t := mi.X.Type()
	if pkg := namedTypePkg(t); pkg == nil || pkg.Path() == "net/http" || framework[pkg.Path()] {
		return nil
	}
	sel := s.prog.MethodSets.MethodSet(t).Lookup(nil, "ServeHTTP")
	if sel == nil {
		return nil
	}
	return s.prog.MethodValue(sel)
}

// flattenVariadic returns args with each variadic slice replaced by the values the
// call packed into it.
func flattenVariadic(args []ssa.Value) []ssa.Value {
	var out []ssa.Value
	for _, a := range args {
		if sl, ok := a.(*ssa.Slice); ok {
			out = append(out, variadicSliceValues(sl)...)
			continue
		}
		out = append(out, a)
	}
	return out
}
