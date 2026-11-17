package goanalysis

import (
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
	// beegoControllerRegistrars route a controller's methods by a rule outside the
	// call: a comment annotation (Include), the method's own name (AutoRouter), or an
	// option value (RouterWithOpts, Add). Every exported method the controller
	// declares is taken as routed.
	beegoControllerRegistrars = map[string]bool{
		"Include": true, "NSInclude": true, "AddInclude": true,
		"AutoRouter": true, "NSAutoRouter": true, "AddAuto": true,
		"AutoPrefix": true, "NSAutoPrefix": true, "AddAutoPrefix": true,
		"RouterWithOpts": true, "Add": true,
	}
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
	emit := func(fns []*ssa.Function) {
		for _, fn := range fns {
			routes = append(routes, route{selector: selector, symbol: s.scipFunc(fn)})
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
			emit(s.declaredMethods(ctrl, beegoPkgPaths, nil))
		case len(mapped) == 0:
			emit(s.declaredMethods(ctrl, beegoPkgPaths, beegoRESTMethods))
		default:
			emit(s.declaredMethods(ctrl, beegoPkgPaths, mapped))
		}
	case beegoControllerRegistrars[name]:
		for _, a := range flattenVariadic(args) {
			if ctrl := s.controllerType(a, beegoPkgPaths); ctrl != nil {
				emit(s.declaredMethods(ctrl, beegoPkgPaths, nil))
			}
		}
	case beegoFuncRegistrars[name]:
		for _, a := range flattenVariadic(args) {
			if fn := s.boxedHandler(a, beegoPkgPaths); fn != nil {
				emit([]*ssa.Function{fn})
			}
		}
	}
	return routes
}

// beegoMappedMethods reads the controller method names out of a Router call's
// mapping arguments. beego reads the first mapping only: entries separated by ";",
// each "<http methods>:<controller method>". known is false when a mapping is given
// but is no constant, so the routed methods cannot be read.
func beegoMappedMethods(args []ssa.Value) (methods []string, known bool) {
	vals := flattenVariadic(args)
	if len(vals) == 0 {
		return nil, true
	}
	mapping, ok := constString(vals[0])
	if !ok {
		// An empty variadic is a nil slice constant: no mapping was given.
		if c, isConst := vals[0].(*ssa.Const); isConst && c.Value == nil {
			return nil, true
		}
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
