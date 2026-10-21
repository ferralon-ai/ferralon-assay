// Command echomod exercises echo ingress detection, the third framework on the shared
// pathRouter table. Every echo registration form — the verb methods, Any, Add, Match,
// handlers registered on a Group (nested, and in a helper) and on a route that also
// carries route middleware, and net/http handlers adapted by WrapHandler — registers
// a handler that hands attacker-controlled request data (an echo.Context accessor) to
// its OWN sink, so a test can prove per form that the handler is an http_route
// ingress under its full composed pattern AND heads the taint trace to that form's
// sink. accessorsForm does the same for every modeled echo.Context accessor.
//
// echo handlers are func(echo.Context) error, where echo.Context is an interface, a
// shape no signature rule lists, so the echo registration is the only thing that
// makes them ingresses. (The http types here are tegron.test/nethttp's stand-ins; see
// nethttpstub/http.go.)
//
// The negatives sit in the same module: a handler-shaped method and a package-scope
// func never registered, Pre, Use, Group and route middleware (and the handler
// closures they return), net/http middleware adapted by WrapMiddleware, echo's own
// Echo.ServeHTTP and the HandlerFunc adapter reached through WrapHandler, and
// handlers registered on a look-alike router (same package name, type and method
// names as echo, different import path).
package main

import (
	"github.com/labstack/echo/v4"
	http "tegron.test/nethttp"

	lookalike "tegron.test/echomod/lookalike"
)

// sunk keeps the sinks' arguments live.
var sunk []any

// One sink per registration form, so each form's taint path is distinguishable.
func sinkGet(v any)        { sunk = append(sunk, v) }
func sinkPost(v any)       { sunk = append(sunk, v) }
func sinkPut(v any)        { sunk = append(sunk, v) }
func sinkPatch(v any)      { sunk = append(sunk, v) }
func sinkDelete(v any)     { sunk = append(sunk, v) }
func sinkHead(v any)       { sunk = append(sunk, v) }
func sinkOptions(v any)    { sunk = append(sunk, v) }
func sinkConnect(v any)    { sunk = append(sunk, v) }
func sinkTrace(v any)      { sunk = append(sunk, v) }
func sinkAny(v any)        { sunk = append(sunk, v) }
func sinkAdd(v any)        { sunk = append(sunk, v) }
func sinkMatch(v any)      { sunk = append(sunk, v) }
func sinkRouteMW(v any)    { sunk = append(sunk, v) }
func sinkGroup(v any)      { sunk = append(sunk, v) }
func sinkNested(v any)     { sunk = append(sunk, v) }
func sinkGroupAdd(v any)   { sunk = append(sunk, v) }
func sinkGroupMatch(v any) { sunk = append(sunk, v) }
func sinkHelper(v any)     { sunk = append(sunk, v) }
func sinkDynamic(v any)    { sunk = append(sunk, v) }
func sinkWrapH(v any)      { sunk = append(sunk, v) }
func sinkWrapF(v any)      { sunk = append(sunk, v) }

// One sink per modeled echo.Context accessor, reached from accessorsForm.
func sinkParam(v any)       { sunk = append(sunk, v) }
func sinkQueryParam(v any)  { sunk = append(sunk, v) }
func sinkQueryParams(v any) { sunk = append(sunk, v) }
func sinkFormValue(v any)   { sunk = append(sunk, v) }
func sinkFormParams(v any)  { sunk = append(sunk, v) }
func sinkRequest(v any)     { sunk = append(sunk, v) }
func sinkCookie(v any)      { sunk = append(sunk, v) }
func sinkBind(v any)        { sunk = append(sunk, v) }

// Negative sinks: no echo-registered handler reaches these.
func sinkNotRequestData(v any)  { sunk = append(sunk, v) }
func sinkNeverRegistered(v any) { sunk = append(sunk, v) }
func sinkMiddleware(v any)      { sunk = append(sunk, v) }
func sinkLookalike(v any)       { sunk = append(sunk, v) }

type server struct{}

func (s *server) getForm(c echo.Context) error     { sinkGet(c.Param("id")); return nil }
func (s *server) postForm(c echo.Context) error    { sinkPost(c.FormValue("name")); return nil }
func (s *server) putForm(c echo.Context) error     { sinkPut(c.QueryParam("q")); return nil }
func (s *server) patchForm(c echo.Context) error   { sinkPatch(c.Request().URL.Path); return nil }
func (s *server) deleteForm(c echo.Context) error  { sinkDelete(c.Param("id")); return nil }
func (s *server) headForm(c echo.Context) error    { sinkHead(c.Param("id")); return nil }
func (s *server) optionsForm(c echo.Context) error { sinkOptions(c.Param("id")); return nil }
func (s *server) connectForm(c echo.Context) error { sinkConnect(c.Param("id")); return nil }
func (s *server) traceForm(c echo.Context) error   { sinkTrace(c.Param("id")); return nil }
func (s *server) anyForm(c echo.Context) error     { sinkAny(c.Request().Method); return nil }
func (s *server) addForm(c echo.Context) error     { sinkAdd(c.Param("id")); return nil }
func (s *server) matchForm(c echo.Context) error   { sinkMatch(c.QueryParam("q")); return nil }
func (s *server) routeMWForm(c echo.Context) error { sinkRouteMW(c.Param("id")); return nil }
func (s *server) nestedForm(c echo.Context) error  { sinkNested(c.Param("id")); return nil }
func (s *server) groupAddForm(c echo.Context) error {
	sinkGroupAdd(c.Param("id"))
	return nil
}
func (s *server) groupMatchForm(c echo.Context) error {
	sinkGroupMatch(c.Param("id"))
	return nil
}
func (s *server) helperForm(c echo.Context) error  { sinkHelper(c.FormValue("v")); return nil }
func (s *server) dynamicForm(c echo.Context) error { sinkDynamic(c.Param("id")); return nil }

func (s *server) accessorsForm(c echo.Context) error {
	sinkParam(c.Param("id"))
	sinkQueryParam(c.QueryParam("q"))
	sinkQueryParams(c.QueryParams())
	sinkFormValue(c.FormValue("f"))
	fp, _ := c.FormParams()
	sinkFormParams(fp)
	sinkRequest(c.Request().URL.RawQuery)
	ck, _ := c.Cookie("session")
	sinkCookie(ck.Value)
	var in struct{ User string }
	_ = c.Bind(&in)
	sinkBind(in.User)
	sinkNotRequestData(c.Path())
	return nil
}

// netForm is a net/http handler adapted by WrapHandler through an http.HandlerFunc
// conversion: it, not echo's wrapper closure, is the ingress.
func (s *server) netForm(w http.ResponseWriter, r *http.Request) { sinkWrapF(r.URL.Path) }

// wrappedHandler is a net/http Handler adapted by WrapHandler: its ServeHTTP is the
// ingress.
type wrappedHandler struct{}

func (h *wrappedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { sinkWrapH(r.URL.Path) }

// neverRegistered is handler-shaped but registered on no echo router directly (only
// through fwdRouter's forwarding, which the detector does not follow): no ingress.
func (s *server) neverRegistered(w http.ResponseWriter, r *http.Request) {
	sinkNeverRegistered(r.URL.Path)
}

// unregisteredFunc is a package-scope echo-handler-shaped func registered on no router.
func unregisteredFunc(c echo.Context) error { sinkNeverRegistered(c.Param("id")); return nil }

// Middleware runs for every route under it and is no route ingress: neither the
// middleware func nor the handler closure it returns.
func preMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error { sinkMiddleware(c.QueryParam("pre")); return next(c) }
}
func useMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error { sinkMiddleware(c.QueryParam("use")); return next(c) }
}
func groupMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error { sinkMiddleware(c.QueryParam("group")); return next(c) }
}
func routeMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error { sinkMiddleware(c.QueryParam("route")); return next(c) }
}

// netMiddleware is net/http middleware, adapted by WrapMiddleware: no ingress.
func netMiddleware(next http.Handler) http.Handler { return next }

// Handlers registered only on (or wrapped only by) the look-alike: no ingress.
func (s *server) lookalikeGet(c echo.Context) error   { sinkLookalike(c.Param("id")); return nil }
func (s *server) lookalikePost(c echo.Context) error  { sinkLookalike(c.Param("id")); return nil }
func (s *server) lookalikeAdd(c echo.Context) error   { sinkLookalike(c.Param("id")); return nil }
func (s *server) lookalikeGroup(c echo.Context) error { sinkLookalike(c.Param("id")); return nil }
func (s *server) lookalikeNet(w http.ResponseWriter, r *http.Request) {
	sinkLookalike(r.URL.Path)
}

// fwdRouter is a first-party wrapper that forwards to echo with a non-constant path,
// so the handler reaches WrapHandler boxed as an http.HandlerFunc in a variable: the
// adapter's ServeHTTP must not become an ingress.
type fwdRouter struct{ e *echo.Echo }

func (f *fwdRouter) Get(p string, h http.HandlerFunc) { f.e.GET(p, echo.WrapHandler(h)) }

// registerV2 registers on the group its one caller passes: the route is composed
// under that group's prefix.
func registerV2(g *echo.Group, s *server) {
	g.POST("/items", s.helperForm)
}

// prefixFromConfig stands in for a prefix read at run time: no constant.
func prefixFromConfig() string { return "" }

func main() {
	s := &server{}

	e := echo.New()
	e.Pre(preMiddleware)
	e.Use(useMiddleware, echo.WrapMiddleware(netMiddleware))
	e.GET("/get/:id", s.getForm)
	e.POST("/post", s.postForm)
	e.PUT("/put", s.putForm)
	e.PATCH("/patch", s.patchForm)
	e.DELETE("/delete/:id", s.deleteForm)
	e.HEAD("/head", s.headForm)
	e.OPTIONS("/options", s.optionsForm)
	e.CONNECT("/connect", s.connectForm)
	e.TRACE("/trace", s.traceForm)
	e.Any("/any", s.anyForm)
	e.Add("GET", "/add/:id", s.addForm)
	e.Match([]string{"GET", "POST"}, "/match", s.matchForm)
	e.GET("/mw/:id", s.routeMWForm, routeMiddleware, echo.WrapMiddleware(netMiddleware))
	e.POST("/accessors", s.accessorsForm)

	api := e.Group("/api", groupMiddleware)
	api.Use(groupMiddleware)
	api.GET("/users/:id", func(c echo.Context) error {
		sinkGroup(c.Param("id"))
		return nil
	})
	api.Group("/admin").DELETE("/:id", s.nestedForm)
	api.Add("PUT", "/add/:id", s.groupAddForm)
	api.Match([]string{"GET"}, "/match/:id", s.groupMatchForm)
	registerV2(e.Group("/v2"), s)
	// A group whose prefix is no constant, under /api: its route keeps its local
	// pattern, neither guessing the prefix nor skipping it to /api/dynamic/:id.
	api.Group(prefixFromConfig()).GET("/dynamic/:id", s.dynamicForm)

	e.GET("/wraph", echo.WrapHandler(&wrappedHandler{}))
	e.GET("/wrapf", echo.WrapHandler(http.HandlerFunc(s.netForm)))
	// echo's own Echo.ServeHTTP mounted through WrapHandler is no ingress.
	e.Any("/echo/*", echo.WrapHandler(echo.New()))
	(&fwdRouter{e: e}).Get("/fwd", s.neverRegistered)

	fake := lookalike.New()
	fake.GET("/fake", s.lookalikeGet)
	fake.POST("/fake", s.lookalikePost)
	fake.Add("GET", "/fake-add", s.lookalikeAdd)
	fake.Group("/fake-group").GET("/:id", s.lookalikeGroup)
	e.GET("/fake-wrap", lookalike.WrapHandler(http.HandlerFunc(s.lookalikeNet)))
}
