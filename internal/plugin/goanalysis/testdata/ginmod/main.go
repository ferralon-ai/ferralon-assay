// Command ginmod exercises gin ingress detection. Every gin registration form — the
// verb methods, Any, Handle, Match, a route's handler chain, handlers registered on a
// Group's *RouterGroup (nested, and through the IRoutes interface in a helper),
// NoRoute and NoMethod, and net/http handlers adapted by WrapF / WrapH — registers a
// handler that hands attacker-controlled request data (a *gin.Context accessor, or a
// field of its *http.Request) to its OWN sink, so a test can prove per form that the
// handler is an http_route ingress under its full composed pattern AND heads the
// taint trace to that form's sink. accessors.go does the same for every modeled
// *gin.Context accessor and binder.
//
// gin handlers are func(*gin.Context), a shape no signature rule lists, so the gin
// registration is the only thing that makes them ingresses. (The http types here are
// tegron.test/nethttp's stand-ins; see nethttpstub/http.go.)
//
// The negatives sit in the same module: a handler-shaped method and a package-scope
// func never registered, Use and Group middleware, a file system served by StaticFS,
// gin's own Engine.ServeHTTP and HandlerFunc adapter reached through WrapH, and
// handlers registered on a look-alike router (same package name, type and method
// names as gin, different import path).
package main

import (
	"github.com/gin-gonic/gin"
	http "tegron.test/nethttp"

	lookalike "tegron.test/ginmod/lookalike"
)

// sunk keeps the sinks' arguments live.
var sunk []string

// One sink per registration form, so each form's taint path is distinguishable.
func sinkGet(v string)       { sunk = append(sunk, v) }
func sinkPost(v string)      { sunk = append(sunk, v) }
func sinkPut(v string)       { sunk = append(sunk, v) }
func sinkPatch(v string)     { sunk = append(sunk, v) }
func sinkDelete(v string)    { sunk = append(sunk, v) }
func sinkHead(v string)      { sunk = append(sunk, v) }
func sinkOptions(v string)   { sunk = append(sunk, v) }
func sinkAny(v string)       { sunk = append(sunk, v) }
func sinkHandle(v string)    { sunk = append(sunk, v) }
func sinkMatch(v string)     { sunk = append(sunk, v) }
func sinkChainAuth(v string) { sunk = append(sunk, v) }
func sinkChain(v string)     { sunk = append(sunk, v) }
func sinkGroup(v string)     { sunk = append(sunk, v) }
func sinkNested(v string)    { sunk = append(sunk, v) }
func sinkIRoutes(v string)   { sunk = append(sunk, v) }
func sinkWrapF(v string)     { sunk = append(sunk, v) }
func sinkWrapH(v string)     { sunk = append(sunk, v) }
func sinkNoRoute(v string)   { sunk = append(sunk, v) }
func sinkNoMethod(v string)  { sunk = append(sunk, v) }
func sinkTwice(v string)     { sunk = append(sunk, v) }
func sinkDynamic(v string)   { sunk = append(sunk, v) }

// Negative sinks: no gin-registered handler reaches these.
func sinkNeverRegistered(v string) { sunk = append(sunk, v) }
func sinkMiddleware(v string)      { sunk = append(sunk, v) }
func sinkLookalike(v string)       { sunk = append(sunk, v) }
func sinkStatic(v string)          { sunk = append(sunk, v) }

type server struct{}

func (s *server) getForm(c *gin.Context)     { sinkGet(c.Param("id")) }
func (s *server) postForm(c *gin.Context)    { sinkPost(c.PostForm("name")) }
func (s *server) putForm(c *gin.Context)     { sinkPut(c.Query("q")) }
func (s *server) patchForm(c *gin.Context)   { sinkPatch(c.Request.URL.Path) }
func (s *server) deleteForm(c *gin.Context)  { sinkDelete(c.Param("id")) }
func (s *server) headForm(c *gin.Context)    { sinkHead(c.Param("id")) }
func (s *server) optionsForm(c *gin.Context) { sinkOptions(c.Param("id")) }
func (s *server) anyForm(c *gin.Context)     { sinkAny(c.Request.Method) }
func (s *server) handleForm(c *gin.Context)  { sinkHandle(c.Param("id")) }
func (s *server) matchForm(c *gin.Context)   { sinkMatch(c.Query("q")) }
func (s *server) chainAuth(c *gin.Context)   { sinkChainAuth(c.Query("token")) }
func (s *server) chainForm(c *gin.Context)   { sinkChain(c.Param("id")) }
func (s *server) nestedForm(c *gin.Context)  { sinkNested(c.Param("id")) }
func (s *server) iroutesForm(c *gin.Context) { sinkIRoutes(c.PostForm("v")) }
func (s *server) noRouteForm(c *gin.Context) { sinkNoRoute(c.Request.URL.Path) }
func (s *server) noMethodForm(c *gin.Context) {
	sinkNoMethod(c.Request.Method)
}
func (s *server) twiceForm(c *gin.Context)   { sinkTwice(c.Param("id")) }
func (s *server) dynamicForm(c *gin.Context) { sinkDynamic(c.Param("id")) }

// netForm is a net/http handler adapted by gin.WrapF: it, not gin's wrapper closure,
// is the ingress.
func (s *server) netForm(w http.ResponseWriter, r *http.Request) { sinkWrapF(r.URL.Path) }

// wrappedHandler is a net/http Handler adapted by gin.WrapH: its ServeHTTP is the
// ingress.
type wrappedHandler struct{}

func (h *wrappedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { sinkWrapH(r.URL.Path) }

// assetFS is a file system served by StaticFS. It is handler-shaped as well, so were
// StaticFS a registrar its ServeHTTP would surface: Static* serve files and take no
// first-party handler, so it must not.
type assetFS struct{}

func (a *assetFS) Open(name string) (http.File, error) { return nil, nil }
func (a *assetFS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sinkStatic(r.URL.Path)
}

// neverRegistered is handler-shaped but registered on no gin router directly (only
// through fwdRouter's forwarding, which the detector does not follow): no ingress.
func (s *server) neverRegistered(w http.ResponseWriter, r *http.Request) {
	sinkNeverRegistered(r.URL.Path)
}

// unregisteredFunc is a package-scope gin-handler-shaped func registered on no router.
func unregisteredFunc(c *gin.Context) { sinkNeverRegistered(c.Param("id")) }

// useMiddleware and groupMiddleware run for every route of the engine or group, and
// are no route ingress.
func useMiddleware(c *gin.Context)   { sinkMiddleware(c.Query("trace")) }
func groupMiddleware(c *gin.Context) { sinkMiddleware(c.Query("auth")) }

// Handlers registered only on (or wrapped only by) the look-alike: no ingress.
func (s *server) lookalikeGet(c *gin.Context)    { sinkLookalike(c.Param("id")) }
func (s *server) lookalikePost(c *gin.Context)   { sinkLookalike(c.Param("id")) }
func (s *server) lookalikeHandle(c *gin.Context) { sinkLookalike(c.Param("id")) }
func (s *server) lookalikeMatch(c *gin.Context)  { sinkLookalike(c.Param("id")) }
func (s *server) lookalikeGroup(c *gin.Context)  { sinkLookalike(c.Param("id")) }
func (s *server) lookalikeNet(w http.ResponseWriter, r *http.Request) {
	sinkLookalike(r.URL.Path)
}

// fwdRouter is a first-party wrapper that forwards to gin with a non-constant pattern,
// so the handler reaches gin.WrapH boxed as an http.HandlerFunc in a variable: the
// adapter's ServeHTTP must not become an ingress.
type fwdRouter struct{ r gin.IRouter }

func (f *fwdRouter) Get(p string, h http.HandlerFunc) { f.r.GET(p, gin.WrapH(h)) }

// registerAPI registers through the gin.IRouter interface (an invoke call), on the
// group its one caller passes: the route is composed under that group's prefix.
func registerAPI(g gin.IRouter, s *server) {
	g.POST("/iroutes", s.iroutesForm)
}

// registerTwice is called with two groups: its route is registered under each prefix.
func registerTwice(g gin.IRoutes, s *server) {
	g.GET("/twice/:id", s.twiceForm)
}

// prefixFromConfig stands in for a prefix read at run time: no constant.
func prefixFromConfig() string { return sunk[0] }

func main() {
	s := &server{}

	r := gin.New()
	r.Use(useMiddleware)
	r.GET("/get/:id", s.getForm)
	r.POST("/post", s.postForm)
	r.PUT("/put", s.putForm)
	r.PATCH("/patch", s.patchForm)
	r.DELETE("/delete/:id", s.deleteForm)
	r.HEAD("/head", s.headForm)
	r.OPTIONS("/options", s.optionsForm)
	r.Any("/any", s.anyForm)
	r.Handle("GET", "/x", s.handleForm)
	r.Match([]string{"GET", "POST"}, "/y", s.matchForm)
	r.GET("/chain/:id", s.chainAuth, s.chainForm)

	v1 := r.Group("/v1", groupMiddleware)
	v1.GET("/users/:id", func(c *gin.Context) {
		sinkGroup(c.Param("id"))
	})
	v1.Group("/admin").DELETE("/:id", s.nestedForm)
	registerAPI(r.Group("/api"), s)
	registerTwice(r.Group("/a"), s)
	registerTwice(v1.Group("/b"), s)
	// A group whose prefix is no constant, under /v1: its route keeps its local
	// pattern, neither guessing the prefix nor skipping it to /v1/dynamic/:id.
	v1.Group(prefixFromConfig()).GET("/dynamic/:id", s.dynamicForm)

	r.NoRoute(s.noRouteForm)
	r.NoMethod(s.noMethodForm)
	r.Static("/assets", "./public")
	r.StaticFile("/favicon.ico", "./favicon.ico")
	r.StaticFS("/fs", &assetFS{})

	r.GET("/wrapf", gin.WrapF(s.netForm))
	r.GET("/wraph", gin.WrapH(&wrappedHandler{}))
	// gin's own Engine.ServeHTTP mounted through WrapH is no ingress.
	r.Any("/engine/*path", gin.WrapH(gin.New()))
	(&fwdRouter{r: r}).Get("/fwd", s.neverRegistered)

	fake := lookalike.New()
	fake.GET("/fake", s.lookalikeGet)
	fake.POST("/fake", s.lookalikePost)
	fake.Handle("GET", "/fake-handle", s.lookalikeHandle)
	fake.Match([]string{"GET"}, "/fake-match", s.lookalikeMatch)
	fake.Group("/fake-group").GET("/:id", s.lookalikeGroup)
	r.GET("/fake-wrap", lookalike.WrapF(s.lookalikeNet))
}
