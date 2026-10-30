// Command ginmod exercises gin ingress detection. Every gin registration form — the
// verb methods, Any, Handle, Match, a route's handler chain, handlers registered on a
// Group's *RouterGroup and through the IRoutes interface, and net/http handlers
// adapted by WrapF / WrapH — registers a handler that hands attacker-controlled
// request data (a *gin.Context accessor, or a field of its *http.Request) to its OWN
// sink, so a test can prove per form that the handler is an http_route ingress AND
// heads the taint trace to that form's sink.
//
// gin handlers are func(*gin.Context), a shape no signature rule lists, so the gin
// registration is the only thing that makes them ingresses. (The http types here are
// tegron.test/nethttp's stand-ins; see nethttpstub/http.go.)
//
// The negatives sit in the same module: a handler-shaped method and a package-scope
// func never registered, Use and Group middleware, gin's own Engine.ServeHTTP and
// HandlerFunc adapter reached through WrapH, and handlers registered on a look-alike
// router (same package name, type and method names as gin, different import path).
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

// Negative sinks: no taint reaches these. ctxStoreForm, a registered handler, hands
// sinkCtxStore only a value the application stored on the context; no gin-registered
// handler calls the others.
func sinkCtxStore(v string)        { sunk = append(sunk, v) }
func sinkNeverRegistered(v string) { sunk = append(sunk, v) }
func sinkMiddleware(v string)      { sunk = append(sunk, v) }
func sinkLookalike(v string)       { sunk = append(sunk, v) }

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

// netForm is a net/http handler adapted by gin.WrapF: it, not gin's wrapper closure,
// is the ingress.
func (s *server) netForm(w http.ResponseWriter, r *http.Request) { sinkWrapF(r.URL.Path) }

// wrappedHandler is a net/http Handler adapted by gin.WrapH: its ServeHTTP is the
// ingress.
type wrappedHandler struct{}

func (h *wrappedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { sinkWrapH(r.URL.Path) }

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

// recovery is handed to gin.CustomRecovery, a one-argument gin function that is no
// net/http adapter (WrapF / WrapH): it handles panics, and is no route ingress.
func recovery(c *gin.Context, err any) { sinkMiddleware(c.Query("r")) }

// ctxStoreForm is a route handler, but GetString reads what the application stored on
// the context, no request data: no taint reaches sinkCtxStore.
func (s *server) ctxStoreForm(c *gin.Context) { sinkCtxStore(c.GetString("user")) }

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

// registerAPI registers through the gin.IRouter interface (an invoke call).
func registerAPI(g gin.IRouter, s *server) {
	g.POST("/iroutes", s.iroutesForm)
}

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

	r.GET("/wrapf", gin.WrapF(s.netForm))
	r.GET("/wraph", gin.WrapH(&wrappedHandler{}))
	// gin's own Engine.ServeHTTP mounted through WrapH is no ingress.
	r.Any("/engine/*path", gin.WrapH(gin.New()))
	r.GET("/rec", gin.CustomRecovery(recovery))
	r.GET("/ctx-store", s.ctxStoreForm)
	(&fwdRouter{r: r}).Get("/fwd", s.neverRegistered)

	fake := lookalike.New()
	fake.GET("/fake", s.lookalikeGet)
	fake.POST("/fake", s.lookalikePost)
	fake.Handle("GET", "/fake-handle", s.lookalikeHandle)
	fake.Match([]string{"GET"}, "/fake-match", s.lookalikeMatch)
	fake.Group("/fake-group").GET("/:id", s.lookalikeGroup)
	r.GET("/fake-wrap", lookalike.WrapF(s.lookalikeNet))
}
