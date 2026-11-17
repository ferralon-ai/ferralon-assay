// Command frameworkmod exercises ingress detection for the frameworks whose handler
// is not an argument beside a route pattern: beego controllers and filters,
// go-restful route builders, gorilla/websocket upgrades and gRPC service
// registrations. Every registration form registers a handler that hands
// attacker-controlled request data to its OWN sink, so a test can prove per form that
// the handler is an ingress of the right kind AND heads the taint trace to that
// form's sink.
//
// The negatives sit in the same module: controller methods no mapping names, methods
// a controller or service only inherits from the framework, a controller and a
// handler never registered, and handlers registered on look-alike registrars (the
// frameworks' names and shapes under another import path).
package main

import (
	"context"

	http "tegron.test/nethttp"

	"github.com/beego/beego/v2/server/web"
	beecontext "github.com/beego/beego/v2/server/web/context"
	restful "github.com/emicklei/go-restful/v3"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc"

	"tegron.test/frameworkmod/lookalike"
	"tegron.test/frameworkmod/pb"
)

// sunk keeps the sinks' arguments live.
var sunk []string

// One sink per registration form, so each form's taint path is distinguishable.
func sinkBeegoMapped(v string)     { sunk = append(sunk, v) }
func sinkBeegoMulti(v string)      { sunk = append(sunk, v) }
func sinkBeegoLogout(v string)     { sunk = append(sunk, v) }
func sinkBeegoREST(v string)       { sunk = append(sunk, v) }
func sinkBeegoDyn(v string)        { sunk = append(sunk, v) }
func sinkBeegoInclude(v string)    { sunk = append(sunk, v) }
func sinkBeegoAuto(v string)       { sunk = append(sunk, v) }
func sinkBeegoAdd(v string)        { sunk = append(sunk, v) }
func sinkBeegoOpts(v string)       { sunk = append(sunk, v) }
func sinkBeegoPrepare(v string)    { sunk = append(sunk, v) }
func sinkBeegoNSRouter(v string)   { sunk = append(sunk, v) }
func sinkBeegoNSInclude(v string)  { sunk = append(sunk, v) }
func sinkBeegoNSMethod(v string)   { sunk = append(sunk, v) }
func sinkBeegoServer(v string)     { sunk = append(sunk, v) }
func sinkBeegoFunc(v string)       { sunk = append(sunk, v) }
func sinkBeegoNSGet(v string)      { sunk = append(sunk, v) }
func sinkBeegoCtrl(v string)       { sunk = append(sunk, v) }
func sinkBeegoAddMethod(v string)  { sunk = append(sunk, v) }
func sinkBeegoFilter(v string)     { sunk = append(sunk, v) }
func sinkBeegoNSBefore(v string)   { sunk = append(sunk, v) }
func sinkBeegoHandler(v string)    { sunk = append(sunk, v) }
func sinkRestGet(v string)         { sunk = append(sunk, v) }
func sinkRestMethod(v string)      { sunk = append(sunk, v) }
func sinkRestFilter(v string)      { sunk = append(sunk, v) }
func sinkRestRouteFilter(v string) { sunk = append(sunk, v) }
func sinkRestContainer(v string)   { sunk = append(sunk, v) }
func sinkRestHandle(v string)      { sunk = append(sunk, v) }
func sinkWS(v string)              { sunk = append(sunk, v) }
func sinkWSLegacy(v string)        { sunk = append(sunk, v) }
func sinkGRPC(v string)            { sunk = append(sunk, v) }
func sinkGRPCLegacy(v string)      { sunk = append(sunk, v) }

// Negative sinks: no registered handler reaches these.
func sinkNeverRegistered(v string) { sunk = append(sunk, v) }
func sinkLookalike(v string)       { sunk = append(sunk, v) }

// --- beego ---

type AuthController struct{ web.Controller }

func (c *AuthController) Login()     { sinkBeegoMapped(c.Ctx.Input.Query("u")) }
func (c *AuthController) NotMapped() { sinkNeverRegistered(c.Ctx.Input.Query("u")) }

// Prepare runs ahead of every request routed to the controller.
func (c *AuthController) Prepare() { sinkBeegoPrepare(c.Ctx.Input.Query("u")) }

type MultiController struct{ web.Controller }

func (c *MultiController) Multi()  { sinkBeegoMulti(c.Ctx.Input.Query("u")) }
func (c *MultiController) Logout() { sinkBeegoLogout(c.Ctx.Input.Query("u")) }

// RESTController is routed with no mapping: its own Get serves GET; the verbs it only
// inherits from web.Controller are beego's no-op defaults.
type RESTController struct{ web.Controller }

func (c *RESTController) Get()    { sinkBeegoREST(c.Ctx.Input.Query("u")) }
func (c *RESTController) Helper() { sinkNeverRegistered(c.Ctx.Input.Query("u")) }

type DynController struct{ web.Controller }

func (c *DynController) Anything() { sinkBeegoDyn(c.Ctx.Input.Query("u")) }

// Helper takes an argument, so no mapping can route a request to it.
func (c *DynController) Helper(v string) { sinkNeverRegistered(v) }

type IncController struct{ web.Controller }

// Annotated is routed by its annotation.
// @router /inc [get]
func (c *IncController) Annotated() { sinkBeegoInclude(c.Ctx.Input.Query("u")) }

// Unannotated has no @router annotation, so Include routes nothing to it.
func (c *IncController) Unannotated() { sinkNeverRegistered(c.Ctx.Input.Query("u")) }

type AutoController struct{ web.Controller }

func (c *AutoController) Auto() { sinkBeegoAuto(c.Ctx.Input.Query("u")) }

// Helper takes an argument, so the auto router cannot call it.
func (c *AutoController) Helper(v string) { sinkNeverRegistered(v) }

type AddController struct{ web.Controller }

// AddController is added with no option, so only its REST verbs are routed.
func (c *AddController) Get()   { sinkBeegoAdd(c.Ctx.Input.Query("u")) }
func (c *AddController) Added() { sinkNeverRegistered(c.Ctx.Input.Query("u")) }

// OptController is added with an option that names its routed methods.
type OptController struct{ web.Controller }

// Opted returns a value, which beego discards.
func (c *OptController) Opted() error {
	sinkBeegoOpts(c.Ctx.Input.Query("u"))
	return nil
}

func (c *OptController) Helper(v string) { sinkNeverRegistered(v) }

type NSController struct{ web.Controller }

func (c *NSController) NSRouted() { sinkBeegoNSRouter(c.Ctx.Input.Query("u")) }
func (c *NSController) NSMethod() { sinkBeegoNSMethod(c.Ctx.Input.Query("u")) }

type NSIncController struct{ web.Controller }

// @router /nsinc [post]
func (c *NSIncController) Included() { sinkBeegoNSInclude(c.Ctx.Input.Query("u")) }

func (c *NSIncController) Unannotated() { sinkNeverRegistered(c.Ctx.Input.Query("u")) }

type ServerController struct{ web.Controller }

func (c *ServerController) Served() { sinkBeegoServer(c.Ctx.Input.Query("u")) }

type CtrlController struct{ web.Controller }

func (c *CtrlController) Expr() { sinkBeegoCtrl(c.Ctx.Input.Query("u")) }

// NeverController is routed nowhere.
type NeverController struct{ web.Controller }

func (c *NeverController) Get() { sinkNeverRegistered(c.Ctx.Input.Query("u")) }

func beegoFunc(ctx *beecontext.Context)      { sinkBeegoFunc(ctx.Input.Query("u")) }
func beegoNSGet(ctx *beecontext.Context)     { sinkBeegoNSGet(ctx.Input.Query("u")) }
func beegoAddMethod(ctx *beecontext.Context) { sinkBeegoAddMethod(ctx.Input.Query("u")) }
func beegoFilter(ctx *beecontext.Context)    { sinkBeegoFilter(ctx.Input.Query("u")) }
func beegoNSBefore(ctx *beecontext.Context)  { sinkBeegoNSBefore(ctx.Input.Query("u")) }
func beegoUnused(ctx *beecontext.Context)    { sinkNeverRegistered(ctx.Input.Query("u")) }

type beegoHandler struct{}

func (h *beegoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sinkBeegoHandler(r.URL.Path)
}

// --- go-restful ---

type server struct{}

func (s *server) restGet(req *restful.Request, resp *restful.Response) {
	sinkRestGet(req.PathParameter("id"))
}
func restMethod(req *restful.Request, resp *restful.Response) {
	sinkRestMethod(req.PathParameter("id"))
}
func restFilter(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	sinkRestFilter(req.PathParameter("id"))
}
func restRouteFilter(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	sinkRestRouteFilter(req.PathParameter("id"))
}
func restContainerFilter(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	sinkRestContainer(req.PathParameter("id"))
}
func (s *server) restNever(req *restful.Request, resp *restful.Response) {
	sinkNeverRegistered(req.PathParameter("id"))
}

type restHandler struct{}

func (h *restHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { sinkRestHandle(r.URL.Path) }

// --- gorilla/websocket ---

var upgrader = &websocket.Upgrader{}

// wsForm has no handler signature and is registered with no router: upgrading the
// request is what makes it an ingress.
func (s *server) wsForm(w http.ResponseWriter, r *http.Request, room string) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	_, msg, _ := conn.ReadMessage()
	sinkWS(string(msg))
}

func (s *server) wsLegacy(w http.ResponseWriter, r *http.Request, room string) {
	conn, err := websocket.Upgrade(w, r, nil, 1024, 1024)
	if err != nil {
		return
	}
	_, msg, _ := conn.ReadMessage()
	sinkWSLegacy(string(msg))
}

// --- gRPC ---

type echoSvc struct{ pb.UnimplementedEchoServer }

func (e *echoSvc) Echo(ctx context.Context, m *pb.Msg) (*pb.Msg, error) {
	sinkGRPC(m.Body)
	return m, nil
}

// Internal is exported but no method of the service interface.
func (e *echoSvc) Internal(m *pb.Msg) { sinkNeverRegistered(m.Body) }

type legacySvc struct{}

func (legacySvc) Old(ctx context.Context, m *pb.Msg) (*pb.Msg, error) {
	sinkGRPCLegacy(m.Body)
	return m, nil
}

// neverSvc implements the service and is registered nowhere.
type neverSvc struct{ pb.UnimplementedEchoServer }

func (n *neverSvc) Echo(ctx context.Context, m *pb.Msg) (*pb.Msg, error) {
	sinkNeverRegistered(m.Body)
	return m, nil
}

// --- look-alikes ---

type lookController struct{}

func (c *lookController) Get()                              { sinkLookalike("x") }
func lookFilter(ctx *lookalike.Context)                     { sinkLookalike(ctx.Value) }
func lookRoute(r *lookalike.Request, w *lookalike.Response) { sinkLookalike(r.Value) }

type lookSvc struct{}

func (lookSvc) Do(v string) { sinkLookalike(v) }

func lookUpgrade(w http.ResponseWriter, r *http.Request, room string) {
	u := &lookalike.Upgrader{}
	if _, err := u.Upgrade(w, r, nil); err == nil {
		sinkLookalike(room)
	}
}

func mapping() string { return "post:Anything" }

func routeOption() web.ControllerOption { return func() {} }

func main() {
	s := &server{}

	web.Router("/api/login", &AuthController{}, "POST:Login")
	web.Router("/api/multi", &MultiController{}, "get,post:Multi;delete:Logout")
	web.Router("/api/rest", &RESTController{})
	web.Router("/api/dyn", &DynController{}, mapping())
	web.Include(&IncController{}, &MultiController{}) // MultiController is routed by pattern above as well
	web.AutoRouter(&AutoController{})
	web.BeeApp.Handlers.Add("/api/add", &AddController{})
	web.BeeApp.Handlers.Add("/api/opt", &OptController{}, routeOption())
	web.BeeApp.Router("/api/server", &ServerController{}, "get:Served")
	ns := web.NewNamespace("/v1",
		web.NSRouter("/ns", &NSController{}, "get:NSRouted"),
		web.NSInclude(&NSIncController{}),
		web.NSGet("/nsget", beegoNSGet),
		web.NSBefore(beegoNSBefore),
	)
	ns.Router("/nsm", &NSController{}, "get:NSMethod")
	web.AddNamespace(ns)
	web.Get("/func", beegoFunc)
	web.CtrlGet("/ctrl", (*CtrlController).Expr)
	web.BeeApp.Handlers.AddMethod("get", "/addmethod", beegoAddMethod)
	web.InsertFilter("*", web.BeforeRouter, beegoFilter)
	web.Handler("/handler", &beegoHandler{})

	ws := new(restful.WebService)
	ws.Path("/api")
	ws.Filter(restFilter)
	ws.Route(ws.GET("/nodes/{id}").To(s.restGet))
	ws.Route(ws.Method("PUT").Path("/put/{id}").Doc("put").Filter(restRouteFilter).To(restMethod))
	container := restful.NewContainer()
	container.Filter(restContainerFilter)
	container.Handle("/raw", &restHandler{})
	container.Add(ws)

	srv := grpc.NewServer()
	pb.RegisterEchoServer(srv, &echoSvc{})
	pb.RegisterLegacyServer(srv, legacySvc{})

	lookalike.Router("/look", &lookController{}, "get:Get")
	lookalike.InsertFilter("*", 1, lookFilter)
	lw := &lookalike.WebService{}
	lw.GET("/look").To(lookRoute)
	lookalike.RegisterThingServer(nil, lookSvc{})

	_ = s.wsForm
	_ = s.wsLegacy
	_ = lookUpgrade
	_ = beegoUnused
	_ = s.restNever
	_ = &NeverController{}
	_ = &neverSvc{}
}
