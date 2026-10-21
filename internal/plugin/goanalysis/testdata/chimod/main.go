// Command chimod exercises chi ingress detection. Every chi registration form —
// the verb methods, Method/MethodFunc, Handle/HandleFunc, and handlers reached
// through Route, Group, With and Mount — registers a handler that hands
// attacker-controlled request data (a field of its *http.Request) to its OWN sink, so
// a test can prove per form that the handler is an http_route ingress AND heads the
// taint trace to that form's sink.
//
// The registered handlers are deliberately methods, closures and ServeHTTP
// implementations, the shapes the package-scope net/http signature rule (Kind
// "handler") never lists, so the chi registration is the only thing that makes them
// ingresses. (The http types here are tegron.test/nethttp's stand-ins; see
// nethttpstub/http.go.)
//
// The negatives sit in the same module: a handler-shaped method never registered
// anywhere, a package-scope handler-shaped func never registered, and handlers
// registered on a look-alike router (same package name, type and method names as
// chi, different import path).
package main

import (
	http "tegron.test/nethttp"

	chiv1 "github.com/go-chi/chi"
	"github.com/go-chi/chi/v5"

	lookalike "tegron.test/chimod/lookalike"
)

// sunk keeps the sinks' arguments live.
var sunk []string

// One sink per registration form, so each form's taint path is distinguishable.
func sinkGet(v string)        { sunk = append(sunk, v) }
func sinkPost(v string)       { sunk = append(sunk, v) }
func sinkPut(v string)        { sunk = append(sunk, v) }
func sinkPatch(v string)      { sunk = append(sunk, v) }
func sinkDelete(v string)     { sunk = append(sunk, v) }
func sinkHead(v string)       { sunk = append(sunk, v) }
func sinkOptions(v string)    { sunk = append(sunk, v) }
func sinkConnect(v string)    { sunk = append(sunk, v) }
func sinkTrace(v string)      { sunk = append(sunk, v) }
func sinkMethod(v string)     { sunk = append(sunk, v) }
func sinkMethodFunc(v string) { sunk = append(sunk, v) }
func sinkHandle(v string)     { sunk = append(sunk, v) }
func sinkHandleFunc(v string) { sunk = append(sunk, v) }
func sinkRoute(v string)      { sunk = append(sunk, v) }
func sinkGroup(v string)      { sunk = append(sunk, v) }
func sinkWith(v string)       { sunk = append(sunk, v) }
func sinkMount(v string)      { sunk = append(sunk, v) }
func sinkMountSub(v string)   { sunk = append(sunk, v) }
func sinkV1(v string)         { sunk = append(sunk, v) }

// Negative sinks: no chi-registered handler reaches these.
func sinkNeverRegistered(v string) { sunk = append(sunk, v) }
func sinkLookalike(v string)       { sunk = append(sunk, v) }

type server struct{}

func (s *server) getForm(w http.ResponseWriter, r *http.Request) {
	sinkGet(r.URL.Path)
}
func (s *server) postForm(w http.ResponseWriter, r *http.Request)    { sinkPost(r.URL.RawQuery) }
func (s *server) putForm(w http.ResponseWriter, r *http.Request)     { sinkPut(r.URL.Path) }
func (s *server) patchForm(w http.ResponseWriter, r *http.Request)   { sinkPatch(r.URL.Path) }
func (s *server) deleteForm(w http.ResponseWriter, r *http.Request)  { sinkDelete(r.URL.Path) }
func (s *server) headForm(w http.ResponseWriter, r *http.Request)    { sinkHead(r.URL.Path) }
func (s *server) optionsForm(w http.ResponseWriter, r *http.Request) { sinkOptions(r.URL.Path) }
func (s *server) connectForm(w http.ResponseWriter, r *http.Request) { sinkConnect(r.URL.Path) }
func (s *server) traceForm(w http.ResponseWriter, r *http.Request)   { sinkTrace(r.URL.Path) }
func (s *server) methodForm(w http.ResponseWriter, r *http.Request)  { sinkMethod(r.URL.Path) }
func (s *server) methodFuncForm(w http.ResponseWriter, r *http.Request) {
	sinkMethodFunc(r.URL.Path)
}
func (s *server) handleForm(w http.ResponseWriter, r *http.Request) { sinkHandle(r.URL.Path) }
func (s *server) handleFuncForm(w http.ResponseWriter, r *http.Request) {
	sinkHandleFunc(r.URL.Path)
}
func (s *server) routeForm(w http.ResponseWriter, r *http.Request) {
	sinkRoute(r.URL.Path)
}
func (s *server) withForm(w http.ResponseWriter, r *http.Request)     { sinkWith(r.URL.Path) }
func (s *server) mountSubForm(w http.ResponseWriter, r *http.Request) { sinkMountSub(r.URL.Path) }
func (s *server) v1Form(w http.ResponseWriter, r *http.Request)       { sinkV1(r.URL.Path) }

// mountedHandler is an http.Handler mounted directly (its ServeHTTP is the ingress).
type mountedHandler struct{}

func (h *mountedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { sinkMount(r.URL.Path) }

// neverRegistered is handler-shaped but registered on no chi router directly (only
// through fwdRouter's forwarding, which the detector does not follow): no ingress.
func (s *server) neverRegistered(w http.ResponseWriter, r *http.Request) {
	sinkNeverRegistered(r.URL.Path)
}

// unregisteredFunc is a package-scope handler-shaped func registered on no router:
// no http_route. (Against the real net/http types the pre-existing signature rule
// would still list it as Kind "handler"; chi recognition does not change that.)
func unregisteredFunc(w http.ResponseWriter, r *http.Request) { sinkNeverRegistered(r.URL.Path) }

// Handlers registered only on the look-alike router: no ingress.
func (s *server) lookalikeGet(w http.ResponseWriter, r *http.Request)    { sinkLookalike(r.URL.Path) }
func (s *server) lookalikePost(w http.ResponseWriter, r *http.Request)   { sinkLookalike(r.URL.Path) }
func (s *server) lookalikeHandle(w http.ResponseWriter, r *http.Request) { sinkLookalike(r.URL.Path) }
func (s *server) lookalikeMethod(w http.ResponseWriter, r *http.Request) { sinkLookalike(r.URL.Path) }
func (s *server) lookalikeRoute(w http.ResponseWriter, r *http.Request)  { sinkLookalike(r.URL.Path) }

type lookalikeMounted struct{}

func (h *lookalikeMounted) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sinkLookalike(r.URL.Path)
}

func middleware(next http.Handler) http.Handler { return next }

// fwdRouter is a first-party wrapper that forwards to chi with a non-constant
// pattern, so the handler reaches chi boxed as an http.HandlerFunc in a variable:
// the adapter's ServeHTTP must not become an ingress.
type fwdRouter struct{ r chi.Router }

func (f *fwdRouter) Get(p string, h http.HandlerFunc) { f.r.Method("GET", p, h) }

// subRouter builds a chi router that the main router mounts; its own route is
// discovered on the sub-router itself.
func subRouter(s *server) http.Handler {
	sr := chi.NewRouter()
	sr.Get("/{id}", s.mountSubForm)
	return sr
}

func main() {
	s := &server{}

	r := chi.NewRouter()
	r.Get("/get/{id}", s.getForm)
	r.Post("/post", s.postForm)
	r.Put("/put", s.putForm)
	r.Patch("/patch", s.patchForm)
	r.Delete("/delete", s.deleteForm)
	r.Head("/head", s.headForm)
	r.Options("/options", s.optionsForm)
	r.Connect("/connect", s.connectForm)
	r.Trace("/trace", s.traceForm)
	r.Method("GET", "/method", http.HandlerFunc(s.methodForm))
	r.MethodFunc("POST", "/methodfunc", s.methodFuncForm)
	r.Handle("/handle", http.HandlerFunc(s.handleForm))
	r.HandleFunc("/handlefunc", s.handleFuncForm)
	r.Route("/route", func(sub chi.Router) {
		sub.Get("/{id}", s.routeForm)
	})
	r.Group(func(g chi.Router) {
		g.Post("/group", func(w http.ResponseWriter, req *http.Request) {
			sinkGroup(req.Method)
		})
	})
	r.With(middleware).Get("/with", s.withForm)
	r.Mount("/mount", &mountedHandler{})
	r.Mount("/sub", subRouter(s))
	// A bare chi router mounted directly: chi's own ServeHTTP is no ingress.
	r.Mount("/bare", chi.NewRouter())
	(&fwdRouter{r: r}).Get("/fwd", s.neverRegistered)

	old := chiv1.NewRouter()
	old.Get("/v1/{id}", s.v1Form)

	fake := lookalike.NewRouter()
	fake.Get("/fake", s.lookalikeGet)
	fake.Post("/fake", s.lookalikePost)
	fake.Handle("/fake-handle", http.HandlerFunc(s.lookalikeHandle))
	fake.Method("GET", "/fake-method", http.HandlerFunc(s.lookalikeMethod))
	fake.Mount("/fake-mount", &lookalikeMounted{})
	fake.Route("/fake-route", func(sub lookalike.Router) {
		sub.Get("/{id}", s.lookalikeRoute)
	})
}
