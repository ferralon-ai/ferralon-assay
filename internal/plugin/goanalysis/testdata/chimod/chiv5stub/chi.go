// Package chi is a minimal local stand-in for github.com/go-chi/chi/v5, just enough
// for the ingress detector to recognize the route-registrar shapes hermetically (no
// network fetch of the real module). The package PATH is what the detector matches
// (github.com/go-chi/chi/v5), supplied via a go.mod module directive + a replace in
// the fixture. The signatures mirror the real chi ones: the verb methods take an
// http.HandlerFunc, Handle/Method/Mount an http.Handler, and Route/Group hand the
// grouping closure a Router INTERFACE, so registrations inside it are interface
// (invoke) calls rather than static (*Mux) calls.
package chi

import http "tegron.test/nethttp"

// Router is the chi routing interface Route, Group and With hand back.
type Router interface {
	http.Handler

	Use(middlewares ...func(http.Handler) http.Handler)
	With(middlewares ...func(http.Handler) http.Handler) Router
	Group(fn func(r Router)) Router
	Route(pattern string, fn func(r Router)) Router
	Mount(pattern string, h http.Handler)

	Handle(pattern string, h http.Handler)
	HandleFunc(pattern string, h http.HandlerFunc)
	Method(method, pattern string, h http.Handler)
	MethodFunc(method, pattern string, h http.HandlerFunc)

	Connect(pattern string, h http.HandlerFunc)
	Delete(pattern string, h http.HandlerFunc)
	Get(pattern string, h http.HandlerFunc)
	Head(pattern string, h http.HandlerFunc)
	Options(pattern string, h http.HandlerFunc)
	Patch(pattern string, h http.HandlerFunc)
	Post(pattern string, h http.HandlerFunc)
	Put(pattern string, h http.HandlerFunc)
	Trace(pattern string, h http.HandlerFunc)
}

// Mux stands in for the chi router.
type Mux struct{}

// NewRouter returns a router.
func NewRouter() *Mux { return &Mux{} }

func (mx *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

func (mx *Mux) Use(middlewares ...func(http.Handler) http.Handler) {}

func (mx *Mux) With(middlewares ...func(http.Handler) http.Handler) Router { return &Mux{} }

func (mx *Mux) Group(fn func(r Router)) Router {
	im := &Mux{}
	fn(im)
	return im
}

func (mx *Mux) Route(pattern string, fn func(r Router)) Router {
	sub := &Mux{}
	fn(sub)
	mx.Mount(pattern, sub)
	return sub
}

func (mx *Mux) Mount(pattern string, h http.Handler) {}

func (mx *Mux) Handle(pattern string, h http.Handler) {}

func (mx *Mux) HandleFunc(pattern string, h http.HandlerFunc) {}

func (mx *Mux) Method(method, pattern string, h http.Handler) {}

func (mx *Mux) MethodFunc(method, pattern string, h http.HandlerFunc) {}

func (mx *Mux) Connect(pattern string, h http.HandlerFunc) {}
func (mx *Mux) Delete(pattern string, h http.HandlerFunc)  {}
func (mx *Mux) Get(pattern string, h http.HandlerFunc)     {}
func (mx *Mux) Head(pattern string, h http.HandlerFunc)    {}
func (mx *Mux) Options(pattern string, h http.HandlerFunc) {}
func (mx *Mux) Patch(pattern string, h http.HandlerFunc)   {}
func (mx *Mux) Post(pattern string, h http.HandlerFunc)    {}
func (mx *Mux) Put(pattern string, h http.HandlerFunc)     {}
func (mx *Mux) Trace(pattern string, h http.HandlerFunc)   {}

// URLParam mirrors chi.URLParam: the URL parameter key of the routed request.
func URLParam(r *http.Request, key string) string { return "" }
