// Package chi is a LOOK-ALIKE router: same package name, type names and method
// names as go-chi, but declared under this fixture's own import path
// (tegron.test/chimod/lookalike), not github.com/go-chi/chi[/v5]. A handler
// registered on it must NOT become an ingress — the detector keys on chi's import
// path, never on a type or method name alone.
package chi

import http "tegron.test/nethttp"

// Router mirrors chi's routing interface.
type Router interface {
	Get(pattern string, h http.HandlerFunc)
	Route(pattern string, fn func(r Router)) Router
}

// Mux mirrors chi's router type.
type Mux struct{}

// NewRouter returns a router.
func NewRouter() *Mux { return &Mux{} }

func (mx *Mux) Get(pattern string, h http.HandlerFunc)        {}
func (mx *Mux) Post(pattern string, h http.HandlerFunc)       {}
func (mx *Mux) Handle(pattern string, h http.Handler)         {}
func (mx *Mux) Mount(pattern string, h http.Handler)          {}
func (mx *Mux) Method(method, pattern string, h http.Handler) {}

func (mx *Mux) Route(pattern string, fn func(r Router)) Router {
	sub := &Mux{}
	fn(sub)
	return sub
}
