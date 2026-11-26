package main

import (
	"github.com/go-chi/chi/v5"
	http "tegron.test/nethttp"
)

// The handlers in this file reach their registrar bound first: loaded from a package
// var, from a struct field, or returned by a first-party factory. Each registered one
// hands request data to its own sink; the negatives (a var stored twice, a field
// holding two handlers, a factory returning its parameter) resolve to no one handler
// and register no ingress, so their sinks get no path.

func sinkVar(v string)     { sunk = append(sunk, v) }
func sinkField(v string)   { sunk = append(sunk, v) }
func sinkFactory(v string) { sunk = append(sunk, v) }
func sinkUnbound(v string) { sunk = append(sunk, v) }

// varHandler is a handler bound to a package var by its declaration (init$1).
var varHandler = func(w http.ResponseWriter, r *http.Request) { sinkVar(r.URL.Path) }

// boundRoutes holds its handler in a struct field.
type boundRoutes struct{ h http.HandlerFunc }

func fieldForm(w http.ResponseWriter, r *http.Request) { sinkField(r.URL.Path) }

func (b *boundRoutes) register(r *chi.Mux) { r.Get("/field", b.h) }

// makeHandler is a first-party factory: the closure it returns is the handler.
func makeHandler(name string) http.HandlerFunc {
	if name == "" {
		return nil
	}
	return func(w http.ResponseWriter, r *http.Request) { sinkFactory(r.URL.Path + name) }
}

// reboundHandler is stored twice, so a load of it is no one handler.
var reboundHandler http.HandlerFunc = reboundA

func reboundA(w http.ResponseWriter, r *http.Request) { sinkUnbound(r.URL.Path) }
func reboundB(w http.ResponseWriter, r *http.Request) { sinkUnbound(r.URL.Path) }

func rebind() { reboundHandler = reboundB }

// twoRoutes' field holds two different handlers, so a load of it is no one handler.
type twoRoutes struct{ h http.HandlerFunc }

func twoA(w http.ResponseWriter, r *http.Request) { sinkUnbound(r.URL.Path) }
func twoB(w http.ResponseWriter, r *http.Request) { sinkUnbound(r.URL.Path) }

// passThrough returns its parameter, which no caller is followed into.
func passThrough(h http.HandlerFunc) http.HandlerFunc { return h }

func paramHandler(w http.ResponseWriter, r *http.Request) { sinkUnbound(r.URL.Path) }

func registerBound(r *chi.Mux) {
	r.Get("/var/{id}", varHandler)
	(&boundRoutes{h: fieldForm}).register(r)
	r.Get("/factory/{id}", makeHandler("id"))

	rebind()
	r.Get("/rebound", reboundHandler)
	pair := []twoRoutes{{h: twoA}, {h: twoB}}
	for _, p := range pair {
		r.Get("/two", p.h)
	}
	r.Get("/param", passThrough(paramHandler))
}
