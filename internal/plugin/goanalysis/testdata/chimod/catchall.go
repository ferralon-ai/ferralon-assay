package main

// Catch-all registrations: chi's NotFound and MethodNotAllowed install the handler for
// a request no route matches (or none matches by method). Each registers under the
// catch-all selector "*", on the concrete Mux, on a chi.Router interface inside a
// Route closure, and on a chi v1 router; a look-alike router's NotFound is no ingress.

import (
	chiv1 "github.com/go-chi/chi"
	"github.com/go-chi/chi/v5"
	http "tegron.test/nethttp"

	lookalike "tegron.test/chimod/lookalike"
)

func sinkNotFound(v string)         { sunk = append(sunk, v) }
func sinkMethodNotAllowed(v string) { sunk = append(sunk, v) }
func sinkSubNotFound(v string)      { sunk = append(sunk, v) }
func sinkV1NotFound(v string)       { sunk = append(sunk, v) }

func (s *server) notFoundForm(w http.ResponseWriter, r *http.Request) { sinkNotFound(r.URL.Path) }
func (s *server) methodNotAllowedForm(w http.ResponseWriter, r *http.Request) {
	sinkMethodNotAllowed(r.Method)
}
func (s *server) subNotFoundForm(w http.ResponseWriter, r *http.Request)   { sinkSubNotFound(r.URL.Path) }
func (s *server) v1NotFoundForm(w http.ResponseWriter, r *http.Request)    { sinkV1NotFound(r.URL.Path) }
func (s *server) lookalikeNotFound(w http.ResponseWriter, r *http.Request) { sinkLookalike(r.URL.Path) }

func registerCatchAll(s *server, r *chi.Mux) {
	r.NotFound(s.notFoundForm)
	r.MethodNotAllowed(s.methodNotAllowedForm)
	r.Route("/nf", func(sub chi.Router) { sub.NotFound(s.subNotFoundForm) })

	old := chiv1.NewRouter()
	old.NotFound(s.v1NotFoundForm)

	fake := lookalike.NewRouter()
	fake.NotFound(s.lookalikeNotFound)
}
