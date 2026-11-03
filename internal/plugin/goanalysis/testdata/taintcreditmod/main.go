// Command taintcreditmod is the shape where the credited entry point depends on the
// order ingresses are seeded: three chi-registered handlers each hand the request
// through helper and helper2 to the one sink, so every handler's taint reaches it and
// only one can be credited. The handlers are declared out of name order, so a test can
// tell the name order the credit follows from the source order it does not.
//
// Server.Handle is a handler method with a value receiver. Taking &Server{} as an
// interface gives *Server a method set, so the SSA program also holds the synthetic
// (*Server).Handle wrapper, which shares the method's SCIP id.
package main

import (
	http "tegron.test/nethttp"

	"github.com/go-chi/chi/v5"
)

// sunk keeps the sink's argument live.
var sunk []any

func sink(v string) { sunk = append(sunk, v) }

func helper2(v string) { sink(v) }

func helper(v string) { helper2(v) }

func handlerC(w http.ResponseWriter, r *http.Request) { helper(r.URL.Path) }

func handlerA(w http.ResponseWriter, r *http.Request) { helper(r.URL.Path) }

func handlerB(w http.ResponseWriter, r *http.Request) { helper(r.URL.Path) }

// Server serves Handle.
type Server struct{}

// Handle is a handler method.
func (Server) Handle(w http.ResponseWriter, r *http.Request) { sink(r.URL.Path) }

var handlers any = &Server{}

func main() {
	r := chi.NewRouter()
	r.Get("/c", handlerC)
	r.Get("/a", handlerA)
	r.Get("/b", handlerB)
}
