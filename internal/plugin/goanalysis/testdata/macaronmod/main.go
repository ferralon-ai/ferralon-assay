// Command macaronmod exercises macaron ingress detection: a handler registered on a
// macaron route via m.Post (with a leading middleware handler) must surface as an
// http_route ingress whose symbol is the SCIP of the registered handler func — the
// handler is boxed into the variadic ...Handler slice the detector unwraps. It also
// keeps a net/http handler so the stdlib registrar path stays exercised in one module.
package main

import (
	"net/http"

	macaron "gopkg.in/macaron.v1"
)

// MyHandler is the macaron leaf handler; it is the attacker-reachable ingress.
func MyHandler(w http.ResponseWriter, r *http.Request) {}

// middleware is a second handler registered ahead of MyHandler, proving the detector
// pulls every statically-resolved handler out of the variadic slice.
func middleware(w http.ResponseWriter, r *http.Request) {}

// stdlibHandler keeps the net/http registrar path exercised alongside macaron.
func stdlibHandler(w http.ResponseWriter, r *http.Request) {}

func main() {
	m := macaron.New()
	m.Post("/edit", middleware, MyHandler)

	http.HandleFunc("/handle", stdlibHandler)
}
