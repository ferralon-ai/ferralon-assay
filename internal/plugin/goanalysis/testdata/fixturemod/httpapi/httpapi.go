// Package httpapi exercises ingress detection with stdlib net/http handler
// shapes: a func(http.ResponseWriter, *http.Request) handler, an http.HandlerFunc
// value, and a statically registered route via http.HandleFunc.
package httpapi

import (
	"fmt"
	"net/http"
)

// Handle is a net/http handler-shaped function: func(http.ResponseWriter,
// *http.Request). It is a recognizable ingress.
func Handle(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "ok")
}

// HandlerValue is an http.HandlerFunc value, another recognizable handler shape.
var HandlerValue = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "value")
})

// Register statically registers Handle on a route so the route selector is
// discoverable from the call to http.HandleFunc.
func Register() {
	http.HandleFunc("/handle", Handle)
}
