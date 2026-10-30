// Command taintmultimod is a stdlib-only fixture with two net/http handler ingresses whose request
// data reaches the same Sink through a shared intermediary. The taint run attributes a sink to one
// ingress, so this fixture pins which one: the lowest ingress symbol, whatever order the handlers
// are registered or found in.
package main

import (
	"fmt"
	"net/http"
)

// Sink is the resolved sink both handlers reach.
func Sink(s string) {
	fmt.Println(s)
}

// relay is the intermediary both flows share: once one handler's taint reaches it, the other's
// stops there, so only one ingress can be attributed to Sink.
func relay(s string) {
	Sink(s + "!")
}

// ZetaHandler is registered first and sorts last.
func ZetaHandler(w http.ResponseWriter, r *http.Request) {
	relay(r.Method)
}

// AlphaHandler is registered second and sorts first.
func AlphaHandler(w http.ResponseWriter, r *http.Request) {
	relay(r.URL.Path)
}

func main() {
	http.HandleFunc("/zeta", ZetaHandler)
	http.HandleFunc("/alpha", AlphaHandler)
}
