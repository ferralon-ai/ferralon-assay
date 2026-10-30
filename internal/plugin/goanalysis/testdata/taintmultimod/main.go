// Command taintmultimod is a stdlib-only fixture with two net/http handler ingresses whose request
// data reaches the same Sink through a shared intermediary, and a handler-shaped helper that is
// itself an ingress. The taint run attributes a sink to one ingress, so this fixture pins which one:
// the lowest ingress symbol, whatever order the handlers are registered or found in, and even when
// the sink is reached only through a higher ingress's parameters.
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

// Deep is a sink reached only through zetaHelper.
func Deep(s string) {
	fmt.Println(s)
}

// zetaHelper has the handler shape, so it is an ingress in its own right, and it sorts after
// AlphaHandler, which calls it.
func zetaHelper(w http.ResponseWriter, r *http.Request) {
	Deep(r.Host)
}

// ZetaHandler is registered first and sorts last.
func ZetaHandler(w http.ResponseWriter, r *http.Request) {
	relay(r.Method)
}

// AlphaHandler is registered second and sorts first.
func AlphaHandler(w http.ResponseWriter, r *http.Request) {
	relay(r.URL.Path)
	zetaHelper(w, r)
}

func main() {
	http.HandleFunc("/zeta", ZetaHandler)
	http.HandleFunc("/alpha", AlphaHandler)
}
