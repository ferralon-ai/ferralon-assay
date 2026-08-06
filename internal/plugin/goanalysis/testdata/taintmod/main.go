// Command taintmod is a stdlib-only fixture exercising variable-level SSA
// value-flow taint. The net/http handler is an ingress whose *http.Request
// parameter is attacker-controllable: TaintedHandler forwards request data to
// Sink through a non-sanitizing intermediary, so an attacker-controlled value
// reaches the sink argument — a real taint path on a fully-resolved clean graph
// (no reflection / cgo / dynamic dispatch). Sink is the resolved sink.
package main

import (
	"fmt"
	"net/http"
)

// Sink is the resolved sink: a value reaching its argument via attacker-
// controllable ingress input is a taint finding.
func Sink(s string) {
	fmt.Println(s)
}

// passthrough is an intermediate, non-sanitizing transform: it carries taint
// from its argument to its result, exercising inter-procedural arg->param
// forwarding and the tainted call-result rule.
func passthrough(s string) string {
	return s + "!"
}

// TaintedHandler forwards the attacker-controlled request method to Sink through
// a non-sanitizing intermediary: a clean source->sink value-flow path.
func TaintedHandler(w http.ResponseWriter, r *http.Request) {
	v := passthrough(r.Method)
	Sink(v)
}

func main() {
	http.HandleFunc("/tainted", TaintedHandler)
}
