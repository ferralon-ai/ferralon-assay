// Command taintreflectmod is a stdlib-only fixture where attacker-controlled
// ingress input reaches a sink, but the enclosing function also performs a
// reflect.* call — a partiality trigger on the tainted path. ComputeTaint must
// still report the taint path AND declare Partial(reflection): honesty over
// reach (inv.5).
package main

import (
	"fmt"
	"net/http"
	"reflect"
)

// Sink is the resolved sink.
func Sink(s string) {
	fmt.Println(s)
}

// ReflectHandler forwards the attacker-controlled request method to Sink, and on
// the same path consults reflect.TypeOf — an unanalyzable reflection call that
// degrades the result to Partial(reflection).
func ReflectHandler(w http.ResponseWriter, r *http.Request) {
	m := r.Method
	_ = reflect.TypeOf(m).Kind()
	Sink(m)
}

func main() {
	http.HandleFunc("/reflect", ReflectHandler)
}
