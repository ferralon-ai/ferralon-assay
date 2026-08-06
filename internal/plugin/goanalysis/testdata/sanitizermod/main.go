// Command sanitizermod is a stdlib-only fixture where the ONLY flow from the
// attacker-controlled ingress input to Sink passes through a modeled sanitizer
// (strconv.Atoi). The value reaching Sink is the sanitized integer's string form,
// not attacker-controlled content, so ComputeTaint must report NO taint path —
// a true negative — and declare no_known_ingress (never "safe", inv.5).
package main

import (
	"fmt"
	"net/http"
	"strconv"
)

// Sink is the resolved sink.
func Sink(s string) {
	fmt.Println(s)
}

// SanitizedHandler routes the attacker-controlled request method through
// strconv.Atoi before the sink: the sink argument is sanitized, not tainted.
func SanitizedHandler(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.Method)
	Sink(strconv.Itoa(n))
}

func main() {
	http.HandleFunc("/sanitized", SanitizedHandler)
}
