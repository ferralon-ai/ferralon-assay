// Command sanitizermod is a stdlib-only fixture where every flow from the
// attacker-controlled ingress input to a sink passes through a modeled sanitizer.
// html.EscapeString's result reaches Sink directly, so the analysis observes a
// sanitized flow there: no taint path, and complete on Sink's account. The
// strconv.Atoi result reaches Opaque only through strconv.Itoa, a dependency call
// whose body the analysis does not hold, so no flow is observed reaching Opaque:
// it stays no_known_ingress (never "safe", inv.5).
package main

import (
	"fmt"
	"html"
	"net/http"
	"strconv"
)

// Sink is the resolved sink a sanitized value reaches directly.
func Sink(s string) {
	fmt.Println(s)
}

// Opaque is the resolved sink a sanitized value reaches only through a
// dependency call.
func Opaque(s string) {
	fmt.Println(s)
}

// SanitizedHandler routes the attacker-controlled request method through a
// sanitizer before each sink: no sink argument is tainted.
func SanitizedHandler(w http.ResponseWriter, r *http.Request) {
	Sink(html.EscapeString(r.Method))
	n, _ := strconv.Atoi(r.Method)
	Opaque(strconv.Itoa(n))
}

func main() {
	http.HandleFunc("/sanitized", SanitizedHandler)
}
