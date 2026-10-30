// Command taintlostmod is a stdlib-only fixture where the attacker-controlled request method
// reaches Sink twice: once sanitized, and once raw through a panic a deferred call recovers. The
// taint pass does not follow a panic to its recover, so it cannot observe that no unsanitized
// flow reaches Sink, and must not report Sink as reached only by sanitized flows.
package main

import (
	"fmt"
	"html"
	"net/http"
)

// Sink is the resolved sink.
func Sink(s string) {
	fmt.Println(s)
}

// RecoverHandler panics with the raw method and recovers it into Sink.
func RecoverHandler(w http.ResponseWriter, r *http.Request) {
	Sink(html.EscapeString(r.Method))
	defer func() {
		if v := recover(); v != nil {
			Sink(fmt.Sprint(v))
		}
	}()
	panic(r.Method)
}

func main() {
	http.HandleFunc("/recover", RecoverHandler)
}
