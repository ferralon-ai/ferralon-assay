// Command twosinkmod is a stdlib-only fixture with two sinks behind one handler: Escaped is
// reached only by the sanitized request method, Raw by the method itself.
package main

import (
	"fmt"
	"html"
	"net/http"
)

// Escaped is the sink only a sanitized flow reaches.
func Escaped(s string) {
	fmt.Println(s)
}

// Raw is the sink the unsanitized method reaches.
func Raw(s string) {
	fmt.Println(s)
}

// Handler hands Escaped the sanitized method and Raw the method itself.
func Handler(w http.ResponseWriter, r *http.Request) {
	Escaped(html.EscapeString(r.Method))
	Raw(r.Method)
}

func main() {
	http.HandleFunc("/", Handler)
}
