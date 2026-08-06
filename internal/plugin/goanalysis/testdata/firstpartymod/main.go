// Command firstpartymod is a stdlib-only fixture that mirrors a FIRST-PARTY vuln repro shape: an
// UNEXPORTED handler (fetchHandler) in package main, statically registered on an HTTP route. It
// exercises first-party-sink resolution + call-graph reachability: govulncheck never
// traces such a sink, so the advisory symbol "main.fetchHandler" must resolve by name in the app's
// own package and be reachable over the static call graph from its ingress.
package main

import (
	"fmt"
	"net/http"
)

// fetchHandler is the first-party SINK: an unexported package-main handler. A first-party advisory
// names it as "main.fetchHandler".
func fetchHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, r.URL.Query().Get("target"))
}

func main() {
	http.HandleFunc("/fetch", fetchHandler)
	_ = http.ListenAndServe(":0", nil)
}
