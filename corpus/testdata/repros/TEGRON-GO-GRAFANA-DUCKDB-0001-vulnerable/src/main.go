// Command grafana-duckdb is a stdlib-only reduced repro of Grafana CVE-2024-9264
// (SQL Expressions → DuckDB RCE/LFI). It mirrors the FIRST-PARTY vuln shape: an
// http_route (/api/ds/query) reaches an unexported package-main sink
// (runDuckQuery) that hands attacker-controlled SQL to the DuckDB engine binary
// via exec.Command. The upstream fix (PR #94942) DELETES this path entirely —
// the go-duck dependency and the exec sink are removed and the route is
// redirected to an inert not-implemented response (see the -fixed variant).
//
// State X (vulnerable): parent of the fix commit, cbe1e7d63f098e306058c0fbcab2f5c30602fa7d.
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

// queryHandler is the recognized ingress: the statically-registered handler for
// /api/ds/query. It forwards the attacker-controlled `sql` parameter straight to
// the first-party sink with no allowlist.
func queryHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("sql")
	out, err := runDuckQuery(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, out)
}

// runDuckQuery is the first-party SINK (advisory: main.runDuckQuery). It executes
// attacker SQL through the DuckDB engine binary — SQL command-injection plus
// DuckDB file functions yield LFI/RCE (CVE-2024-9264). The advisory names it as
// a first-party sink; govulncheck never traces it, so reachability falls back to
// the static call graph from the /api/ds/query ingress (ADR 0005).
func runDuckQuery(query string) (string, error) {
	cmd := exec.Command("duckdb", "-c", query)
	b, err := cmd.CombinedOutput()
	return string(b), err
}

func main() {
	http.HandleFunc("/api/ds/query", queryHandler)
	_ = http.ListenAndServe(":0", nil)
}
