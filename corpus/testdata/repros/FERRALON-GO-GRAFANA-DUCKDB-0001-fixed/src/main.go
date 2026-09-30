// Command grafana-duckdb is the FIXED variant of the Grafana CVE-2024-9264 repro.
// It applies the real upstream fix (PR #94942, "disable sql expressions"): the
// go-duck dependency and the exec sink (runDuckQuery) are DELETED, and the
// /api/ds/query route is redirected to an inert not-implemented response. The
// reachable exec sink no longer exists in the build, so ResolveDependencySymbols
// for main.runDuckQuery resolves nothing (len==0) → not_exploitable.
//
// State Y (fixed): 6e6ed73416ebed5e92c98963937a5f349534c76a "disable sql expressions".
package main

import "net/http"

// queryHandler no longer reaches any SQL/DuckDB engine. The upstream fix disables
// SQL expressions before the query is built; this route now returns an inert
// error, exactly as the fixed Grafana reader.go does (QueryTypeSQL →
// "sqlExpressions is not implemented"). No exec sink remains on any path.
func queryHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "sqlExpressions is not implemented", http.StatusNotImplemented)
}

func main() {
	http.HandleFunc("/api/ds/query", queryHandler)
	_ = http.ListenAndServe(":0", nil)
}
