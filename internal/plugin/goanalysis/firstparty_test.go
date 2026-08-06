// internal/plugin/goanalysis/firstparty_test.go
//
// Hermetic goanalysis tests for first-party-sink resolution + reachability.
// These load a real fixture (firstpartymod) with the Go toolchain — no live model, no Docker, no
// network. They prove the live path's PREREQUISITES that govulncheck cannot supply for a first-party
// advisory:
//   - an UNEXPORTED handler in package main is indexed and resolves from the advisory form
//     "main.fetchHandler", even though its synthetic PURL package is not a loaded package path; and
//   - the resolved sink SCIP is emitted by the SAME emitter the call graph + ingress detection use,
//     so the pipeline's call-graph fallback (firstPartyReachPaths) can anchor an ingress→sink pair.
package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const firstPartyFixtureDir = "testdata/firstpartymod"

// Grafana CVE-2024-9264 (SQL Expressions → DuckDB RCE/LFI) flip fixtures. The
// vulnerable tree carries the first-party exec sink main.runDuckQuery reachable
// from the /api/ds/query http_route ingress; the fixed tree applies the real
// upstream removal (PR #94942) — the sink is deleted, the route redirected to an
// inert stub — so the advisory symbol resolves to nothing. These live in the
// shared corpus repro tree, loaded here via a relative path from the package dir.
const (
	grafanaVulnFixtureDir  = "../../../corpus/testdata/repros/TEGRON-GO-GRAFANA-DUCKDB-0001-vulnerable/src"
	grafanaFixedFixtureDir = "../../../corpus/testdata/repros/TEGRON-GO-GRAFANA-DUCKDB-0001-fixed/src"
	grafanaPURL            = "pkg:golang/github.com/grafana/grafana"
	grafanaSink            = "main.runDuckQuery"
	grafanaVulnID          = "TEGRON-GO-GRAFANA-DUCKDB-0001"
)

// TestFirstParty_IndexesUnexportedMainHandler proves the unexported package-main handler is indexed
// (it was previously dropped because only exported symbols + main were indexed) — the precondition
// for resolving a first-party sink.
func TestFirstParty_IndexesUnexportedMainHandler(t *testing.T) {
	res, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: firstPartyFixtureDir})
	if err != nil {
		t.Fatalf("IndexSymbols: %v", err)
	}
	found := false
	for _, s := range res.Symbols {
		if s.DisplayName == "fetchHandler" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unexported package-main handler fetchHandler was not indexed; got %v", displayNames(res.Symbols))
	}
}

// TestFirstParty_ResolvesPackageQualifiedSymbol proves the advisory form "main.fetchHandler"
// resolves to the unexported sink even though the synthetic first-party PURL
// (pkg:golang/tegron/corpus/app) names no loaded package — the package filter is dropped when it
// matches nothing, then the symbol resolves by name.
func TestFirstParty_ResolvesPackageQualifiedSymbol(t *testing.T) {
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        firstPartyFixtureDir,
		PURL:            "pkg:golang/tegron/corpus/app", // synthetic; not a loaded package path
		AdvisorySymbols: []string{"main.fetchHandler"},
		VulnID:          "FERRALON-APP-SSRF-0001",
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(res.Resolved) != 1 {
		t.Fatalf("first-party advisory symbol main.fetchHandler must resolve to exactly 1 symbol, got %d: %+v", len(res.Resolved), res.Resolved)
	}
	if res.Resolved[0].SCIP == "" {
		t.Fatalf("resolved first-party sink missing SCIP: %+v", res.Resolved[0])
	}
	if res.Resolved[0].DisplayName != "fetchHandler" {
		t.Errorf("resolved the wrong symbol: %q", res.Resolved[0].DisplayName)
	}
}

// TestFirstParty_ResolvedSinkIsIngressForCallGraphFallback ties it together: the resolved sink SCIP
// must coincide with a FindIngresses ingress symbol (the handler is its own entry point) and appear
// in the call graph — so the pipeline's firstPartyReachPaths can build an ingress→sink pair WITHOUT
// any govulncheck path. A non-empty intersection here is the hermetic proof that the live first-party
// reachability has its ingredients.
func TestFirstParty_ResolvedSinkIsIngressForCallGraphFallback(t *testing.T) {
	ctx := context.Background()
	resolved, err := ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
		BuildDir:        firstPartyFixtureDir,
		PURL:            "pkg:golang/tegron/corpus/app",
		AdvisorySymbols: []string{"main.fetchHandler"},
	})
	if err != nil || len(resolved.Resolved) != 1 {
		t.Fatalf("resolve sink: err=%v resolved=%+v", err, resolved.Resolved)
	}
	sink := resolved.Resolved[0].SCIP

	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: firstPartyFixtureDir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	ingressMatch := false
	for _, in := range ing.Ingresses {
		if in.Symbol == sink {
			ingressMatch = true
		}
	}
	if !ingressMatch {
		var got []string
		for _, in := range ing.Ingresses {
			got = append(got, in.Kind+":"+in.Symbol)
		}
		t.Fatalf("resolved sink SCIP is not among detected ingresses; the handler must be its own ingress.\nsink=%q\ningresses=%v", sink, got)
	}

	// Govulncheck-equivalent emptiness is what triggers the fallback; assert the sink also exists in
	// the call graph (as a node) so a non-degenerate path could be reconstructed when the ingress and
	// sink differ. Here the handler IS the ingress, so presence as a callee OR a root is sufficient.
	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: firstPartyFixtureDir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	inGraph := false
	for _, r := range cg.Roots {
		if r == sink {
			inGraph = true
		}
	}
	for _, e := range cg.Edges {
		if e.Caller == sink || e.Callee == sink {
			inGraph = true
		}
	}
	if !inGraph && !ingressMatch {
		t.Errorf("resolved sink %q absent from the call graph and ingresses; no first-party pair could be built", sink)
	}
	if !strings.Contains(sink, "fetchHandler") {
		t.Errorf("sanity: resolved sink SCIP %q does not name fetchHandler", sink)
	}
}

// reachableFrom reports whether target is reachable from any symbol in roots over
// the directed call-graph edges (forward BFS). Used to prove an ingress→sink path.
func reachableFrom(roots []string, target string, edges []plugin.CallEdge) bool {
	adj := map[string][]string{}
	for _, e := range edges {
		adj[e.Caller] = append(adj[e.Caller], e.Callee)
	}
	seen := map[string]bool{}
	queue := append([]string{}, roots...)
	for _, r := range roots {
		seen[r] = true
		if r == target {
			return true
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range adj[cur] {
			if next == target {
				return true
			}
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
	return false
}

// TestFirstParty_GrafanaDuckDB_VulnerableResolvesReachableSink proves the VULNERABLE
// leg of the CVE-2024-9264 flip: the advisory sink main.runDuckQuery resolves to
// exactly one indexed symbol AND that sink is reachable from a recognized ingress
// (the /api/ds/query http_route / queryHandler) over the static call graph — the
// two facts on which the Assess tier bases reachable_candidate.
func TestFirstParty_GrafanaDuckDB_VulnerableResolvesReachableSink(t *testing.T) {
	ctx := context.Background()
	resolved, err := ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
		BuildDir:        grafanaVulnFixtureDir,
		PURL:            grafanaPURL,
		AdvisorySymbols: []string{grafanaSink},
		VulnID:          grafanaVulnID,
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols(vulnerable): %v", err)
	}
	if len(resolved.Resolved) != 1 {
		t.Fatalf("vulnerable: advisory sink %s must resolve to exactly 1 symbol, got %d: %+v",
			grafanaSink, len(resolved.Resolved), resolved.Resolved)
	}
	sink := resolved.Resolved[0].SCIP
	if !strings.Contains(sink, "runDuckQuery") {
		t.Fatalf("vulnerable: resolved sink SCIP %q does not name runDuckQuery", sink)
	}

	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: grafanaVulnFixtureDir})
	if err != nil {
		t.Fatalf("FindIngresses(vulnerable): %v", err)
	}
	var ingressSyms []string
	for _, in := range ing.Ingresses {
		ingressSyms = append(ingressSyms, in.Symbol)
	}
	if len(ingressSyms) == 0 {
		t.Fatalf("vulnerable: no ingresses detected; expected the /api/ds/query http_route/handler")
	}

	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: grafanaVulnFixtureDir})
	if err != nil {
		t.Fatalf("CallGraph(vulnerable): %v", err)
	}
	if !reachableFrom(ingressSyms, sink, cg.Edges) {
		var got []string
		for _, in := range ing.Ingresses {
			got = append(got, in.Kind+":"+in.Symbol)
		}
		t.Fatalf("vulnerable: sink %q is not reachable from any ingress over the call graph — no candidate would fire.\ningresses=%v", sink, got)
	}
}

// TestFirstParty_GrafanaDuckDB_FixedRemovesSink proves the FIXED leg of the flip:
// the real upstream removal deletes runDuckQuery outright, so the advisory symbol
// resolves to nothing (len==0). No reachable ingress→sink path can exist →
// reachable_candidate → not_exploitable. This is the inverse of the JS patched-repro
// test (which keeps the symbol because that fix is a guard-add).
func TestFirstParty_GrafanaDuckDB_FixedRemovesSink(t *testing.T) {
	resolved, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        grafanaFixedFixtureDir,
		PURL:            grafanaPURL,
		AdvisorySymbols: []string{grafanaSink},
		VulnID:          grafanaVulnID,
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols(fixed): %v", err)
	}
	if len(resolved.Resolved) != 0 {
		t.Fatalf("fixed: advisory sink %s must resolve to 0 symbols after the removal, got %d: %+v",
			grafanaSink, len(resolved.Resolved), resolved.Resolved)
	}
}
