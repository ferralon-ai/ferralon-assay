package jsanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// reproSrc is the source root of the vendored JS SSRF repro, relative to this
// package. The hermetic first-party-reachability proof runs the REAL JS analysis
// over it.
const reproSrc = "../../../corpus/testdata/repros/TEGRON-JS-SSRF-0001-vulnerable/src"

// reverseReachable reports whether sink is reachable from any of entries over the
// directed call-graph edges. This mirrors the pipeline's firstPartyReachPaths BFS
// (which is unexported in package pipeline) so this analysis-layer test can assert
// the SAME structural-reachability property the production fallback consumes —
// without crossing the inv.8 import boundary (pipeline must not import jsanalysis).
func reverseReachable(edges []plugin.CallEdge, entries map[string]bool, sink string) bool {
	callers := map[string][]string{}
	for _, e := range edges {
		callers[e.Callee] = append(callers[e.Callee], e.Caller)
	}
	visited := map[string]bool{sink: true}
	queue := []string{sink}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if entries[cur] {
			return true
		}
		for _, c := range callers[cur] {
			if !visited[c] {
				visited[c] = true
				queue = append(queue, c)
			}
		}
	}
	return false
}

// TestFirstParty_ReproSinkReachableFromRouteIngress is the hermetic end-to-end proof
// that the JS SSRF repro yields the ingredients for a CandidatePair: the REAL JS
// analysis resolves the advisory sink (fetchUrl) to a SCIP that is a node in the REAL
// call graph, the Express route handler ingress resolves to a call-graph entry, and a
// directed path connects the ingress to the sink. That is exactly what the pipeline's
// firstPartyReachPaths fallback turns into a pair.
func TestFirstParty_ReproSinkReachableFromRouteIngress(t *testing.T) {
	ctx := context.Background()

	res, err := ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
		BuildDir:        reproSrc,
		AdvisorySymbols: []string{"fetchUrl"},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(res.Resolved) == 0 {
		t.Fatal("advisory symbol fetchUrl did not resolve in the repro")
	}
	sink := res.Resolved[0].SCIP

	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: reproSrc})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: reproSrc})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}

	// The resolved sink must be a real call-graph node (the SCIP-equality property
	// firstPartyReachPaths relies on: resolver, call graph, and ingress all use the
	// same emitter).
	sinkIsNode := false
	for _, e := range cg.Edges {
		if e.Caller == sink || e.Callee == sink {
			sinkIsNode = true
		}
	}
	if !sinkIsNode {
		t.Fatalf("resolved sink %q is not a node in the call graph", sink)
	}

	// Entries are the route ingresses plus call-graph roots — exactly the set
	// firstPartyReachPaths terminates its reverse BFS at.
	entries := map[string]bool{}
	for _, in := range ing.Ingresses {
		entries[in.Symbol] = true
	}
	for _, r := range cg.Roots {
		entries[r] = true
	}
	if len(entries) == 0 {
		t.Fatal("no ingress/root entries discovered for the repro")
	}

	if !reverseReachable(cg.Edges, entries, sink) {
		t.Fatalf("sink %q is NOT reachable from any ingress/root over the call graph;\nentries=%v\nedges=%+v", sink, entries, cg.Edges)
	}

	// The Express route ingress specifically must be present.
	routeFound := false
	for _, in := range ing.Ingresses {
		if in.Kind == "http_route" {
			routeFound = true
		}
	}
	if !routeFound {
		t.Errorf("expected an http_route ingress (express app.get) in the repro; got %+v", ing.Ingresses)
	}
}

// TestFirstParty_PatchedReproStillResolvesSinkAndIngress confirms the PATCHED repro
// keeps the same resolvable sink + ingress (the negative control is a RUNTIME guard,
// not a structural one): the call graph still connects ingress→sink, so the pipeline
// still forms a candidate pair — the patched build is dark only because the sink's
// runtime allowlist forecloses the beacon, which is the live gate's call.
func TestFirstParty_PatchedReproStillResolvesSinkAndIngress(t *testing.T) {
	ctx := context.Background()
	const patchedSrc = "../../../corpus/testdata/repros/TEGRON-JS-SSRF-0001-patched/src"

	res, err := ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
		BuildDir:        patchedSrc,
		AdvisorySymbols: []string{"fetchUrl"},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(res.Resolved) == 0 {
		t.Fatal("patched repro: advisory sink did not resolve (must still exist; it is runtime-guarded)")
	}
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: patchedSrc})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	route := false
	for _, in := range ing.Ingresses {
		if in.Kind == "http_route" {
			route = true
		}
	}
	if !route {
		t.Errorf("patched repro: expected http_route ingress; got %+v", ing.Ingresses)
	}
}

// nextRCEVulnSrc / nextRCEFixedSrc are the source roots of the Next.js < 5.1.0
// module-resolution RCE repro pair (TEGRON-JS-NEXTRCE-0001, GHSA-5vj8-3v2h-h38v).
// Unlike the SSRF repro (a runtime-guard patch that keeps the sink resolvable), this
// pair proves the Assess-tier SYMBOL-REMOVAL flip: the advisory-named sink
// requireModule resolves + is reachable at X (5.0.0) and no longer resolves at Y
// (5.1.0), because 5.1.0 deleted requireModule (renamed to the guarded requirePage).
const (
	nextRCEVulnSrc  = "../../../corpus/testdata/repros/TEGRON-JS-NEXTRCE-0001-vulnerable/src"
	nextRCEFixedSrc = "../../../corpus/testdata/repros/TEGRON-JS-NEXTRCE-0001-fixed/src"
)

// TestFirstParty_NextRCE_VulnerableResolvesAndReachable is the reachable_candidate
// leg: over the vulnerable (X = 5.0.0) fixture the REAL JS analysis resolves the
// advisory sink requireModule to a SCIP that is a node in the REAL call graph, and a
// directed path connects the http_route ingress (app.get('/:path*', handleRender)) to
// that sink over the handleRender -> render -> requireModule chain.
func TestFirstParty_NextRCE_VulnerableResolvesAndReachable(t *testing.T) {
	ctx := context.Background()

	res, err := ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
		BuildDir:        nextRCEVulnSrc,
		AdvisorySymbols: []string{"requireModule"},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(res.Resolved) != 1 {
		t.Fatalf("vulnerable repro: expected requireModule to resolve exactly once, got len=%d (%+v)", len(res.Resolved), res.Resolved)
	}
	sink := res.Resolved[0].SCIP

	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: nextRCEVulnSrc})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: nextRCEVulnSrc})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}

	sinkIsNode := false
	for _, e := range cg.Edges {
		if e.Caller == sink || e.Callee == sink {
			sinkIsNode = true
		}
	}
	if !sinkIsNode {
		t.Fatalf("resolved sink %q is not a node in the call graph", sink)
	}

	entries := map[string]bool{}
	routeFound := false
	for _, in := range ing.Ingresses {
		entries[in.Symbol] = true
		if in.Kind == "http_route" {
			routeFound = true
		}
	}
	for _, r := range cg.Roots {
		entries[r] = true
	}
	if !routeFound {
		t.Errorf("expected an http_route ingress (app.get catch-all) in the repro; got %+v", ing.Ingresses)
	}
	if !reverseReachable(cg.Edges, entries, sink) {
		t.Fatalf("sink %q is NOT reachable from any ingress/root over the call graph;\nentries=%v\nedges=%+v", sink, entries, cg.Edges)
	}
}

// TestFirstParty_NextRCE_FixedNoLongerResolves is THE FLIP: over the fixed (Y =
// 5.1.0) fixture the advisory sink requireModule no longer resolves anywhere in the
// tree (it was deleted, renamed to the guarded requirePage), so len(Resolved)==0 —
// reachable_candidate -> not_exploitable by symbol removal. This is the INVERSE of
// TestFirstParty_PatchedReproStillResolvesSinkAndIngress (guard-add keeps the sink;
// symbol-removal deletes it).
func TestFirstParty_NextRCE_FixedNoLongerResolves(t *testing.T) {
	ctx := context.Background()

	res, err := ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
		BuildDir:        nextRCEFixedSrc,
		AdvisorySymbols: []string{"requireModule"},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(res.Resolved) != 0 {
		t.Fatalf("fixed repro: expected requireModule to be REMOVED (len==0), but it still resolved: %+v", res.Resolved)
	}
}
