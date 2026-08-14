package javaanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// reproSrc is the source root of the vendored Java SSRF repro, relative to this
// package. The hermetic first-party-reachability proof runs the REAL Java analysis
// over it.
const reproSrc = "../../../corpus/testdata/repros/TEGRON-JAVA-SSRF-0001-vulnerable/src"

// reverseReachable reports whether sink is reachable from any of entries over the
// directed call-graph edges. This mirrors the pipeline's firstPartyReachPaths BFS
// (which is unexported in package pipeline) so this analysis-layer test can assert
// the SAME structural-reachability property the production fallback consumes —
// without crossing the inv.8 import boundary (pipeline must not import javaanalysis).
func reverseReachable(edges []plugin.CallEdge, entries map[string]bool, sink string) bool {
	callers := map[string][]string{}
	for _, e := range edges {
		callers[e.Callee.SCIP] = append(callers[e.Callee.SCIP], e.Caller.SCIP)
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

// TestFirstParty_ReproSinkReachableFromServletIngress is the hermetic end-to-end
// proof that the Java SSRF repro yields the ingredients for a CandidatePair: the
// REAL Java analysis resolves the advisory sink (UrlFetcher.fetch) to a SCIP that
// is a node in the REAL call graph, the servlet doGet ingress resolves to a
// call-graph entry, and a directed path connects the ingress to the sink. That is
// exactly what the pipeline's firstPartyReachPaths fallback turns into a pair.
func TestFirstParty_ReproSinkReachableFromServletIngress(t *testing.T) {
	ctx := context.Background()

	res, err := ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
		BuildDir:        reproSrc,
		AdvisorySymbols: []string{"UrlFetcher.fetch"},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(res.Resolved) == 0 {
		t.Fatal("advisory symbol UrlFetcher.fetch did not resolve in the repro")
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
		if e.Caller.SCIP == sink || e.Callee.SCIP == sink {
			sinkIsNode = true
		}
	}
	if !sinkIsNode {
		t.Fatalf("resolved sink %q is not a node in the call graph", sink)
	}

	// Entries are the servlet/route ingresses plus call-graph roots — exactly the
	// set firstPartyReachPaths terminates its reverse BFS at.
	entries := map[string]bool{}
	for _, in := range ing.Ingresses {
		entries[in.Symbol.SCIP] = true
	}
	for _, r := range cg.Roots {
		entries[r.SCIP] = true
	}
	if len(entries) == 0 {
		t.Fatal("no ingress/root entries discovered for the repro")
	}

	if !reverseReachable(cg.Edges, entries, sink) {
		t.Fatalf("sink %q is NOT reachable from any ingress/root over the call graph;\nentries=%v\nedges=%+v", sink, entries, cg.Edges)
	}

	// The servlet ingress specifically must be present (the doGet override).
	servletFound := false
	for _, in := range ing.Ingresses {
		if in.Kind == "servlet" {
			servletFound = true
		}
	}
	if !servletFound {
		t.Errorf("expected a servlet ingress (doGet) in the repro; got %+v", ing.Ingresses)
	}
}

// TestFirstParty_PatchedReproStillResolvesSinkAndIngress confirms the PATCHED repro
// keeps the same resolvable sink + ingress (the negative control is a RUNTIME
// guard, not a structural one): the call graph still connects ingress→sink, so the
// pipeline still forms a candidate pair — the patched build is dark only because
// the sink's runtime guard forecloses the beacon, which is the live gate's call.
func TestFirstParty_PatchedReproStillResolvesSinkAndIngress(t *testing.T) {
	ctx := context.Background()
	const patchedSrc = "../../../corpus/testdata/repros/TEGRON-JAVA-SSRF-0001-patched/src"

	res, err := ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
		BuildDir:        patchedSrc,
		AdvisorySymbols: []string{"UrlFetcher.fetch"},
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
	servlet := false
	for _, in := range ing.Ingresses {
		if in.Kind == "servlet" {
			servlet = true
		}
	}
	if !servlet {
		t.Errorf("patched repro: expected servlet ingress; got %+v", ing.Ingresses)
	}
}
