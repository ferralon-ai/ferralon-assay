package javaanalysis

import (
	"context"
	"os"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// reproSpringSrc is the source root of the vendored Spring SSRF repro, the source
// the REAL pure-Go emitter (symbol_mapping, FindIngresses, lexical CallGraph) runs
// over. The committed real-scip-java index was emitted by scip-java over THIS tree,
// so the two id sources describe the same physical methods.
const reproSpringSrc = "../../../corpus/testdata/repros/TEGRON-JAVA-SPRING-SSRF-0001-vulnerable/src"

// TestSpringSSRF_AdvisoryToReachability_FullChain is the missing INTEGRATION test
// for TEGRON-JAVA-SPRING-SSRF-0001. It exercises the real advisory →
// symbol_mapping → reachability chain hermetically (no container): the sink id is
// the one ResolveDependencySymbols (symbol_mapping) actually produces from the
// advisory-named symbol, the resolved interface→impl graph is derived from the
// committed real scip-java index, and the two are joined through the SAME merge +
// arity reconciliation the live CallGraph applies. It then asserts the pipeline's
// firstPartyReachPaths property — the symbol_mapping sink is reverse-reachable from
// the @GetMapping ingress over the merged graph — i.e. a CandidatePair forms.
//
// This is the test the suite was missing: the previous canonicalization test pinned
// the resolved id against a HAND-FORCED arity-0 sink in isolation, so it never
// exercised the real path where symbol_mapping resolves the sink at its TRUE arity
// (fetch(1).) while scip-java erases parameters to fetch(). — the id-space mismatch
// that left the live verdict not_exploitable/reasoned with no pair. Without
// reconcileResolvedArity this test fails (sink not reachable); with it, it passes.
func TestSpringSSRF_AdvisoryToReachability_FullChain(t *testing.T) {
	ctx := context.Background()

	// (a) symbol_mapping: resolve the advisory's named first-party symbol to a sink
	// SCIP — exactly what stage symbol_mapping does via ResolveDependencySymbols.
	res, err := ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
		BuildDir:        reproSpringSrc,
		AdvisorySymbols: []string{"com.example.web.UrlServiceImpl.fetch"},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(res.Resolved) == 0 {
		t.Fatal("advisory symbol UrlServiceImpl.fetch did not resolve")
	}
	sink := res.Resolved[0].SCIP // the id the pipeline targets as the sink

	// (b) the merged lexical+resolved call graph, derived as the live CallGraph does
	// (without the container): lexical baseline + the resolved interface→impl edges
	// from the committed real scip-java index, joined through the same merge +
	// arity-reconciliation seam scipJavaResolve's result flows through.
	prog, err := loadProgram(reproSpringSrc)
	if err != nil {
		t.Fatalf("loadProgram: %v", err)
	}
	lexical, err := CallGraph(t.Context(), plugin.CallGraphRequest{BuildDir: reproSpringSrc}) // gate unset ⇒ pure-Go lexical
	if err != nil {
		t.Fatalf("CallGraph (lexical): %v", err)
	}
	data, err := os.ReadFile(springIndexFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := readSCIPIndex(data)
	if err != nil {
		t.Fatalf("readSCIPIndex: %v", err)
	}
	g = reconcileResolvedArity(prog, g)
	merged := mergeResolvedCallGraph(lexical, g)

	// (c) ingresses (the @GetMapping route), merged into the resolved id space the
	// same way FindIngresses does.
	ingSet := map[string]bool{}
	for _, in := range g.ingresses {
		if in.Symbol != "" {
			ingSet[in.Symbol] = true
		}
	}
	for _, r := range merged.Roots {
		ingSet[r] = true
	}
	if len(ingSet) == 0 {
		t.Fatal("no ingress/root entries for the Spring repro")
	}

	// The sink the pipeline targets must be a node in the merged graph (the id-
	// EQUALITY the bug violated: symbol_mapping's fetch(1). vs scip-java's fetch().).
	sinkIsNode := false
	for _, e := range merged.Edges {
		if e.Caller == sink || e.Callee == sink {
			sinkIsNode = true
		}
	}
	if !sinkIsNode {
		t.Fatalf("symbol_mapping sink %q is not a node in the merged graph — id-space mismatch (arity erasure) reproduced; edges=%+v", sink, merged.Edges)
	}

	// The reachability property firstPartyReachPaths turns into a CandidatePair: the
	// resolved sink is reverse-reachable from the @GetMapping ingress over the merged
	// graph (ingress → FetchController.fetch → UrlService#fetch → UrlServiceImpl#fetch).
	if !reverseReachable(merged.Edges, ingSet, sink) {
		t.Fatalf("CandidatePair broken: sink %q NOT reachable from any ingress/root over the merged graph;\nentries=%v\nedges=%+v", sink, ingSet, merged.Edges)
	}

	// Pin the specific resolved interface→impl hop in the TRUE-arity id space, so a
	// regression in the arity reconciliation (not just any path) is caught.
	wantIfaceArity1 := scipSymbol("com.example.web", []string{"UrlService"}, methodDescriptor("fetch", 1))
	wantImplArity1 := scipSymbol("com.example.web", []string{"UrlServiceImpl"}, methodDescriptor("fetch", 1))
	if wantImplArity1 != sink {
		t.Fatalf("expected reconciled impl id %q to equal symbol_mapping sink %q", wantImplArity1, sink)
	}
	hasEdge := false
	for _, e := range merged.Edges {
		if e.Caller == wantIfaceArity1 && e.Callee == wantImplArity1 {
			hasEdge = true
		}
	}
	if !hasEdge {
		t.Errorf("missing reconciled interface→impl edge %q → %q in merged graph", wantIfaceArity1, wantImplArity1)
	}
}
