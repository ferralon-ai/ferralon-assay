package javaanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// springReproSrc is the source root of the vendored Spring SSRF repro (Maven
// layout). The pure-Go lexical analyzer runs over it WITHOUT the analyzer
// container (the gate is unset in these hermetic tests).
const springReproSrc = "../../../corpus/testdata/repros/TEGRON-JAVA-SPRING-SSRF-0001-vulnerable/src/main/java"

// TestSpringRepro_LexicalDynamicDispatch is the honesty CONTROL: with the Prove
// gate UNSET, the pure-Go lexical call graph over the Spring repro declares
// Partial(dynamic_dispatch) AND fails to connect the @RestController ingress to
// the concrete UrlServiceImpl.fetch sink — because svc.fetch keys to fetch/1
// matching BOTH UrlService.fetch and UrlServiceImpl.fetch, so no edge is
// fabricated (inv.5). This is the verdict gap Increment 3's container resolves;
// the lexical pass must NOT silently bridge it.
func TestSpringRepro_LexicalDynamicDispatch(t *testing.T) {
	t.Setenv(scipAnalyzerImageEnv, "") // gate closed: pure-Go only.
	ctx := t.Context()

	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: springReproSrc})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if cg.Algorithm != "source-lexical" {
		t.Fatalf("gate unset: Algorithm=%q, want source-lexical", cg.Algorithm)
	}

	// The dispatch ambiguity must be declared, not bridged.
	hasDispatch := false
	for _, r := range cg.Partiality.Reasons {
		if r == plugin.PartialReasonDynamicDispatch {
			hasDispatch = true
		}
	}
	if !hasDispatch {
		t.Errorf("lexical Spring graph: reasons=%v, want dynamic_dispatch (the interface hop)", cg.Partiality.Reasons)
	}

	// Resolve the sink and confirm it is NOT reachable from any ingress/root over
	// the lexical graph — the broken interface hop means no candidate path.
	res, err := ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
		BuildDir:        springReproSrc,
		AdvisorySymbols: []string{"UrlServiceImpl.fetch"},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(res.Resolved) == 0 {
		t.Fatal("advisory sink UrlServiceImpl.fetch did not resolve in the Spring repro")
	}
	sink := res.Resolved[0].SCIP

	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: springReproSrc})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	entries := map[string]bool{}
	for _, in := range ing.Ingresses {
		entries[in.Symbol.SCIP] = true
	}
	for _, r := range cg.Roots {
		entries[r.SCIP] = true
	}

	if reverseReachable(cg.Edges, entries, sink) {
		t.Fatalf("lexical pass UNSOUNDLY connected ingress→%q across the interface dispatch; it must declare dynamic_dispatch and leave the hop unbridged.\nentries=%v\nedges=%+v", sink, entries, cg.Edges)
	}
}
