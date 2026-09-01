package javaanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// springReproSrc is the source root of the vendored Spring SSRF repro (Maven
// layout). The pure-Go lexical analyzer runs over it WITHOUT the analyzer
// container (the gate is unset in these hermetic tests).
const springReproSrc = "../../../corpus/testdata/repros/TEGRON-JAVA-SPRING-SSRF-0001-vulnerable/src/main/java"

// TestSpringRepro_BeanGraphBridgesDispatch proves the DI bean model closes the exact
// verdict gap this repro was built to demonstrate — on the Assess path, with the Prove
// container gate UNSET. FetchController's @Autowired UrlService field resolves to the
// unique concrete UrlServiceImpl (the sole first-party impl and the sole concrete
// fetch/1), so the bean graph emits the resolved FetchController.fetch →
// UrlServiceImpl.fetch edge and the @RestController ingress now reaches the SSRF sink
// with no analyzer container. (This supersedes the former honesty control that asserted
// the pure-Go pass could NOT bridge the hop — that limitation is what the cycle removed.)
//
// The retirement is PER-KEY and honest: the graph still declares Partial(dynamic_dispatch)
// because other, genuinely-unresolvable library calls (java.net.* and the stub helpers)
// remain unresolved. The bean hop is bridged; the residual is not silently retired.
func TestSpringRepro_BeanGraphBridgesDispatch(t *testing.T) {
	t.Setenv(scipAnalyzerImageEnv, "") // gate closed: pure-Go Assess path only.
	ctx := t.Context()

	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: springReproSrc})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if cg.Algorithm != "source-lexical" {
		t.Fatalf("gate unset: Algorithm=%q, want source-lexical", cg.Algorithm)
	}

	// dynamic_dispatch remains for the residual library calls the bean graph does not
	// (and must not) resolve — per-key retirement keeps the graph honest.
	hasDispatch := false
	for _, r := range cg.Partiality.Reasons {
		if r == plugin.PartialReasonDynamicDispatch {
			hasDispatch = true
		}
	}
	if !hasDispatch {
		t.Errorf("Spring graph: reasons=%v, want dynamic_dispatch to survive for the residual library calls", cg.Partiality.Reasons)
	}

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

	// The bean graph bridged the interface hop: the ingress now reaches the sink.
	if !reverseReachable(cg.Edges, entries, sink) {
		t.Fatalf("bean graph did NOT bridge the interface dispatch; ingress→%q must now be reachable on the Assess path.\nentries=%v\nedges=%+v", sink, entries, cg.Edges)
	}
}
