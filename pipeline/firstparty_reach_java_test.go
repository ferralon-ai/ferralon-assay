// internal/pipeline/firstparty_reach_java_test.go
//
// Hermetic proof that the Java Increment-1 analysis outputs flow through the SAME language-agnostic
// first-party reachability fallback the Go plugin uses. The SCIP ids below are the EXACT strings the
// real javaanalysis emitter produces for the TEGRON-JAVA-SSRF-0001 repro (servlet doGet ingress →
// handle utility → UrlFetcher.fetch sink); the javaanalysis-layer test
// TestFirstParty_ReproSinkReachableFromServletIngress proves the real analyzer emits them, and this
// test proves reachability_ingress turns them into a CandidatePair via firstPartyReachPaths — with
// NO live model, NO Docker, NO plugin subprocess. The pipeline never imports javaanalysis (inv.8), so
// the stub carries the captured outputs across the boundary.
package pipeline

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Real javaanalysis SCIP ids for the Java SSRF repro (see firstparty_test.go output).
const (
	javaDoGetSCIP  = "scip-java maven . . com/example/web/FetchServlet#doGet(2)."
	javaHandleSCIP = "scip-java maven . . com/example/web/FetchServlet#handle(1)."
	javaFetchSCIP  = "scip-java maven . . com/example/web/UrlFetcher#fetch(1)."
)

// javaFirstPartyStub mimics the live Java plugin on the SSRF repro: ResolveDependencySymbols maps the
// advisory sink to UrlFetcher.fetch; Reachability is Unsupported (Java has no govulncheck, so the
// pipeline must use the call-graph fallback); CallGraph emits the doGet→handle→fetch chain with the
// servlet doGet as a root; FindIngresses reports the servlet ingress. The result is declared partial
// (dynamic_dispatch), exactly as the real analyzer reports for library-call-bearing Java.
type javaFirstPartyStub struct {
	plugin.StubPlugin
}

func (javaFirstPartyStub) Language() string { return "java" }

func (javaFirstPartyStub) ResolveDependencySymbols(_ context.Context, _ plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	return plugin.SymbolResolutionResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Resolved:   []plugin.Symbol{{SCIP: javaFetchSCIP, DisplayName: "UrlFetcher.fetch(1)", Package: "com.example.web"}},
	}, nil
}

func (javaFirstPartyStub) Reachability(_ context.Context, _ plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	// Java Increment 1 leaves Reachability Unsupported: there is no govulncheck for Java, so the
	// candidate path comes from the call-graph fallback. Unsupported carries no paths.
	return plugin.ReachabilityResult{Partiality: plugin.Unsupported()}, nil
}

func (javaFirstPartyStub) CallGraph(_ context.Context, _ plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Algorithm:  "source-lexical",
		Edges: []plugin.CallEdge{
			{Caller: plugin.Symbol{SCIP: javaDoGetSCIP}, Callee: plugin.Symbol{SCIP: javaHandleSCIP}},
			{Caller: plugin.Symbol{SCIP: javaHandleSCIP}, Callee: plugin.Symbol{SCIP: javaFetchSCIP}},
		},
		Roots: []plugin.Symbol{{SCIP: javaDoGetSCIP}},
	}, nil
}

func (javaFirstPartyStub) FindIngresses(_ context.Context, _ plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	return plugin.IngressResult{
		Partiality: plugin.Complete(),
		Ingresses:  []plugin.Ingress{{Kind: "servlet", Symbol: plugin.Symbol{SCIP: javaDoGetSCIP}}},
	}, nil
}

// TestFirstPartyReach_JavaServletChainProducesCandidatePair proves the Java analysis outputs produce a
// CandidatePair through the unchanged firstPartyReachPaths fallback: the servlet doGet ingress reaches
// the UrlFetcher.fetch sink over the source call graph, so reachability_ingress emits exactly one
// Partial pair with both legs resolving — the ingredient live_confirmation drives to a reasoned model
// call, and (live) to a proven verdict only on a real canary observation.
func TestFirstPartyReach_JavaServletChainProducesCandidatePair(t *testing.T) {
	store, pairs := runFirstPartyReach(t, javaFirstPartyStub{})
	if len(pairs) != 1 {
		t.Fatalf("Java servlet chain must yield exactly 1 candidate pair, got %d", len(pairs))
	}
	pair := pairs[0]
	if !pair.Partial {
		t.Errorf("Java source-lexical reachability must declare Partial=true (structural, not confirmed)")
	}
	if pair.Sink.ID == "" {
		t.Fatal("candidate pair missing sink ref")
	}
	if _, err := store.Get(pair.Sink.ID); err != nil {
		t.Errorf("sink ref does not resolve: %v", err)
	}
	if pair.Ingress == nil {
		t.Fatal("servlet ingress must attach the Ingress leg")
	}
	if _, err := store.Get(pair.Ingress.ID); err != nil {
		t.Errorf("ingress ref does not resolve: %v", err)
	}
}

// TestFirstPartyReach_JavaUnresolvedSinkYieldsNoPair is the inv.5 honesty guard at the pipeline layer
// for Java: when the call graph does NOT connect the ingress to the resolved sink (the analyzer
// declared the callee unresolved and fabricated no edge), the fallback must produce NO pair — Java
// reachability is never fabricated. This is the pipeline-side mirror of the analyzer's
// "ambiguous/unknown callee does not fabricate an edge" guarantee.
func TestFirstPartyReach_JavaUnresolvedSinkYieldsNoPair(t *testing.T) {
	_, pairs := runFirstPartyReach(t, javaUnresolvedStub{})
	if len(pairs) != 0 {
		t.Fatalf("an unresolved (no-edge) Java sink must yield NO candidate pair, got %d", len(pairs))
	}
}

// javaUnresolvedStub models the honest unresolved case: the analyzer could not resolve the call from
// the ingress to the sink (interface dispatch / ambiguous overload), so the call graph carries NO
// edge into the sink. ResolveDependencySymbols still resolves the sink symbol (it exists as a
// declaration), but it is unreachable over the (edge-less toward it) graph.
type javaUnresolvedStub struct{ javaFirstPartyStub }

func (javaUnresolvedStub) CallGraph(_ context.Context, _ plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{
		// dynamic_dispatch: the callee from handle was unresolved, so NO edge to fetch exists.
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Algorithm:  "source-lexical",
		Edges: []plugin.CallEdge{
			{Caller: plugin.Symbol{SCIP: javaDoGetSCIP}, Callee: plugin.Symbol{SCIP: javaHandleSCIP}},
			// No handle -> fetch edge: the sink is unreachable (not fabricated).
		},
		Roots: []plugin.Symbol{{SCIP: javaDoGetSCIP}},
	}, nil
}
