// internal/pipeline/firstparty_reach_python_test.go
//
// Hermetic proof that the Python reachability-slice analysis outputs flow through the SAME
// language-agnostic first-party reachability fallback the Go/Java/JS plugins use. The SCIP
// ids below are the EXACT strings the real pythonanalysis emitter produces for a Flask
// route chain (route handler handle_fetch → handle utility → fetch_url sink); the
// pythonanalysis-layer tests prove the real analyzer emits them and connects them, and
// this test proves reachability_ingress turns them into a CandidatePair via
// firstPartyReachPaths — with NO live model, NO Docker, NO plugin subprocess. The pipeline
// never imports pythonanalysis (inv.8), so the stub carries the captured outputs across the
// boundary.
//
// Python-specific honesty (inv.5): the stub declares CallGraph Partial(dynamic_dispatch)
// and Reachability Unsupported (no paths) — exactly the real Python plugin's shape, where
// reachability is a structurally-weak candidate narrower. The resulting CandidatePair is
// therefore Partial=true: a structural candidate the effect trial must adjudicate, never a
// confirmed verdict.
package pipeline

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Real pythonanalysis SCIP ids for the Flask route chain (module "app"). scipSymbol emits
// "scip-python python . . <module>/<descriptor>"; functionDescriptor appends the arity.
const (
	pyHandleFetchSCIP = "scip-python python . . app/handle_fetch()."
	pyHandleSCIP      = "scip-python python . . app/handle(1)."
	pyFetchURLSCIP    = "scip-python python . . app/fetch_url(1)."
)

// pythonFirstPartyStub mimics the live Python plugin on the Flask route chain:
// ResolveDependencySymbols maps the advisory sink to app.fetch_url; Reachability is
// Unsupported (Python has no govulncheck, and the plugin's own reachability is a Partial
// narrower — the pipeline uses the call-graph fallback for the per-advisory ingress trace);
// CallGraph emits the handle_fetch→handle→fetch_url chain with the route handler as a root;
// FindIngresses reports the Flask route ingress. The call graph is Partial(dynamic_dispatch),
// exactly as the real analyzer reports for any Python source.
type pythonFirstPartyStub struct {
	plugin.StubPlugin
}

func (pythonFirstPartyStub) Language() string { return "python" }

func (pythonFirstPartyStub) ResolveDependencySymbols(_ context.Context, _ plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	return plugin.SymbolResolutionResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Resolved:   []plugin.Symbol{{SCIP: pyFetchURLSCIP, DisplayName: "fetch_url(1)", Package: "app"}},
	}, nil
}

func (pythonFirstPartyStub) Reachability(_ context.Context, _ plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	// The Python plugin's Reachability is a structurally-weak narrower; here it carries no
	// govulncheck-style paths, so the candidate path comes from the call-graph fallback.
	return plugin.ReachabilityResult{Partiality: plugin.Unsupported()}, nil
}

func (pythonFirstPartyStub) CallGraph(_ context.Context, _ plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Algorithm:  "source-lexical",
		Edges: []plugin.CallEdge{
			{Caller: plugin.Symbol{SCIP: pyHandleFetchSCIP}, Callee: plugin.Symbol{SCIP: pyHandleSCIP}},
			{Caller: plugin.Symbol{SCIP: pyHandleSCIP}, Callee: plugin.Symbol{SCIP: pyFetchURLSCIP}},
		},
		Roots: []plugin.Symbol{{SCIP: pyHandleFetchSCIP}},
	}, nil
}

func (pythonFirstPartyStub) FindIngresses(_ context.Context, _ plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	return plugin.IngressResult{
		Partiality: plugin.Complete(),
		Ingresses:  []plugin.Ingress{{Kind: "http_route", Symbol: plugin.Symbol{SCIP: pyHandleFetchSCIP}, Selector: "route"}},
	}, nil
}

// TestFirstPartyReach_PythonRouteChainProducesCandidatePair proves the Python analysis
// outputs produce a CandidatePair through the unchanged firstPartyReachPaths fallback: the
// Flask route handler ingress reaches the fetch_url sink over the source call graph, so
// reachability_ingress emits exactly one Partial pair with both legs resolving.
func TestFirstPartyReach_PythonRouteChainProducesCandidatePair(t *testing.T) {
	store, pairs := runFirstPartyReach(t, pythonFirstPartyStub{})
	if len(pairs) != 1 {
		t.Fatalf("Python route chain must yield exactly 1 candidate pair, got %d", len(pairs))
	}
	pair := pairs[0]
	if !pair.Partial {
		t.Errorf("Python source-lexical reachability must declare Partial=true (structural, not confirmed)")
	}
	if pair.Sink.ID == "" {
		t.Fatal("candidate pair missing sink ref")
	}
	if _, err := store.Get(pair.Sink.ID); err != nil {
		t.Errorf("sink ref does not resolve: %v", err)
	}
	if pair.Ingress == nil {
		t.Fatal("route ingress must attach the Ingress leg")
	}
	if _, err := store.Get(pair.Ingress.ID); err != nil {
		t.Errorf("ingress ref does not resolve: %v", err)
	}
}

// TestFirstPartyReach_PythonUnresolvedSinkYieldsNoPair is the inv.5 honesty guard at the
// pipeline layer for Python: when the call graph does NOT connect the ingress to the
// resolved sink (the analyzer declared the callee unresolved — dynamic dispatch / getattr /
// ambiguous name — and fabricated no edge), the fallback must produce NO pair. Python
// reachability is never fabricated: a missing edge is UNKNOWN, resolved by the effect trial.
func TestFirstPartyReach_PythonUnresolvedSinkYieldsNoPair(t *testing.T) {
	_, pairs := runFirstPartyReach(t, pythonUnresolvedStub{})
	if len(pairs) != 0 {
		t.Fatalf("an unresolved (no-edge) Python sink must yield NO candidate pair, got %d", len(pairs))
	}
}

// pythonUnresolvedStub models the honest unresolved case: the analyzer could not resolve
// the call from the utility to the sink (Python dynamic dispatch), so the call graph
// carries NO edge into the sink. ResolveDependencySymbols still resolves the sink symbol
// (it exists as a declaration), but it is unreachable over the graph.
type pythonUnresolvedStub struct{ pythonFirstPartyStub }

func (pythonUnresolvedStub) CallGraph(_ context.Context, _ plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Algorithm:  "source-lexical",
		Edges: []plugin.CallEdge{
			{Caller: plugin.Symbol{SCIP: pyHandleFetchSCIP}, Callee: plugin.Symbol{SCIP: pyHandleSCIP}},
			// No handle -> fetch_url edge: the sink is unreachable (not fabricated).
		},
		Roots: []plugin.Symbol{{SCIP: pyHandleFetchSCIP}},
	}, nil
}
