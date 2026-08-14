// internal/pipeline/firstparty_reach_js_test.go
//
// Hermetic proof that the JS Increment-1 analysis outputs flow through the SAME
// language-agnostic first-party reachability fallback the Go and Java plugins use. The
// SCIP ids below are the EXACT strings the real jsanalysis emitter produces for the
// TEGRON-JS-SSRF-0001 repro (Express route handler handleFetch → handle utility →
// fetchUrl sink); the jsanalysis-layer test TestFirstParty_ReproSinkReachableFromRouteIngress
// proves the real analyzer emits them, and this test proves reachability_ingress turns
// them into a CandidatePair via firstPartyReachPaths — with NO live model, NO Docker, NO
// plugin subprocess. The pipeline never imports jsanalysis (inv.8), so the stub carries
// the captured outputs across the boundary.
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Real jsanalysis SCIP ids for the JS SSRF repro (see jsanalysis firstparty_test.go).
const (
	jsHandleFetchSCIP = "scip-typescript npm . . app/handleFetch(2)."
	jsHandleSCIP      = "scip-typescript npm . . app/handle(1)."
	jsFetchURLSCIP    = "scip-typescript npm . . fetcher/fetchUrl(1)."
)

// jsFirstPartyStub mimics the live JS plugin on the SSRF repro: ResolveDependencySymbols
// maps the advisory sink to fetcher.fetchUrl; Reachability is Unsupported (JS has no
// govulncheck, so the pipeline must use the call-graph fallback); CallGraph emits the
// handleFetch→handle→fetchUrl chain with the route handler as a root; FindIngresses
// reports the Express route ingress. The result is declared partial (dynamic_dispatch),
// exactly as the real analyzer reports for import/library-call-bearing JS.
type jsFirstPartyStub struct {
	plugin.StubPlugin
}

func (jsFirstPartyStub) Language() string { return "js" }

func (jsFirstPartyStub) ResolveDependencySymbols(_ context.Context, _ plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	return plugin.SymbolResolutionResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Resolved:   []plugin.Symbol{{SCIP: jsFetchURLSCIP, DisplayName: "fetchUrl(1)", Package: "fetcher"}},
	}, nil
}

func (jsFirstPartyStub) Reachability(_ context.Context, _ plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	// JS Increment 1 leaves Reachability Unsupported: there is no govulncheck for JS, so
	// the candidate path comes from the call-graph fallback. Unsupported carries no paths.
	return plugin.ReachabilityResult{Partiality: plugin.Unsupported()}, nil
}

func (jsFirstPartyStub) CallGraph(_ context.Context, _ plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Algorithm:  "source-lexical",
		Edges: []plugin.CallEdge{
			{Caller: plugin.Symbol{SCIP: jsHandleFetchSCIP}, Callee: plugin.Symbol{SCIP: jsHandleSCIP}},
			{Caller: plugin.Symbol{SCIP: jsHandleSCIP}, Callee: plugin.Symbol{SCIP: jsFetchURLSCIP}},
		},
		Roots: []plugin.Symbol{{SCIP: jsHandleFetchSCIP}},
	}, nil
}

func (jsFirstPartyStub) FindIngresses(_ context.Context, _ plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	return plugin.IngressResult{
		Partiality: plugin.Complete(),
		Ingresses:  []plugin.Ingress{{Kind: "http_route", Symbol: plugin.Symbol{SCIP: jsHandleFetchSCIP}}},
	}, nil
}

// TestFirstPartyReach_JSRouteChainProducesCandidatePair proves the JS analysis outputs
// produce a CandidatePair through the unchanged firstPartyReachPaths fallback: the
// Express route handler ingress reaches the fetchUrl sink over the source call graph, so
// reachability_ingress emits exactly one Partial pair with both legs resolving — the
// ingredient live_confirmation drives to a reasoned model call, and (live) to a proven
// verdict only on a real canary observation.
func TestFirstPartyReach_JSRouteChainProducesCandidatePair(t *testing.T) {
	store, pairs := runFirstPartyReach(t, jsFirstPartyStub{})
	if len(pairs) != 1 {
		t.Fatalf("JS route chain must yield exactly 1 candidate pair, got %d", len(pairs))
	}
	pair := pairs[0]
	if !pair.Partial {
		t.Errorf("JS source-lexical reachability must declare Partial=true (structural, not confirmed)")
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

// TestFirstPartyReach_JSUnresolvedSinkYieldsNoPair is the inv.5 honesty guard at the
// pipeline layer for JS: when the call graph does NOT connect the ingress to the resolved
// sink (the analyzer declared the callee unresolved and fabricated no edge), the fallback
// must produce NO pair — JS reachability is never fabricated. This is the pipeline-side
// mirror of the analyzer's "ambiguous/unknown callee does not fabricate an edge"
// guarantee.
func TestFirstPartyReach_JSUnresolvedSinkYieldsNoPair(t *testing.T) {
	_, pairs := runFirstPartyReach(t, jsUnresolvedStub{})
	if len(pairs) != 0 {
		t.Fatalf("an unresolved (no-edge) JS sink must yield NO candidate pair, got %d", len(pairs))
	}
}

// jsUnresolvedStub models the honest unresolved case: the analyzer could not resolve the
// call from the utility to the sink (prototype/dynamic dispatch / ambiguous name), so the
// call graph carries NO edge into the sink. ResolveDependencySymbols still resolves the
// sink symbol (it exists as a declaration), but it is unreachable over the graph.
type jsUnresolvedStub struct{ jsFirstPartyStub }

func (jsUnresolvedStub) CallGraph(_ context.Context, _ plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{
		// dynamic_dispatch: the callee from handle was unresolved, so NO edge to fetchUrl.
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Algorithm:  "source-lexical",
		Edges: []plugin.CallEdge{
			{Caller: plugin.Symbol{SCIP: jsHandleFetchSCIP}, Callee: plugin.Symbol{SCIP: jsHandleSCIP}},
			// No handle -> fetchUrl edge: the sink is unreachable (not fabricated).
		},
		Roots: []plugin.Symbol{{SCIP: jsHandleFetchSCIP}},
	}, nil
}

// TestInventoryJSRepro_NoGoModRoutesToJSPlugin is the pipeline-layer reproduce-first proof
// that a JS vendored_repro (NO go.mod, NO .java, with .js sources) passes codebase_inventory
// and produces an inventory tagged language="js" so it routes downstream to the JS plugin
// path. The wired plugin is the JS first-party stub (Language()=="js"), so BuildManifest is
// invoked on the matching language and returns Unsupported (empty fields → omitted), exactly
// as Increment-1 expects.
func TestInventoryJSRepro_NoGoModRoutesToJSPlugin(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-js", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "TEGRON-JS-SSRF-0001", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:     "tegron.corpus/ssrf-js",
			Revision: "v1",
			Acquisition: assessment.Acquisition{
				Mode: "vendored_repro",
				Path: "../checkout/testdata/js-fixture",
			},
		},
	}}
	stage := codebaseInventory{plugin: jsFirstPartyStub{}}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("a no-go.mod JS repro must pass codebase_inventory, got: %v", err)
	}
	arts, _ := store.Query(c.ID, artifact.TypeInventory)
	if len(arts) == 0 {
		t.Fatal("no inventory artifact")
	}
	var inv struct {
		BuildDir     string `json:"build_dir"`
		Language     string `json:"language"`
		Module       string `json:"module"`
		GoVersion    string `json:"go_version"`
		BuildCommand string `json:"build_command"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		t.Fatalf("inventory artifact must decode: %v", err)
	}
	if inv.BuildDir == "" {
		t.Fatal("JS inventory must record the resolved BuildDir")
	}
	if inv.Language != "js" {
		t.Fatalf("JS repro inventory must route to the JS plugin (language=%q), got %q", "js", inv.Language)
	}
	if inv.Module != "" || inv.GoVersion != "" || inv.BuildCommand != "" {
		t.Fatalf("JS stub manifest must yield empty fields, got module=%q goVersion=%q buildCommand=%q",
			inv.Module, inv.GoVersion, inv.BuildCommand)
	}
}
