// internal/pipeline/firstparty_reach_dotnet_test.go
//
// Hermetic proof that the .NET Assess-parity analysis outputs flow through the SAME
// language-agnostic first-party reachability fallback the Go/Java/JS plugins use. The SCIP
// ids below are the EXACT strings the real dotnetanalysis emitter produces for a .NET SSRF
// repro (ASP.NET [HttpGet] controller action Handle → Fetch utility → OpenConn sink); the
// dotnetanalysis-layer tests (callgraph_test/reachability_test) prove the real analyzer emits
// them, and this test proves reachability_ingress turns them into a CandidatePair via
// firstPartyReachPaths — with NO live model, NO Docker, NO plugin subprocess. The pipeline
// never imports dotnetanalysis (inv.8), so the stub carries the captured outputs across the
// boundary.
//
// Note: unlike the Go/JS plugins, the .NET plugin's own Reachability op IS live (always
// Partial(dynamic_dispatch)); that is proved at the dotnetanalysis layer. This test
// deliberately exercises the pipeline-side call-graph FALLBACK (Reachability Unsupported),
// which is the seam a first-party sink relies on and the language-agnostic path every plugin
// must feed correctly.
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Real dotnetanalysis SCIP ids for the .NET SSRF repro (namespace Acme.Web, type
// FetchController). Byte-identical to funcSCIP / IndexSymbols output: dots in the namespace
// become slashes, the enclosing type is '#'-suffixed, the descriptor is name(arity).
const (
	dotnetHandleSCIP   = "scip-dotnet nuget . . Acme/Web/FetchController#Handle(1)."
	dotnetFetchSCIP    = "scip-dotnet nuget . . Acme/Web/FetchController#Fetch(1)."
	dotnetOpenConnSCIP = "scip-dotnet nuget . . Acme/Web/FetchController#OpenConn(1)."
)

// dotnetFirstPartyStub mimics the live .NET plugin on the SSRF repro: ResolveDependencySymbols
// maps the advisory sink to FetchController.OpenConn; Reachability is Unsupported (so the
// pipeline must use the call-graph fallback — the seam under test); CallGraph emits the
// Handle→Fetch→OpenConn chain with the controller action as a root; FindIngresses reports the
// ASP.NET route ingress. The graph is declared Partial(dynamic_dispatch), exactly as the real
// lexical C# analyzer reports.
type dotnetFirstPartyStub struct {
	plugin.StubPlugin
}

func (dotnetFirstPartyStub) Language() string { return "dotnet" }

func (dotnetFirstPartyStub) ResolveDependencySymbols(_ context.Context, _ plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	return plugin.SymbolResolutionResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Resolved:   []plugin.Symbol{{SCIP: dotnetOpenConnSCIP, DisplayName: "OpenConn(1)", Package: "Acme.Web"}},
	}, nil
}

func (dotnetFirstPartyStub) Reachability(_ context.Context, _ plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	// Exercise the fallback: no paths here, so the candidate path comes from the call graph.
	return plugin.ReachabilityResult{Partiality: plugin.Unsupported()}, nil
}

func (dotnetFirstPartyStub) CallGraph(_ context.Context, _ plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Algorithm:  "source-lexical",
		Edges: []plugin.CallEdge{
			{Caller: plugin.Symbol{SCIP: dotnetHandleSCIP}, Callee: plugin.Symbol{SCIP: dotnetFetchSCIP}},
			{Caller: plugin.Symbol{SCIP: dotnetFetchSCIP}, Callee: plugin.Symbol{SCIP: dotnetOpenConnSCIP}},
		},
		Roots: []plugin.Symbol{{SCIP: dotnetHandleSCIP}},
	}, nil
}

func (dotnetFirstPartyStub) FindIngresses(_ context.Context, _ plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	return plugin.IngressResult{
		Partiality: plugin.Complete(),
		Ingresses:  []plugin.Ingress{{Kind: "http_route", Symbol: plugin.Symbol{SCIP: dotnetHandleSCIP}, Selector: "GET api/Fetch"}},
	}, nil
}

// TestFirstPartyReach_DotNetRouteChainProducesCandidatePair proves the .NET analysis outputs
// produce a CandidatePair through the unchanged firstPartyReachPaths fallback: the ASP.NET
// controller ingress reaches the OpenConn sink over the source call graph, so
// reachability_ingress emits exactly one Partial pair with both legs resolving.
func TestFirstPartyReach_DotNetRouteChainProducesCandidatePair(t *testing.T) {
	store, pairs := runFirstPartyReach(t, dotnetFirstPartyStub{})
	if len(pairs) != 1 {
		t.Fatalf(".NET route chain must yield exactly 1 candidate pair, got %d", len(pairs))
	}
	pair := pairs[0]
	if !pair.Partial {
		t.Errorf(".NET source-lexical reachability must declare Partial=true (structural, not confirmed)")
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

// TestFirstPartyReach_DotNetUnresolvedSinkYieldsNoPair is the inv.5 honesty guard at the
// pipeline layer for .NET: when the call graph does NOT connect the ingress to the resolved
// sink (the analyzer declared the callee unresolved — interface/virtual/DI dispatch — and
// fabricated no edge), the fallback must produce NO pair. .NET reachability is never
// fabricated.
func TestFirstPartyReach_DotNetUnresolvedSinkYieldsNoPair(t *testing.T) {
	_, pairs := runFirstPartyReach(t, dotnetUnresolvedStub{})
	if len(pairs) != 0 {
		t.Fatalf("an unresolved (no-edge) .NET sink must yield NO candidate pair, got %d", len(pairs))
	}
}

// dotnetUnresolvedStub models the honest unresolved case: the analyzer could not resolve the
// call from Fetch to the sink (interface/virtual/DI dispatch / ambiguous overload), so the
// call graph carries NO edge into OpenConn. ResolveDependencySymbols still resolves the sink
// symbol (it exists as a declaration), but it is unreachable over the graph.
type dotnetUnresolvedStub struct{ dotnetFirstPartyStub }

func (dotnetUnresolvedStub) CallGraph(_ context.Context, _ plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Algorithm:  "source-lexical",
		Edges: []plugin.CallEdge{
			{Caller: plugin.Symbol{SCIP: dotnetHandleSCIP}, Callee: plugin.Symbol{SCIP: dotnetFetchSCIP}},
			// No Fetch -> OpenConn edge: the sink is unreachable (not fabricated).
		},
		Roots: []plugin.Symbol{{SCIP: dotnetHandleSCIP}},
	}, nil
}

// TestInventoryDotNetRepro_RoutesToDotNetPlugin is the pipeline-layer reproduce-first proof
// that a .NET vendored_repro (NO go.mod, NO .java/.js, with .cs sources) passes
// codebase_inventory and produces an inventory tagged language="dotnet" so it routes
// downstream to the .NET plugin path. The wired plugin is the .NET first-party stub
// (Language()=="dotnet"), so BuildManifest is invoked on the matching language and returns
// Unsupported (empty fields → omitted), exactly as Assess-parity expects.
func TestInventoryDotNetRepro_RoutesToDotNetPlugin(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-dotnet", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "TEGRON-DOTNET-SSRF-0001", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:     "tegron.corpus/ssrf-dotnet",
			Revision: "v1",
			Acquisition: assessment.Acquisition{
				Mode: "vendored_repro",
				Path: "../checkout/testdata/dotnet-fixture",
			},
		},
	}}
	stage := codebaseInventory{plugin: dotnetFirstPartyStub{}}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("a no-go.mod .NET repro must pass codebase_inventory, got: %v", err)
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
		t.Fatal(".NET inventory must record the resolved BuildDir")
	}
	if inv.Language != "dotnet" {
		t.Fatalf(".NET repro inventory must route to the .NET plugin (language=%q), got %q", "dotnet", inv.Language)
	}
	if inv.Module != "" || inv.GoVersion != "" || inv.BuildCommand != "" {
		t.Fatalf(".NET stub manifest must yield empty fields, got module=%q goVersion=%q buildCommand=%q",
			inv.Module, inv.GoVersion, inv.BuildCommand)
	}
}
