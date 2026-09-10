// internal/pipeline/firstparty_reach_test.go
//
// Hermetic tests for first-party-sink reachability. govulncheck (the plugin
// Reachability op) only traces KNOWN dependency advisories, so a FIRST-PARTY advisory — a sink in
// the app's own code, e.g. main.fetchHandler — yields ZERO govulncheck paths even though the sink is
// reachable over the static call graph. Before this fix that produced no CandidatePair, so
// live_confirmation skipped the model and the verdict defaulted to reasoned_not_exploitable.
//
// These tests drive reachability_ingress with a stub plugin that mimics that exact shape (empty
// Reachability, populated CallGraph + FindIngresses) and assert the call-graph fallback now produces
// a CandidatePair (ingress→sink). The pair is declared Partial=true: it asserts only STRUCTURAL
// reachability, never proof — inv.5 holds because the pair flows into the reasoned model call and
// only a real sandbox observation can set StrengthProven.
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// firstPartyStubPlugin mimics the live Go plugin's behavior on a FIRST-PARTY advisory: the dependency
// symbol resolver maps the advisory symbol to a sink in the app's own (main) package, govulncheck
// Reachability returns NO paths (it has no entry for a first-party advisory), but the CallGraph and
// FindIngresses ops resolve fully — the ingredients the call-graph fallback consumes.
type firstPartyStubPlugin struct {
	plugin.StubPlugin
	// sink is the resolved first-party sink SCIP. ingress reaches it over the call graph.
	sink    string
	ingress string
	// ingressKind controls whether the ingress is reported by FindIngresses (so the
	// Ingress leg attaches) or only as a bare call-graph root (nil Ingress leg).
	ingressIsKnown bool
}

func (p firstPartyStubPlugin) ResolveDependencySymbols(_ context.Context, _ plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	return plugin.SymbolResolutionResult{
		Partiality: plugin.Complete(),
		Resolved:   []plugin.Symbol{{SCIP: p.sink, DisplayName: "main.fetchHandler", Package: "tegron.corpus/app"}},
	}, nil
}

func (p firstPartyStubPlugin) Reachability(_ context.Context, _ plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	// The first-party blind spot: govulncheck knows no advisory for this symbol → zero paths.
	return plugin.ReachabilityResult{Partiality: plugin.Complete(), Paths: nil}, nil
}

func (p firstPartyStubPlugin) CallGraph(_ context.Context, _ plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{
		Partiality: plugin.Complete(),
		Algorithm:  "vta",
		Edges:      []plugin.CallEdge{{Caller: plugin.Symbol{SCIP: p.ingress}, Callee: plugin.Symbol{SCIP: p.sink}}},
		Roots:      []plugin.Symbol{{SCIP: p.ingress}},
	}, nil
}

func (p firstPartyStubPlugin) FindIngresses(_ context.Context, _ plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	if !p.ingressIsKnown {
		return plugin.IngressResult{Partiality: plugin.Complete()}, nil
	}
	return plugin.IngressResult{
		Partiality: plugin.Complete(),
		Ingresses:  []plugin.Ingress{{Kind: "http_route", Symbol: plugin.Symbol{SCIP: p.ingress}, Selector: "GET /fetch"}},
	}, nil
}

// runFirstPartyReach drives symbol_mapping + reachability_ingress with the given stub and returns
// the resulting candidate pairs.
func runFirstPartyReach(t *testing.T, p plugin.LanguagePlugin) (artifact.Store, []artifact.CandidatePair) {
	t.Helper()
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-fp"}
	c.Request.Vulnerability = assessment.VulnRef{ID: "FERRALON-APP-SSRF-0001", Source: "osv"}

	if err := (symbolMapping{plugin: p}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("symbol_mapping: %v", err)
	}
	if err := (reachabilityIngress{plugin: p}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("reachability_ingress: %v", err)
	}
	pairArts, err := store.Query(c.ID, artifact.TypeCandidatePair)
	if err != nil {
		t.Fatalf("query candidate_pair: %v", err)
	}
	var pairs []artifact.CandidatePair
	for _, a := range pairArts {
		var pair artifact.CandidatePair
		if err := json.Unmarshal(a.Payload, &pair); err != nil {
			t.Fatalf("decode candidate_pair: %v", err)
		}
		pairs = append(pairs, pair)
	}
	return store, pairs
}

// TestFirstPartyReach_BuildsPairFromCallGraphWhenGovulncheckBlind is the core fix: with empty
// govulncheck Reachability but a known first-party sink reachable over the call graph from a known
// ingress, reachability_ingress must produce exactly one CandidatePair (ingress→sink), declared
// Partial, with both legs resolving — NOT skip straight to no-pair (the old reasoned_not_exploitable
// false-negative).
func TestFirstPartyReach_BuildsPairFromCallGraphWhenGovulncheckBlind(t *testing.T) {
	p := firstPartyStubPlugin{
		sink:           "scip-go gomod tegron.corpus/app . tegron.corpus/app/fetchHandler().",
		ingress:        "scip-go gomod tegron.corpus/app . tegron.corpus/app/fetchHandler().",
		ingressIsKnown: true,
	}
	store, pairs := runFirstPartyReach(t, p)

	if len(pairs) != 1 {
		t.Fatalf("first-party govulncheck-blind advisory must yield 1 candidate pair, got %d", len(pairs))
	}
	pair := pairs[0]
	if !pair.Partial {
		t.Errorf("first-party call-graph reachability must declare Partial=true (structural, not govulncheck-confirmed)")
	}
	if pair.Sink.ID == "" {
		t.Errorf("candidate pair missing sink ref")
	}
	if _, err := store.Get(pair.Sink.ID); err != nil {
		t.Errorf("sink ref does not resolve: %v", err)
	}
	if pair.Ingress == nil {
		t.Fatal("known ingress must attach the Ingress leg")
	}
	if _, err := store.Get(pair.Ingress.ID); err != nil {
		t.Errorf("ingress ref does not resolve: %v", err)
	}
}

// TestFirstPartyReach_NoKnownIngressStillPairsViaRoot proves that when the entry node is a
// call-graph root (main/init) but NOT a framework ingress, the fallback still produces a pair with a
// nil Ingress leg (declared partiality) rather than dropping the candidate.
func TestFirstPartyReach_NoKnownIngressStillPairsViaRoot(t *testing.T) {
	p := firstPartyStubPlugin{
		sink:           "scip-go gomod tegron.corpus/app . tegron.corpus/app/expandHandler().",
		ingress:        "scip-go gomod tegron.corpus/app . tegron.corpus/app/main().",
		ingressIsKnown: false, // root only, no FindIngresses entry
	}
	_, pairs := runFirstPartyReach(t, p)
	if len(pairs) != 1 {
		t.Fatalf("root-anchored first-party path must yield 1 candidate pair, got %d", len(pairs))
	}
	if pairs[0].Ingress != nil {
		t.Errorf("a root-only (no framework ingress) path must leave the Ingress leg nil (declared partiality)")
	}
	if !pairs[0].Partial {
		t.Errorf("first-party call-graph reachability must declare Partial=true")
	}
}

// TestFirstPartyReach_UnreachableSinkYieldsNoPair is the soundness guard: if the resolved sink is NOT
// reachable over the call graph (no path to any entry), the fallback must produce NO pair — it never
// fabricates reachability. This keeps the honest no-candidate-pair → reasoned_not_exploitable path
// for a genuinely unreachable first-party sink (inv.5: no overclaim).
func TestFirstPartyReach_UnreachableSinkYieldsNoPair(t *testing.T) {
	p := firstPartyStubPlugin{
		// The call graph (ingress→someOtherSink) does NOT reach this sink.
		sink:           "scip-go gomod tegron.corpus/app . tegron.corpus/app/unreachableSink().",
		ingress:        "scip-go gomod tegron.corpus/app . tegron.corpus/app/main().",
		ingressIsKnown: false,
	}
	// Override CallGraph to an edge that does not touch the sink.
	p2 := disconnectedFirstPartyStub{firstPartyStubPlugin: p}
	_, pairs := runFirstPartyReach(t, p2)
	if len(pairs) != 0 {
		t.Fatalf("an unreachable first-party sink must yield NO candidate pair (no fabricated reachability), got %d", len(pairs))
	}
}

// disconnectedFirstPartyStub returns a call graph whose only edge does not reach the resolved sink.
type disconnectedFirstPartyStub struct{ firstPartyStubPlugin }

func (p disconnectedFirstPartyStub) CallGraph(_ context.Context, _ plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{
		Partiality: plugin.Complete(),
		Algorithm:  "vta",
		Edges:      []plugin.CallEdge{{Caller: plugin.Symbol{SCIP: p.ingress}, Callee: plugin.Symbol{SCIP: "scip-go gomod tegron.corpus/app . tegron.corpus/app/otherFn()."}}},
		Roots:      []plugin.Symbol{{SCIP: p.ingress}},
	}, nil
}

// TestFirstPartyReach_PersistsResolvedPathForReportBuilder is the entry-point-attribution
// regression at the persistence boundary: reachability_ingress must persist the RESOLVED reach path — the
// first-party fallback's advisory-specific ingress + ingress→sink trace — into the
// TypeReachability artifact the report builder reads. Persisting the raw govulncheck reach
// (empty for a first-party sink) drops that ingress, which forces the report builder onto a
// positional pick from the shared, sorted ingress map and collapses every advisory's entry
// point onto whichever ingress sorts first (the SSRF→expandHandler mis-attribution).
func TestFirstPartyReach_PersistsResolvedPathForReportBuilder(t *testing.T) {
	p := firstPartyStubPlugin{
		sink:           "scip-go gomod tegron.corpus/app . tegron.corpus/app/fetchHandler().",
		ingress:        "scip-go gomod tegron.corpus/app . tegron.corpus/app/fetchHandler().",
		ingressIsKnown: true,
	}
	store, _ := runFirstPartyReach(t, p)

	arts, err := store.Query("case-fp", artifact.TypeReachability)
	if err != nil || len(arts) == 0 {
		t.Fatalf("no reachability artifact persisted: %v", err)
	}
	var payload struct {
		Reachability plugin.ReachabilityResult `json:"reachability"`
	}
	if err := json.Unmarshal(arts[0].Payload, &payload); err != nil {
		t.Fatalf("decode reachability: %v", err)
	}
	if len(payload.Reachability.Paths) != 1 {
		t.Fatalf("reachability artifact must carry the resolved first-party path, got %d paths (the dropped-ingress regression)", len(payload.Reachability.Paths))
	}
	if got := payload.Reachability.Paths[0].Ingress; got.SCIP != p.ingress {
		t.Errorf("persisted ReachPath.Ingress = %q, want the advisory-specific reaching ingress %q", got.SCIP, p.ingress)
	}
	if got := payload.Reachability.Paths[0].Sink; got.SCIP != p.sink {
		t.Errorf("persisted ReachPath.Sink = %q, want %q", got.SCIP, p.sink)
	}
}

// The full-pipeline inv.5 regression for the first-party path
// (TestFirstPartyReach_CandidatePairNeverProvesViaModelSelfReport) lives Service-side in the prove
// composition (service/internal/pipeline), since it drives DefaultStagesWith (S1–S10) to a verdict.
