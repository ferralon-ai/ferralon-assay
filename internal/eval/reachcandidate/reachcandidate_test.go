package reachcandidate

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// fakeProgramPlugin is a hermetic stand-in for a real language plugin. It models a fixed
// "program": a set of resolvable symbols (keyed by the EXACT corpus identifier a complete
// corpus would carry, in bare DisplayName form) and a set of sinks reachable from one
// ingress over the call graph. It stubs ONLY the analysis; the harness still drives the REAL
// exported S4/S5 stages, so this test exercises the genuine seed → resolve → reach → tabulate
// path. govulncheck Reachability returns no paths, forcing the first-party call-graph
// fallback (firstPartyReachPaths) — the general reachable-candidate path this eval measures.
type fakeProgramPlugin struct {
	plugin.StubPlugin
	resolvable map[string]plugin.Symbol // corpus identifier → resolved program symbol
	ingress    string                   // ingress SCIP id (call-graph root)
	reachable  map[string]bool          // sink SCIP ids reachable from ingress
}

func (p fakeProgramPlugin) ResolveDependencySymbols(_ context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	var resolved []plugin.Symbol
	for _, s := range req.AdvisorySymbols {
		if sym, ok := p.resolvable[s]; ok {
			resolved = append(resolved, sym)
		}
	}
	return plugin.SymbolResolutionResult{Partiality: plugin.Complete(), Resolved: resolved}, nil
}

func (p fakeProgramPlugin) CallGraph(_ context.Context, _ plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	var edges []plugin.CallEdge
	for sink := range p.reachable {
		edges = append(edges, plugin.CallEdge{Caller: plugin.Symbol{SCIP: p.ingress}, Callee: plugin.Symbol{SCIP: sink}})
	}
	return plugin.CallGraphResult{Partiality: plugin.Complete(), Algorithm: "test", Edges: edges, Roots: []plugin.Symbol{{SCIP: p.ingress}}}, nil
}

func (p fakeProgramPlugin) FindIngresses(_ context.Context, _ plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	return plugin.IngressResult{
		Partiality: plugin.Complete(),
		Ingresses:  []plugin.Ingress{{Kind: "http_route", Symbol: plugin.Symbol{SCIP: p.ingress}, Selector: "GET /"}},
	}, nil
}

func (p fakeProgramPlugin) Reachability(_ context.Context, _ plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	// The first-party blind spot: no govulncheck path → the call-graph fallback runs.
	return plugin.ReachabilityResult{Partiality: plugin.Complete(), Paths: nil}, nil
}

// program models "golang.org/x/text/language" with two funcs: Parse (the vuln sink) and
// Compose (a bystander, reachable but NOT the fix-guarded symbol).
func program() fakeProgramPlugin {
	return fakeProgramPlugin{
		resolvable: map[string]plugin.Symbol{
			"language.Parse":   {SCIP: "scip:xtext#Parse", DisplayName: "language.Parse", Package: "golang.org/x/text/language"},
			"language.Compose": {SCIP: "scip:xtext#Compose", DisplayName: "language.Compose", Package: "golang.org/x/text/language"},
		},
		ingress:   "scip:app#handler",
		reachable: map[string]bool{"scip:xtext#Parse": true, "scip:xtext#Compose": true},
	}
}

func TestRun_RecallAndPrecision(t *testing.T) {
	p := program()
	cases := []Case{
		{ // complete + correct: resolves the real sink, reachable → candidate + correct
			VulnID: "CVE-CORRECT", Symbols: []string{"language.Parse"},
			ExpectedSinks: []string{"language.Parse"}, BuildDir: "/fake",
		},
		{ // silent miss: corpus symbol absent from the program → nothing resolves → no candidate
			VulnID: "CVE-MISSING", Symbols: []string{"language.NoSuchFunc"},
			ExpectedSinks: []string{"language.Parse"}, BuildDir: "/fake",
		},
		{ // over-population: resolves a real-but-wrong sink → candidate forms but sink incorrect
			VulnID: "CVE-WRONGSINK", Symbols: []string{"language.Compose"},
			ExpectedSinks: []string{"language.Parse"}, BuildDir: "/fake",
		},
	}
	rep := Run(context.Background(), p, "hermetic", cases)
	t.Log("\n" + rep.Table())

	byID := map[string]CaseResult{}
	for _, r := range rep.Results {
		if r.Err != nil {
			t.Fatalf("%s: unexpected error: %v", r.VulnID, r.Err)
		}
		byID[r.VulnID] = r
	}

	if !byID["CVE-CORRECT"].CandidatePairFormed || !byID["CVE-CORRECT"].SinkCorrect {
		t.Errorf("CVE-CORRECT: want candidate+correct, got %+v", byID["CVE-CORRECT"])
	}
	if byID["CVE-MISSING"].CandidatePairFormed {
		t.Errorf("CVE-MISSING: want no candidate (silent miss), got formed; resolved=%q", byID["CVE-MISSING"].ResolvedSinkDisplay)
	}
	if !byID["CVE-WRONGSINK"].CandidatePairFormed {
		t.Errorf("CVE-WRONGSINK: want candidate formed, got none")
	}
	if byID["CVE-WRONGSINK"].SinkCorrect {
		t.Errorf("CVE-WRONGSINK: want sink INCORRECT (over-population), got correct")
	}

	// Recall = candidates formed / sink-applicable = 2/3 (CORRECT + WRONGSINK form; MISSING doesn't).
	if got := rep.Recall(); got.Num != 2 || got.Denom != 3 {
		t.Errorf("recall = %s, want 2/3", got)
	}
	// Precision = correct sinks / candidates formed = 1/2 (only CORRECT is right).
	if got := rep.Precision(); got.Num != 1 || got.Denom != 2 {
		t.Errorf("precision = %s, want 1/2", got)
	}
}

// TestDiff_PartialVsComplete proves the before/after primitive downstream features reuse: a
// CVE that dropped under a partial (empty-symbol) corpus surfaces a candidate under the
// complete corpus, with no precision regression.
func TestDiff_PartialVsComplete(t *testing.T) {
	p := program()
	partial := Run(context.Background(), p, "corpus vN (partial)", []Case{
		{VulnID: "CVE-CORRECT", Symbols: nil, ExpectedSinks: []string{"language.Parse"}, BuildDir: "/fake"},
	})
	complete := Run(context.Background(), p, "corpus vN+1 (complete)", []Case{
		{VulnID: "CVE-CORRECT", Symbols: []string{"language.Parse"}, ExpectedSinks: []string{"language.Parse"}, BuildDir: "/fake"},
	})
	d := Diff(partial, complete)
	t.Log("\n" + d.String())

	if rb, ra := d.RecallDelta(); !(rb.Num == 0 && ra.Num == 1) {
		t.Errorf("recall delta = %s → %s, want 0/1 → 1/1", rb, ra)
	}
	if len(d.Transitions) != 1 || !d.Transitions[0].GainedCandidate {
		t.Errorf("want one GainedCandidate transition, got %+v", d.Transitions)
	}
	if d.Regressed() {
		t.Errorf("populate must not regress; diff:\n%s", d.String())
	}
}

// TestSeededAdvisoryShapeMatchesRealS1 is the drift guard: the harness seeds a
// normalized_advisory it hand-builds instead of running S1. This asserts the four fields the
// downstream consumers read (purl, advisory_symbols, advisory_guards, aliases) carry the SAME
// JSON keys the real advisory_intake stage emits — so a future S1 rename breaks this test
// rather than silently zeroing the eval.
func TestSeededAdvisoryShapeMatchesRealS1(t *testing.T) {
	assessments := assessment.NewMemStore()
	store := artifact.NewMemStore()
	a, err := assessments.Create(assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "GO-2021-0113", Source: "osv"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := pipeline.NewAdvisoryIntake().Run(context.Background(), a, store); err != nil {
		t.Fatalf("real S1: %v", err)
	}
	arts, err := store.Query(a.ID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		t.Fatalf("query normalized_advisory: %v (n=%d)", err, len(arts))
	}
	var realKeys map[string]json.RawMessage
	if err := json.Unmarshal(arts[0].Payload, &realKeys); err != nil {
		t.Fatalf("decode real S1 payload: %v", err)
	}

	seededBytes, _ := json.Marshal(seededAdvisory{
		VulnID: "GO-2021-0113", Source: "osv",
		Aliases: []string{"CVE-2021-38561"}, PURL: "pkg:golang/golang.org/x/text",
		AdvisorySymbols: []string{"language.Parse"}, AdvisoryGuards: []string{"guard"},
	})
	var seededKeys map[string]json.RawMessage
	_ = json.Unmarshal(seededBytes, &seededKeys)

	// GO-2021-0113 populates purl/advisory_symbols/aliases, so real S1 must emit those keys
	// (a rename here silently zeroes the eval). advisory_guards is omitempty and this fixture
	// declares no guards, so it is legitimately absent from the REAL payload; we still assert
	// the SEEDED payload carries all four consumer-read keys (advisory_guards' tag is copied
	// verbatim from advisory_intake's struct).
	for _, k := range []string{"purl", "advisory_symbols", "aliases"} {
		if _, ok := realKeys[k]; !ok {
			t.Errorf("real S1 normalized_advisory is missing key %q — the consumer contract moved; update seededAdvisory", k)
		}
	}
	for _, k := range []string{"purl", "advisory_symbols", "advisory_guards", "aliases"} {
		if _, ok := seededKeys[k]; !ok {
			t.Errorf("seededAdvisory is missing key %q the resolver reads", k)
		}
	}
}
