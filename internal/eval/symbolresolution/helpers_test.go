package symbolresolution

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/internal/eval/reachcandidate"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// fakeRunner is a deterministic CaseRunner for the hermetic suite: it returns a preconfigured
// CaseResult per advisory id (keyed by fix.Advisory.ID), defaulting to dflt. It records call
// order so a test can assert step 5 ran ONLY for the buildable subset — never for a record the
// committed fields already classify. No toolchain is involved.
type fakeRunner struct {
	byID  map[string]reachcandidate.CaseResult
	dflt  reachcandidate.CaseResult
	calls []string
}

func (f *fakeRunner) run(_ context.Context, _ pipeline.AdvisoryFacts, fix corpus.Fixture) reachcandidate.CaseResult {
	f.calls = append(f.calls, fix.Advisory.ID)
	if r, ok := f.byID[fix.Advisory.ID]; ok {
		return r
	}
	return f.dflt
}

// The five CaseResult shapes classifyCaseResult must fan out into distinct outcomes.
func resolvedResult(display string) reachcandidate.CaseResult {
	return reachcandidate.CaseResult{Measured: true, ResolvedCount: 1, ResolvedSinkSCIP: "scip:" + display, ResolvedSinkDisplay: display}
}
func noMatchResult() reachcandidate.CaseResult { return reachcandidate.CaseResult{Measured: true} }
func assessGapResult() reachcandidate.CaseResult {
	return reachcandidate.CaseResult{Measured: true, CandidatePairFormed: true}
}
func toolFailureResult() reachcandidate.CaseResult {
	return reachcandidate.CaseResult{PartialReason: plugin.PartialReasonToolFailure}
}
func unmeasuredResult() reachcandidate.CaseResult { return reachcandidate.CaseResult{Measured: false} }

// boundGoBearingIDs are the golang, symbol-bearing records with a bound vendored_repro fixture —
// the subset the classifier's step 5 runs over. Derived at runtime so the tests track the corpus.
func boundGoBearingIDs(fixtures []corpus.Fixture) []string {
	bound := bindFixtures(fixtures)
	var ids []string
	for id, r := range pipeline.AdvisoryTable {
		if pipeline.EcosystemToken(r) != "golang" || !pipeline.SymbolBearing(r) {
			continue
		}
		if _, ok := bound[id]; ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// spreadRunner assigns a DIVERSE CaseResult shape to each step-5 record, cycling through
// resolved / no-match / assess-gap / tool-failure / unmeasured. A catch-all in classifyCaseResult
// (uniform output from diverse input) is then visible as a collapsed reason distribution (C2(c)).
func spreadRunner(fixtures []corpus.Fixture) *fakeRunner {
	shapes := []reachcandidate.CaseResult{
		resolvedResult("pkg.Alpha"),
		noMatchResult(),
		assessGapResult(),
		toolFailureResult(),
		resolvedResult("pkg.Beta"),
		unmeasuredResult(),
	}
	f := &fakeRunner{byID: map[string]reachcandidate.CaseResult{}, dflt: resolvedResult("pkg.Default")}
	for i, id := range boundGoBearingIDs(fixtures) {
		f.byID[id] = shapes[i%len(shapes)]
	}
	return f
}

// loadCorpus is the shared hermetic corpus load.
func loadCorpus(t interface{ Fatalf(string, ...any) }) []corpus.Fixture {
	fx, err := corpus.Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	return fx
}
