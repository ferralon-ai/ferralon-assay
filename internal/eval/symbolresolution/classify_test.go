package symbolresolution

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/internal/eval/reachcandidate"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// TestClassifyStep5Mapping is the step-5 fan-out table (§3.1): each CaseResult shape maps to its
// OWN distinct outcome. This is the primary anti-catch-all guard — a classifier that funnelled
// diverse CaseResults into one reason (e.g. symbol-indexed-no-match) is caught here by type, not
// by convention (C2).
func TestClassifyStep5Mapping(t *testing.T) {
	tests := []struct {
		name         string
		res          reachcandidate.CaseResult
		wantResolved bool
		wantReason   ResolutionReason
		wantDisplay  string
	}{
		{"resolved", resolvedResult("pkg.Fn"), true, "", "pkg.Fn"},
		{"hard error → tool failure", reachcandidate.CaseResult{Err: context.DeadlineExceeded}, false, ReasonResolverToolFailure, ""},
		{"tool_failure partiality → tool failure", toolFailureResult(), false, ReasonResolverToolFailure, ""},
		{"unmeasured → artifact not indexed", unmeasuredResult(), false, ReasonArtifactNotIndexed, ""},
		{"measured, candidate formed, 0 matched → assess-tier gap", assessGapResult(), false, ReasonAssessTierGap, ""},
		{"measured, no candidate, 0 matched → symbol indexed no match", noMatchResult(), false, ReasonSymbolIndexedNoMatch, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out ResolutionOutcome
			classifyCaseResult(&out, tt.res)
			if out.Resolved != tt.wantResolved {
				t.Fatalf("Resolved = %v, want %v", out.Resolved, tt.wantResolved)
			}
			if out.Reason != tt.wantReason {
				t.Fatalf("Reason = %q, want %q", out.Reason, tt.wantReason)
			}
			if tt.wantResolved {
				if out.Symbol == nil || out.Symbol.DisplayName != tt.wantDisplay {
					t.Fatalf("Symbol = %+v, want display %q", out.Symbol, tt.wantDisplay)
				}
			} else if out.Symbol != nil {
				t.Fatalf("unresolved outcome carries a symbol: %+v", out.Symbol)
			}
			// Every produced outcome must satisfy the invariant.
			out.RecordID, out.Lane = "R", "go"
			if err := out.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

// TestClassifyPrecedence walks steps 1-4 (pure over committed fields) — the routing/producer
// classifications that never run the resolver — asserting first-match precedence. The injected
// runner fails the test if invoked, proving these records are classified without the resolver.
func TestClassifyPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		purl       string
		symbols    []string
		bound      bool
		wantReason ResolutionReason
	}{
		{"ecosystem unsupported (no lane)", "pkg:cargo/serde", []string{"serde::de"}, false, ReasonEcosystemUnsupported},
		{"ecosystem unsupported (no purl)", "", []string{"x"}, false, ReasonEcosystemUnsupported},
		{"out-of-lane ecosystem", "pkg:maven/org.example/lib", []string{"org.example.Lib.f"}, false, ReasonOutOfLaneEcosystem},
		{"in-lane, no symbol", "pkg:golang/example.com/m", nil, false, ReasonAdvisoryNamesNoSymbol},
		{"in-lane, symbol-bearing, unbound", "pkg:golang/example.com/m", []string{"example.com/m.F"}, false, ReasonArtifactNotIndexed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := pipeline.AdvisoryFacts{PURL: tt.purl, Symbols: tt.symbols}
			mustNotRun := CaseRunner(func(_ context.Context, _ pipeline.AdvisoryFacts, _ corpus.Fixture) reachcandidate.CaseResult {
				t.Fatal("resolver ran for a step-1..4 (committed-field) record")
				return reachcandidate.CaseResult{}
			})
			out := Classify(context.Background(), "R", "go", rec, corpus.Fixture{}, tt.bound, mustNotRun)
			if out.Resolved || out.Reason != tt.wantReason {
				t.Fatalf("got resolved=%v reason=%q, want reason=%q", out.Resolved, out.Reason, tt.wantReason)
			}
			if err := out.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

// TestClassifyLaneCount is the C1 count guard: one outcome per record for the single in-scope
// (measured) lane, so a dropped record fails on the count rather than being invisible.
func TestClassifyLaneCount(t *testing.T) {
	fixtures := loadCorpus(t)
	bound := bindFixtures(fixtures)
	run := spreadRunner(fixtures)
	outcomes := ClassifyLane(context.Background(), "go", pipeline.AdvisoryTable, bound, run.run)

	inScopeLanes := len(measuredLanes) // this cycle: {go}
	want := len(pipeline.AdvisoryTable) * inScopeLanes
	if len(outcomes) != want {
		t.Fatalf("outcome count = %d, want records(%d) × in-scope lanes(%d) = %d",
			len(outcomes), len(pipeline.AdvisoryTable), inScopeLanes, want)
	}
	// Every outcome is well-formed, and every record id appears exactly once (none absent).
	seen := map[string]int{}
	for _, o := range outcomes {
		if err := o.Validate(); err != nil {
			t.Errorf("outcome %s: %v", o.RecordID, err)
		}
		seen[o.RecordID]++
	}
	for id := range pipeline.AdvisoryTable {
		if seen[id] != 1 {
			t.Errorf("record %s appears %d times, want exactly 1", id, seen[id])
		}
	}

	// run is invoked ONLY for the buildable subset (step 5), never for a committed-field
	// classification.
	if got, want := len(run.calls), len(boundGoBearingIDs(fixtures)); got != want {
		t.Errorf("resolver run %d times, want %d (buildable in-lane subset)", got, want)
	}
}

// TestReasonDistributionNoCatchAll is C2(c): over the records the resolver actually RAN (step 5 —
// the only locus where a catch-all can be reintroduced by convention), no single reason absorbs
// an implausible share of the unresolved set, and the fan-out uses multiple distinct reasons. A
// diverse set of CaseResults that collapsed to one reason would fail here.
func TestReasonDistributionNoCatchAll(t *testing.T) {
	fixtures := loadCorpus(t)
	bound := bindFixtures(fixtures)
	run := spreadRunner(fixtures)
	outcomes := ClassifyLane(context.Background(), "go", pipeline.AdvisoryTable, bound, run.run)

	step5 := map[string]bool{}
	for _, id := range boundGoBearingIDs(fixtures) {
		step5[id] = true
	}

	byReason := map[ResolutionReason]int{}
	unresolved := 0
	for _, o := range outcomes {
		if !step5[o.RecordID] || o.Resolved {
			continue
		}
		byReason[o.Reason]++
		unresolved++
	}
	if unresolved == 0 {
		t.Fatal("no unresolved step-5 outcomes to sweep — the control is vacuous")
	}
	if len(byReason) < 3 {
		t.Fatalf("step-5 unresolved reasons collapsed to %d distinct (%v); diverse CaseResults must fan out (catch-all?)", len(byReason), byReason)
	}
	for reason, n := range byReason {
		if share := float64(n) / float64(unresolved); share > 0.5 {
			t.Errorf("reason %q absorbs %.0f%% of the step-5 unresolved set (%d/%d) — implausible for diverse inputs (catch-all?)",
				reason, share*100, n, unresolved)
		}
	}
}
