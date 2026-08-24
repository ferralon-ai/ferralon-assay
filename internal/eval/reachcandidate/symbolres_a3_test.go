package reachcandidate

// symbolres_a3_test.go
//
// A3 (cycle 2026-08-24 corpus-scaffold): the measurement harness must show that growing the corpus
// `symbols[]` coverage MOVES SymbolResolutionRate — the observable the (A) scaffold exists to prove
// before any (B) proof-logic spends risk on it. TestDiff_PartialVsComplete already shows coverage
// moving RECALL; this pins the resolution-rate metric specifically, over the Go lane, matching bare
// DisplayName-form identifiers (the corpus's symbol form — see package doc).
//
// The independent variable is the per-case corpus symbol list and NOTHING else: the same hermetic Go
// program, the same four CVEs, the same real S4/S5 stages. Only which cases carry a RESOLVING symbol
// changes across tiers, so a rising rate can only come from coverage.

import (
	"context"
	"testing"
)

// TestSymbolResolutionRate_TracksCoverage drives three corpus tiers (0, 2, 4 of the four cases carry
// a resolving symbol) and asserts SymbolResolutionRate climbs 0/4 → 2/4 → 4/4. The MEASURED
// denominator stays 4 throughout — every case is analyzed by a real (fake) plugin regardless of its
// symbols — so the metric moves purely on the numerator (symbols that resolved), which is exactly the
// coverage signal Gene's growing extraction is meant to light up.
func TestSymbolResolutionRate_TracksCoverage(t *testing.T) {
	p := program() // resolvable in-program symbols: language.Parse, language.Compose

	const resolving = "language.Parse"    // matches the program → resolves (a covered corpus symbol)
	const missing = "language.NoSuchFunc" // no match → measured but unresolved (a coverage gap)
	const total = 4

	// build a report where the first `covered` of the four cases carry the resolving symbol and the
	// rest carry a non-resolving one (measured, but no resolution — the honest coverage gap).
	build := func(covered int) Report {
		cases := make([]Case, 0, total)
		for i := 0; i < total; i++ {
			sym := missing
			if i < covered {
				sym = resolving
			}
			cases = append(cases, Case{
				CaseID:        string(rune('a' + i)),
				VulnID:        "CVE-" + string(rune('1'+i)),
				Symbols:       []string{sym},
				ExpectedSinks: []string{resolving},
				BuildDir:      "/fake",
			})
		}
		return Run(context.Background(), p, "coverage tier", cases)
	}

	tiers := []struct {
		name    string
		covered int
		wantNum int
	}{
		{"empty coverage", 0, 0},
		{"partial coverage", 2, 2},
		{"complete coverage", 4, 4},
	}

	var prev = -1.0
	for _, tier := range tiers {
		t.Run(tier.name, func(t *testing.T) {
			rep := build(tier.covered)
			rate := rep.SymbolResolutionRate()
			// The measured base is invariant: coverage moves the numerator, never the denominator.
			if rate.Denom != total {
				t.Fatalf("measured denominator = %d, want %d — every case must be measured so the rate moves on coverage alone", rate.Denom, total)
			}
			if rate.Num != tier.wantNum {
				t.Fatalf("SymbolResolutionRate = %s, want %d/%d", rate, tier.wantNum, total)
			}
		})
		// Strictly increasing across tiers: more coverage ⇒ a higher resolution rate.
		if f := build(tier.covered).SymbolResolutionRate().Float(); f <= prev {
			t.Fatalf("SymbolResolutionRate did not increase with coverage: %.3f followed %.3f", f, prev)
		} else {
			prev = f
		}
	}
}
