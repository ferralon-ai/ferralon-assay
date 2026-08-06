// disqual_multirange_test.go
//
// Slice U2: multi-range version consumers. A backport/split-fix advisory declares DISJOINT affected
// ranges (the canonical case is Go CVE-2023-39325: the 1.20.x branch fixed at 1.20.10 AND mainline
// fixed at 1.21.3 — TWO ranges, not one bound). A version is disqualifiable (provably not-affected)
// ONLY when it is provably outside EVERY range; uncertainty in any range fails OPEN (inv.5) — a
// disjoint set never fabricates a not-affected across the gap.
package pipeline

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// runMultiRangeDisqual seeds a normalized advisory carrying N structured affected ranges plus a
// resolved version, then runs the disqualification stage and returns the verdict.
func runMultiRangeDisqual(t *testing.T, ranges []map[string]string, resolvedVersion string) DisqualResult {
	t.Helper()
	store := artifact.NewMemStore()
	caseID := "case-multirange"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id":         "GO-2023-BACKPORT",
		"affected_ranges": ranges,
		"trust_tier":      "first_party", // curated-corpus provenance intake would stamp (inv.5 gate)
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"resolved_version": resolvedVersion,
	})
	return runDisqual(t, store, caseID)
}

// The Go CVE-2023-39325 backport as two upper-exclusive ranges: [_, v1.20.10) on the 1.20 branch
// and [_, v1.21.3) on mainline.
func goBackportRanges() []map[string]string {
	return []map[string]string{
		{"upper_exclusive": "v1.20.10"},
		{"upper_exclusive": "v1.21.3"},
	}
}

// A version in the disjoint GAP (patched on the 1.20 branch at 1.20.10, but below the mainline
// range) is NOT disqualified: with upper-exclusive-only ranges the second range has no floor, so
// the version stays inside it. Failing OPEN here is the SOUND, conservative answer (inv.5) — the
// version axis never fabricates a not-affected across the gap.
func TestMultiRange_BetweenRanges_NotDisqualified(t *testing.T) {
	res := runMultiRangeDisqual(t, goBackportRanges(), "v1.20.15")
	if res.Disqualified {
		t.Fatalf("v1.20.15 sits inside the second range [<v1.21.3] -> must PROCEED (still affected), got %+v", res)
	}
}

// A version at/above the tighter branch fix but still below the mainline fix likewise stays
// affected (inside the second range). Pins the canonical branch-fix version.
func TestMultiRange_BranchFixVersion_NotDisqualified(t *testing.T) {
	res := runMultiRangeDisqual(t, goBackportRanges(), "v1.20.10")
	if res.Disqualified {
		t.Fatalf("v1.20.10 (>=branch fix, <mainline fix) is inside [<v1.21.3] -> must PROCEED, got %+v", res)
	}
}

// A version provably outside EVERY range IS disqualified: v1.21.3 is >= both upper bounds.
func TestMultiRange_OutsideAllRanges_Disqualifies(t *testing.T) {
	res := runMultiRangeDisqual(t, goBackportRanges(), "v1.21.3")
	if !res.Disqualified {
		t.Fatalf("v1.21.3 is outside both [<v1.20.10] and [<v1.21.3] -> must DISQUALIFY, got %+v", res)
	}
	if res.Reason != ReasonVersionNotInRange {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonVersionNotInRange)
	}
}

// A version well above every range is likewise disqualified.
func TestMultiRange_FarAboveAllRanges_Disqualifies(t *testing.T) {
	res := runMultiRangeDisqual(t, goBackportRanges(), "v1.22.0")
	if !res.Disqualified {
		t.Fatalf("v1.22.0 is outside every range -> must DISQUALIFY, got %+v", res)
	}
}

// A version provably INSIDE one of the ranges is still affected (proceed), even though it is
// outside the other. Inside-any = affected is definitive.
func TestMultiRange_InsideFirstRange_NotDisqualified(t *testing.T) {
	res := runMultiRangeDisqual(t, goBackportRanges(), "v1.20.5")
	if res.Disqualified {
		t.Fatalf("v1.20.5 is inside the first range [<v1.20.10] -> must PROCEED (affected), got %+v", res)
	}
}

// One AMBIGUOUS range in the set fails the WHOLE version axis OPEN, even when the version is
// provably outside the parseable range: without a proof for every range there is no
// provably-outside-EVERY-range, so the axis never disqualifies (inv.5).
func TestMultiRange_AmbiguousRange_FailsOpen(t *testing.T) {
	ranges := []map[string]string{
		{"upper_exclusive": "v1.20.10"},
		{"upper_exclusive": "not-a-version"},
	}
	res := runMultiRangeDisqual(t, ranges, "v1.21.3") // outside the good range, but the bad range is unprovable
	if res.Disqualified {
		t.Fatalf("an ambiguous range must fail the set OPEN (proceed), got disqualified %+v", res)
	}
	if res.Reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonInsufficient)
	}
}

// A range that carries no usable upper bound (empty Fixed) withholds the whole set — extraction
// returns rangeKnown=false and the axis fails OPEN, rather than disqualifying on the sibling ranges.
func TestMultiRange_EmptyUpperInSet_FailsOpen(t *testing.T) {
	ranges := []map[string]string{
		{"upper_exclusive": "v1.20.10"},
		{"upper_exclusive": ""},
	}
	res := runMultiRangeDisqual(t, ranges, "v1.21.3")
	if res.Disqualified {
		t.Fatalf("an empty-bound range must withhold the set (proceed), got disqualified %+v", res)
	}
}

// --- npm multi-range (activates npmVersionInRange within the multi-range check) ---------------

// A disjoint npm backport expressed with FULL range expressions (floors honored via
// npmVersionInRange): [1.0.0,1.4.0) and [2.0.0,2.3.0). A version in the GAP (1.5.0: past the 1.x
// fix, before the 2.x vulnerable window) is provably outside BOTH ranges -> DISQUALIFIED. This is
// the precision the range-expression path buys over upper-exclusive-only, and it exercises
// npmVersionInRange per range inside the multi-range check.
func TestMultiRange_NPM_RangeExprGapDisqualifies(t *testing.T) {
	ranges := []map[string]string{
		{"upper_exclusive": ">=1.0.0 <1.4.0", "scheme": "npm"},
		{"upper_exclusive": ">=2.0.0 <2.3.0", "scheme": "npm"},
	}
	res := runMultiRangeDisqual(t, ranges, "1.5.0")
	if !res.Disqualified {
		t.Fatalf("1.5.0 is outside both [1.0.0,1.4.0) and [2.0.0,2.3.0) -> must DISQUALIFY, got %+v", res)
	}
	if res.Reason != ReasonVersionNotInRange {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonVersionNotInRange)
	}
}

// A version INSIDE one npm range is still affected (proceed).
func TestMultiRange_NPM_InsideOneRange_NotDisqualified(t *testing.T) {
	ranges := []map[string]string{
		{"upper_exclusive": ">=1.0.0 <1.4.0", "scheme": "npm"},
		{"upper_exclusive": ">=2.0.0 <2.3.0", "scheme": "npm"},
	}
	res := runMultiRangeDisqual(t, ranges, "2.1.0") // inside the second window
	if res.Disqualified {
		t.Fatalf("2.1.0 is inside [2.0.0,2.3.0) -> must PROCEED (affected), got %+v", res)
	}
}

// An unmodellable npm range in the set fails the whole axis OPEN (inv.5).
func TestMultiRange_NPM_UnparseableRange_FailsOpen(t *testing.T) {
	ranges := []map[string]string{
		{"upper_exclusive": ">=1.0.0 <1.4.0", "scheme": "npm"},
		{"upper_exclusive": ">=bad <also-bad", "scheme": "npm"},
	}
	res := runMultiRangeDisqual(t, ranges, "1.5.0")
	if res.Disqualified {
		t.Fatalf("an unmodellable npm range must fail the set OPEN (proceed), got disqualified %+v", res)
	}
}

// --- versionOutsideRanges direct unit coverage -------------------------------------------------

func TestVersionOutsideRanges_Direct(t *testing.T) {
	rngs := []affectedRange{{UpperExclusive: "v1.20.10"}, {UpperExclusive: "v1.21.3"}}
	cases := []struct {
		name        string
		ver         string
		wantOutside bool
		wantOK      bool
	}{
		{"outside every range", "v1.21.3", true, true},
		{"inside second range (gap)", "v1.20.15", false, true},
		{"inside first range", "v1.20.5", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outside, ok := versionOutsideRanges(tc.ver, rngs)
			if outside != tc.wantOutside || ok != tc.wantOK {
				t.Fatalf("versionOutsideRanges(%q) = %v,%v; want %v,%v", tc.ver, outside, ok, tc.wantOutside, tc.wantOK)
			}
		})
	}
}

// An empty range set is not a proof of anything: ok=false (fail open).
func TestVersionOutsideRanges_EmptySet_FailsOpen(t *testing.T) {
	if outside, ok := versionOutsideRanges("v1.0.0", nil); outside || ok {
		t.Fatalf("empty set must yield (false,false), got (%v,%v)", outside, ok)
	}
}

// Uncertainty in any range fails the whole set OPEN even when the version is outside the parseable
// range (mirrors the stage-level TestMultiRange_AmbiguousRange_FailsOpen at the primitive layer).
func TestVersionOutsideRanges_AmbiguousRange_FailsOpen(t *testing.T) {
	rngs := []affectedRange{{UpperExclusive: "v1.20.10"}, {UpperExclusive: "not-a-version"}}
	if outside, ok := versionOutsideRanges("v1.21.3", rngs); outside || ok {
		t.Fatalf("ambiguous range must yield (false,false), got (%v,%v)", outside, ok)
	}
}
