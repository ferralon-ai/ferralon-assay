// internal/pipeline/disqual_npm_range_test.go
//
// Tranche A #3: un-bypass npmVersionInRange. The npm-scheme version axis dispatches on the SHAPE of
// the advisory bound: a PLAIN version keeps the single-upper-exclusive comparator (every existing
// corpus verdict is unchanged — pinned in disqual_js_test.go), a single-contiguous RANGE EXPRESSION
// (">=1.2.0 <1.4.0", "^1.2.0", …) is evaluated by the full node-semver matcher so a below-floor
// version the upper-bound-only path would over-include as affected is precisely disqualified. The
// version axis MUST fail OPEN on any uncertainty (inv.5): unknown is never "not affected".
package pipeline

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// runNPMRangeDisqual seeds a normalized npm advisory whose bound is the given (possibly range)
// string plus a resolved version, then runs the disqualification stage and returns the verdict.
func runNPMRangeDisqual(t *testing.T, bound, resolvedVersion string) DisqualResult {
	t.Helper()
	store := artifact.NewMemStore()
	caseID := "case-npm-range"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id":         "TEGRON-JS-RANGE-0001",
		"affected_ranges": []map[string]string{{"upper_exclusive": bound, "scheme": "npm"}},
		"trust_tier":      "first_party", // curated-corpus provenance intake would stamp (inv.5 gate)
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"resolved_version": resolvedVersion,
	})
	return runDisqual(t, store, caseID)
}

// A single contiguous range expression with a LOWER floor: a version BELOW the floor is provably
// outside the affected set and DISQUALIFIES — precision the upper-bound-only path cannot express
// (it would treat everything < 1.4.0, including 1.1.0, as affected and fail open).
func TestNPMDisqual_RangeExpression_BelowFloorDisqualifies(t *testing.T) {
	res := runNPMRangeDisqual(t, ">=1.2.0 <1.4.0", "1.1.0")
	if !res.Disqualified {
		t.Fatalf("1.1.0 is below the affected floor [1.2.0,1.4.0) -> must DISQUALIFY, got %+v", res)
	}
	if res.Reason != ReasonVersionNotInRange {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonVersionNotInRange)
	}
}

// A version INSIDE the affected range proceeds (still affected).
func TestNPMDisqual_RangeExpression_InRangeProceeds(t *testing.T) {
	res := runNPMRangeDisqual(t, ">=1.2.0 <1.4.0", "1.3.0")
	if res.Disqualified {
		t.Fatalf("1.3.0 is inside [1.2.0,1.4.0) -> must PROCEED (affected), got %+v", res)
	}
}

// A version AT the upper bound is outside the half-open affected set and disqualifies.
func TestNPMDisqual_RangeExpression_AtUpperBoundDisqualifies(t *testing.T) {
	res := runNPMRangeDisqual(t, ">=1.2.0 <1.4.0", "1.4.0")
	if !res.Disqualified {
		t.Fatalf("1.4.0 == upper bound of [1.2.0,1.4.0) -> must DISQUALIFY, got %+v", res)
	}
}

// An IN-WINDOW PRERELEASE must FAIL OPEN (stay affected): "1.3.0-rc.1" falls numerically inside the
// vulnerable window [1.2.0,1.4.0), so it IS vulnerable. node-semver's default prerelease isolation
// would wrongly exclude it (a fail-CLOSED false negative); the disqualifier uses include-prerelease
// membership so the in-window prerelease counts as affected → NOT disqualified (inv.5). This pins the
// reviewer's exact case.
func TestNPMDisqual_InWindowPrerelease_FailsOpen(t *testing.T) {
	res := runNPMRangeDisqual(t, ">=1.2.0 <1.4.0", "1.3.0-rc.1")
	if res.Disqualified {
		t.Fatalf("1.3.0-rc.1 is inside the affected window [1.2.0,1.4.0) -> must PROCEED (affected), got %+v", res)
	}
}

// A second in-window prerelease, clearly interior to the window, likewise stays affected.
func TestNPMDisqual_InteriorPrerelease_FailsOpen(t *testing.T) {
	res := runNPMRangeDisqual(t, ">=1.2.0 <1.4.0", "1.2.5-rc.2")
	if res.Disqualified {
		t.Fatalf("1.2.5-rc.2 is inside [1.2.0,1.4.0) -> must PROCEED (affected), got %+v", res)
	}
}

// A genuinely OUT-OF-WINDOW prerelease is correctly not-affected/disqualified: "1.5.0-rc.1" is above
// the upper bound, so it fails the "<1.4.0" comparator on its numeric core — include-prerelease does
// NOT over-admit it. Pins the other direction (the fix must not turn into a fail-OPEN blanket).
func TestNPMDisqual_OutOfWindowPrerelease_Disqualifies(t *testing.T) {
	res := runNPMRangeDisqual(t, ">=1.2.0 <1.4.0", "1.5.0-rc.1")
	if !res.Disqualified {
		t.Fatalf("1.5.0-rc.1 is above the affected window [1.2.0,1.4.0) -> must DISQUALIFY, got %+v", res)
	}
	if res.Reason != ReasonVersionNotInRange {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonVersionNotInRange)
	}
}

// A caret range ("^1.2.0" == [1.2.0, 2.0.0)) resolves through the same matcher: 2.0.0 is outside.
func TestNPMDisqual_CaretRange_OutsideCeilingDisqualifies(t *testing.T) {
	res := runNPMRangeDisqual(t, "^1.2.0", "2.0.0")
	if !res.Disqualified {
		t.Fatalf("2.0.0 is outside ^1.2.0 == [1.2.0,2.0.0) -> must DISQUALIFY, got %+v", res)
	}
}

// An UNPARSEABLE range expression must FAIL OPEN — the version axis never fabricates a not-affected
// from a bound it cannot model (inv.5).
func TestNPMDisqual_UnparseableRange_FailsOpen(t *testing.T) {
	res := runNPMRangeDisqual(t, ">=not-a-version <also-bad", "1.3.0")
	if res.Disqualified {
		t.Fatalf("an unmodellable range must FAIL OPEN (proceed), got disqualified %+v", res)
	}
	if res.Reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonInsufficient)
	}
}

// --- comparator-level dispatch + fail-open on prereleases (npmDisqualifyOutside) --------------

// npmDisqualifyOutside routes a PLAIN version bound to the single-upper-exclusive comparator (which
// is npm-aware and identical to today's behavior) and a RANGE EXPRESSION to the full matcher.
func TestNPMDisqualifyOutside_PlainBoundMatchesLegacyComparator(t *testing.T) {
	cases := []struct {
		ver, bound  string
		wantOutside bool
		wantSettled bool
	}{
		{"1.4.0", "1.4.0", true, true},  // == fix, outside affects<1.4.0
		{"1.3.9", "1.4.0", false, true}, // below fix, still affected
		{"1.10.0", "1.9.0", true, true}, // numeric (not lexical) ordering
	}
	for _, tc := range cases {
		gotOutside, gotSettled := npmDisqualifyOutside(tc.ver, tc.bound)
		legacyOutside, legacySettled := npmVersionOutsideRange(tc.ver, tc.bound)
		if gotOutside != legacyOutside || gotSettled != legacySettled {
			t.Errorf("plain bound %q vs %q: dispatch diverged from legacy comparator (got %v/%v, legacy %v/%v)",
				tc.ver, tc.bound, gotOutside, gotSettled, legacyOutside, legacySettled)
		}
		if gotOutside != tc.wantOutside || gotSettled != tc.wantSettled {
			t.Errorf("npmDisqualifyOutside(%q,%q) = %v,%v; want %v,%v", tc.ver, tc.bound, gotOutside, gotSettled, tc.wantOutside, tc.wantSettled)
		}
	}
}

// A boundary PRERELEASE against a PLAIN version bound must FAIL OPEN (stay affected): a prerelease
// below the fix release is still vulnerable. This pins the fail-open guard the version axis requires
// (the plain path handles all current corpus data), independent of the range-matcher's own
// node-semver prerelease-isolation semantics.
func TestNPMDisqualifyOutside_BoundaryPrereleaseFailsOpen(t *testing.T) {
	outside, settled := npmDisqualifyOutside("1.4.0-rc.1", "1.4.0")
	if outside {
		t.Fatalf("1.4.0-rc.1 (a prerelease below the 1.4.0 fix) must NOT be marked outside/not-affected")
	}
	if !settled {
		t.Fatalf("the comparison is well-defined (settled=true), it simply resolves to 'still affected'")
	}
}
