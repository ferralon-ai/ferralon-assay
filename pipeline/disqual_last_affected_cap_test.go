package pipeline

import "testing"

func TestVersionOutsideRanges_LastAffectedCappedByNextRange(t *testing.T) {
	// The CVE-2025-41249 record's spring-core ranges: two branch lines that end at last_affected
	// with no fix, then a fixed line.
	springCore := []affectedRange{
		{LowerInclusive: "5.3.0", LastAffected: "5.3.44", Scheme: "maven"},
		{LowerInclusive: "6.0.0", LastAffected: "6.1.22", Scheme: "maven"},
		{LowerInclusive: "6.2.0", UpperExclusive: "6.2.11", Scheme: "maven"},
	}
	cases := []struct {
		name        string
		ver         string
		rngs        []affectedRange
		wantOutside bool
		wantOK      bool
	}{
		{"past every capped range and the fixed top", "7.0.9", springCore, true, true},
		{"inside the fixed top range", "6.2.5", springCore, false, true},
		{"at last_affected of a capped range", "5.3.44", springCore, false, true},
		{"between last_affected and the next introduced stays inside", "5.3.50", springCore, false, true},
		{"between capped branches stays inside", "6.1.30", springCore, false, true},
		{"below the lowest introduced", "5.2.9", springCore, true, true},
		{"lone open last_affected range stays open above", "7.0.9",
			[]affectedRange{{LowerInclusive: "5.3.0", LastAffected: "5.3.44", Scheme: "maven"}}, false, true},
		{"topmost open last_affected range stays open above", "7.0.9",
			[]affectedRange{
				{LowerInclusive: "5.3.0", UpperExclusive: "5.3.45", Scheme: "maven"},
				{LowerInclusive: "6.0.0", LastAffected: "6.1.22", Scheme: "maven"},
			}, false, true},
		{"a later range with no introduced does not cap", "7.0.9",
			[]affectedRange{
				{LowerInclusive: "5.3.0", LastAffected: "5.3.44", Scheme: "maven"},
				{UpperExclusive: "6.2.11", Scheme: "maven"},
			}, false, true},
		{"an introduced at or below last_affected does not cap", "7.0.9",
			[]affectedRange{
				{LowerInclusive: "5.3.0", LastAffected: "5.3.44", Scheme: "maven"},
				{LowerInclusive: "5.3.10", UpperExclusive: "5.3.20", Scheme: "maven"},
			}, false, true},
		{"the lowest later introduced is the cap", "6.5.0",
			[]affectedRange{
				{LowerInclusive: "5.3.0", LastAffected: "5.3.44", Scheme: "maven"},
				{LowerInclusive: "7.0.0", UpperExclusive: "7.0.5", Scheme: "maven"},
				{LowerInclusive: "6.0.0", UpperExclusive: "6.0.3", Scheme: "maven"},
			}, true, true},
		{"an unorderable last_affected is not capped", "1.4.3",
			[]affectedRange{
				{LowerInclusive: "1.0.0", LastAffected: "garbage", Scheme: "npm"},
				{LowerInclusive: "2.0.0", UpperExclusive: "2.1.0", Scheme: "npm"},
			}, false, true},
		{"a later range of a non-orderable type does not cap", "7.0.9",
			[]affectedRange{
				{LowerInclusive: "5.3.0", LastAffected: "5.3.44", Scheme: "maven"},
				{Type: "GIT", LowerInclusive: "6.0.0", UpperExclusive: "6.0.3", Scheme: "maven"},
			}, false, true},
		{"a later range of another scheme does not cap", "7.0.9",
			[]affectedRange{
				{LowerInclusive: "5.3.0", LastAffected: "5.3.44", Scheme: "maven"},
				{LowerInclusive: "6.0.0", UpperExclusive: "6.0.3", Scheme: "npm"},
			}, false, true},
		{"an unorderable later introduced does not cap", "7.0.9",
			[]affectedRange{
				{LowerInclusive: "1.0.0", LastAffected: "1.4.0", Scheme: "npm"},
				{LowerInclusive: "garbage", UpperExclusive: "2.1.0", Scheme: "npm"},
			}, false, true},
		{"a zero introduced does not cap", "7.0.9",
			[]affectedRange{
				{LowerInclusive: "5.3.0", LastAffected: "5.3.44", Scheme: "maven"},
				{LowerInclusive: "0", UpperExclusive: "6.0.3", Scheme: "maven"},
			}, false, true},
		{"a legacy range does not cap an element range", "7.0.9",
			[]affectedRange{
				{LowerInclusive: "5.3.0", LastAffected: "5.3.44", Scheme: "maven"},
				{LowerInclusive: "6.0.0", UpperExclusive: "6.0.3", Scheme: "maven", Legacy: true},
			}, false, true},
		{"an element range does not cap a legacy range", "7.0.9",
			[]affectedRange{
				{LowerInclusive: "6.0.0", UpperExclusive: "6.0.3", Scheme: "maven"},
				{LowerInclusive: "5.3.0", LastAffected: "5.3.44", Scheme: "maven", Legacy: true},
			}, false, true},
		{"legacy ranges cap each other", "7.0.9",
			[]affectedRange{
				{LowerInclusive: "5.3.0", LastAffected: "5.3.44", Scheme: "maven", Legacy: true},
				{LowerInclusive: "6.0.0", UpperExclusive: "6.0.3", Scheme: "maven", Legacy: true},
			}, true, true},
		{"a range never caps itself", "7.0.0",
			[]affectedRange{
				{LowerInclusive: "6.0.0", LastAffected: "5.0.0", Scheme: "maven"},
				{LowerInclusive: "1.0.0", UpperExclusive: "1.0.3", Scheme: "maven"},
			}, false, true},
		{"a cap at or below the range's own introduced is not taken", "7.0.0",
			[]affectedRange{
				{LowerInclusive: "6.0.0", LastAffected: "5.0.0", Scheme: "maven"},
				{LowerInclusive: "5.5.0", UpperExclusive: "5.5.3", Scheme: "maven"},
			}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outside, ok := versionOutsideRanges(tc.ver, tc.rngs)
			if outside != tc.wantOutside || ok != tc.wantOK {
				t.Errorf("versionOutsideRanges(%q) = (%v, %v), want (%v, %v)", tc.ver, outside, ok, tc.wantOutside, tc.wantOK)
			}
		})
	}
}

func TestCapOpenLastAffected_DoesNotModifyInput(t *testing.T) {
	rngs := []affectedRange{
		{LowerInclusive: "5.3.0", LastAffected: "5.3.44", Scheme: "maven"},
		{LowerInclusive: "6.0.0", UpperExclusive: "6.0.3", Scheme: "maven"},
	}
	got := capOpenLastAffected(rngs)
	if rngs[0].UpperExclusive != "" {
		t.Fatalf("input range modified: %+v", rngs[0])
	}
	if got[0].UpperExclusive != "6.0.0" {
		t.Errorf("capped upper = %q, want 6.0.0", got[0].UpperExclusive)
	}
}

// An element whose one range is open above stays open when disagreeing legacy ranges are merged
// beside it: the merged set admits wherever either source admits, so a legacy range's introduced
// never caps the element's range.
func TestCapOpenLastAffected_MergedLegacyKeepsElementOpen(t *testing.T) {
	pkg := AffectedPackage{
		Coordinate:     "org.springframework:spring-core",
		AffectedRanges: []Range{{Introduced: "5.3.0", LastAffected: "5.3.44"}},
	}
	facts := AdvisoryFacts{
		Coordinate:     pkg.Coordinate,
		AffectedRanges: []Range{{Introduced: "6.0.0", Fixed: "6.0.3"}},
	}
	rngs := withDisagreeingLegacyRanges(buildAffectedRanges(pkg.AffectedRanges, "", "maven"), pkg, facts, "maven")
	if len(rngs) != 2 {
		t.Fatalf("merged ranges = %+v, want the element's and the legacy one", rngs)
	}
	if outside, ok := versionOutsideRanges("7.0.9", rngs); outside || !ok {
		t.Errorf("versionOutsideRanges(7.0.9, %+v) = (%v, %v), want (false, true)", rngs, outside, ok)
	}
}
