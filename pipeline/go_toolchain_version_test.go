// internal/pipeline/go_toolchain_version_test.go
//
// U7 comparator unit tests: the Go stdlib/toolchain release-version comparator
// (goToolchainVersionOutsideRange). Table-driven over normal outside/inside, the two-range
// backport reducer, and EVERY fail-open path (prerelease, unparseable, empty bound, wrong scheme).
package pipeline

import "testing"

func TestGoToolchainVersionOutsideRange(t *testing.T) {
	cases := []struct {
		name        string
		ver, upper  string
		wantOutside bool
		wantOK      bool
	}{
		// --- provably outside (ver >= upper): at or past the fix ---
		{"patched past fix", "go1.21.5", "go1.21.3", true, true},
		{"patched at fix (equal)", "go1.20.10", "go1.20.10", true, true},
		{"patched newer minor", "go1.22.0", "go1.21.3", true, true},
		{"bare form outside", "1.21.5", "1.21.3", true, true},
		{"go vs bare mixed prefix outside", "go1.21.5", "1.21.3", true, true},
		{"major.minor only == .0, outside", "go1.22", "go1.21.3", true, true},

		// --- provably inside (ver < upper): still affected ---
		{"vulnerable older patch", "go1.21.0", "go1.21.3", false, true},
		{"vulnerable older minor", "go1.20.5", "go1.20.10", false, true},
		{"major.minor only == .0, inside", "go1.21", "go1.21.3", false, true},
		{"bare form inside", "1.20.5", "1.20.10", false, true},

		// --- fail open (inv.5): ok=false, never a confident ordering ---
		{"prerelease rc no-dot", "go1.21rc1", "go1.21.3", false, false},
		{"prerelease rc dotted", "go1.21.0-rc.1", "go1.21.3", false, false},
		{"prerelease beta", "go1.22beta1", "go1.22.4", false, false},
		{"unparseable version", "go1.21.x", "go1.21.3", false, false},
		{"garbage version", "notaversion", "go1.21.3", false, false},
		{"empty version", "", "go1.21.3", false, false},
		{"empty bound (unbounded)", "go1.21.3", "", false, false},
		{"both empty", "", "", false, false},
		{"unparseable bound", "go1.21.3", "go1.21.rc", false, false},
		{"v-prefixed module semver is wrong scheme", "v0.17.0", "go1.21.3", false, false},
		{"bound is v-prefixed module semver", "go1.21.3", "v0.17.0", false, false},
		{"too few segments", "go1", "go1.21.3", false, false},
		{"too many segments", "go1.21.3.4", "go1.21.3", false, false},
		{"negative segment", "go1.-1.3", "go1.21.3", false, false},
		{"only go prefix", "go", "go1.21.3", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotOutside, gotOK := goToolchainVersionOutsideRange(tc.ver, tc.upper)
			if gotOutside != tc.wantOutside || gotOK != tc.wantOK {
				t.Errorf("goToolchainVersionOutsideRange(%q, %q) = (%v, %v), want (%v, %v)",
					tc.ver, tc.upper, gotOutside, gotOK, tc.wantOutside, tc.wantOK)
			}
		})
	}
}

// TestGoToolchain_MultiRangeBackport exercises the U2 reducer over the go-toolchain scheme with
// the CVE-2023-39325 backport shape (fixed go1.20.10 on 1.20.x AND go1.21.3 on mainline). A
// version disqualifies (provably outside EVERY range) only when it clears BOTH branch bounds;
// inside any one range it stays affected; any unparseable range fails the whole set OPEN (inv.5).
func TestGoToolchain_MultiRangeBackport(t *testing.T) {
	rapidReset := []affectedRange{
		{UpperExclusive: "go1.20.10", Scheme: "go-toolchain"},
		{UpperExclusive: "go1.21.3", Scheme: "go-toolchain"},
	}
	cases := []struct {
		name        string
		ver         string
		wantOutside bool
		wantOK      bool
	}{
		{"patched on mainline clears both bounds", "go1.21.5", true, true},
		{"patched far newer clears both", "go1.22.0", true, true},
		{"vulnerable 1.21.0 inside mainline range", "go1.21.0", false, true},
		{"vulnerable 1.20.5 inside 1.20 range", "go1.20.5", false, true},
		// go1.20.10 clears the 1.20.x bound but is < go1.21.3 so the mainline range still
		// contains it: the Introduced-less reducer soundly keeps it AFFECTED (fail toward
		// affected — never a fabricated not-affected, inv.5), not disqualified.
		{"branch-patch stays affected under Introduced-less reducer", "go1.20.10", false, true},
		{"prerelease fails whole set OPEN", "go1.21rc1", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotOutside, gotOK := versionOutsideRanges(tc.ver, rapidReset)
			if gotOutside != tc.wantOutside || gotOK != tc.wantOK {
				t.Errorf("versionOutsideRanges(%q, rapidReset) = (%v, %v), want (%v, %v)",
					tc.ver, gotOutside, gotOK, tc.wantOutside, tc.wantOK)
			}
		})
	}
}

// TestGoToolchain_MixedSchemeRangeFailsOpen: if one range in a disjoint set carries a bound the
// go-toolchain comparator cannot parse (a v-prefixed module semver — a mixed/wrong scheme), the
// whole set fails OPEN rather than disqualifying on the parseable subset (inv.5).
func TestGoToolchain_MixedSchemeRangeFailsOpen(t *testing.T) {
	mixed := []affectedRange{
		{UpperExclusive: "go1.20.10", Scheme: "go-toolchain"},
		{UpperExclusive: "v0.17.0", Scheme: "go-toolchain"}, // wrong scheme value → unparseable
	}
	if outside, ok := versionOutsideRanges("go1.21.5", mixed); ok || outside {
		t.Fatalf("mixed-scheme range must FAIL OPEN, got (outside=%v, ok=%v)", outside, ok)
	}
}
