package pipeline

import "testing"

// TestCompareMaven covers the Maven version-ordering rules the disqualification axis depends on:
// numeric-segment ordering (incl. 1.2.10 > 1.2.9 — the lexical-vs-numeric trap), qualifier
// ordering, the RELEASE/FINAL/GA == "" normalization, and length normalization (1 == 1.0.0).
func TestCompareMaven(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.10", "1.2.9", 1},        // numeric, NOT lexical: 10 > 9
		{"1.2.9", "1.2.10", -1},       //
		{"1.4.0", "1.4.0", 0},         //
		{"2.0.0", "1.9.9", 1},         //
		{"1.4.1", "1.4.0", 1},         //
		{"1.4.0", "1.4.1", -1},        //
		{"1.0.0", "1", 0},             // trailing-zero normalization
		{"1.0.0", "1.0", 0},           //
		{"1", "1.0.0", 0},             //
		{"1.4.0-RELEASE", "1.4.0", 0}, // RELEASE == "" (release rank)
		{"1.4.0.Final", "1.4.0", 0},   // .Final == release
		{"1.4.0-GA", "1.4.0", 0},      // GA == release
		{"1.4.0", "1.4.0-RC1", 1},     // release > rc
		{"1.4.0-RC1", "1.4.0-RC2", -1},
		{"1.4.0-alpha", "1.4.0-beta", -1},
		{"1.4.0-beta", "1.4.0-rc", -1},
		{"1.4.0-SNAPSHOT", "1.4.0", -1},    // snapshot < release
		{"1.4.0-SNAPSHOT", "1.4.0-RC1", 1}, // snapshot > rc
		{"1.0.0-RC1", "1.0.0-rc1", 0},      // case-insensitive qualifier
		// Classic Maven ComparableVersion reference orderings:
		{"1.0-alpha-1", "1.0", -1},
		{"1.0-alpha-1", "1.0-beta-1", -1},
		{"1.0-beta-1", "1.0-SNAPSHOT", -1},
		{"1.0-SNAPSHOT", "1.0", -1},
		{"1.0-rc1", "1.0-cr1", 0}, // rc == cr alias
		{"1.0.1", "1.0", 1},
		{"1.0-milestone-1", "1.0-rc-1", -1},
	}
	for _, tc := range cases {
		got, ok := compareMaven(tc.a, tc.b)
		if !ok {
			t.Errorf("compareMaven(%q,%q) ok=false, want a confident ordering", tc.a, tc.b)
			continue
		}
		if got != tc.want {
			t.Errorf("compareMaven(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestCompareMaven_FailsOpenOnExotic asserts the comparator declines (ok=false) on inputs it
// cannot order confidently — the inv.5 fail-open guard at the version-compare layer.
func TestCompareMaven_FailsOpenOnExotic(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"", "1.0.0"},
		{"1.0.0", ""},
		{"1.0.0", "1.0.0!weird"}, // '!' outside the modelled grammar
		{"a/b", "1.0.0"},
	} {
		if _, ok := compareMaven(tc.a, tc.b); ok {
			t.Errorf("compareMaven(%q,%q) ok=true, want false (exotic input must fail open)", tc.a, tc.b)
		}
	}
}

// TestMavenVersionOutsideRange exercises the disqualification-shaped predicate: provably-outside
// (declared >= fixed) is true; inside (declared < fixed) is false; ambiguous fails open.
func TestMavenVersionOutsideRange(t *testing.T) {
	cases := []struct {
		ver, upper      string
		outside, wantOK bool
	}{
		{"1.4.0", "1.4.0", true, true},      // == fixed → outside (patched)
		{"1.4.1", "1.4.0", true, true},      // > fixed → outside
		{"1.2.10", "1.2.9", true, true},     // numeric guard: 1.2.10 >= 1.2.9
		{"1.3.9", "1.4.0", false, true},     // < fixed → inside (vulnerable)
		{"1.2.9", "1.2.10", false, true},    //
		{"1.4.0-RC1", "1.4.0", false, true}, // prerelease < release → inside (vulnerable)
		{"", "1.4.0", false, false},         // unknown version → fail open
		{"1.4.0", "weird!", false, false},   // unparseable bound → fail open
	}
	for _, tc := range cases {
		outside, ok := mavenVersionOutsideRange(tc.ver, tc.upper)
		if ok != tc.wantOK {
			t.Errorf("mavenVersionOutsideRange(%q,%q) ok=%v, want %v", tc.ver, tc.upper, ok, tc.wantOK)
			continue
		}
		if ok && outside != tc.outside {
			t.Errorf("mavenVersionOutsideRange(%q,%q) outside=%v, want %v", tc.ver, tc.upper, outside, tc.outside)
		}
	}
}
