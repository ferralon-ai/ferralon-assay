// internal/pipeline/npm_version_test.go
//
// Unit proof of the node-semver comparator + range matcher backing the JS/TS
// disqualification axis. Ordering must be NUMERIC (not lexical: 1.10.0 > 1.9.0), the
// operators advisories use (^ ~ || x-ranges, hyphen, comparators) must match node-semver,
// and ANY input outside the modelled grammar must return ok=false so the predicate fails
// OPEN (inv.5).
package pipeline

import "testing"

func TestNPMCompare_NumericNotLexical(t *testing.T) {
	// 1.10.0 vs 1.9.0: a lexical compare orders "1.10" below "1.9"; numeric is the reverse.
	outside, ok := npmVersionOutsideRange("1.10.0", "1.9.0")
	if !ok || !outside {
		t.Fatalf("1.10.0 >= 1.9.0 (numeric) must be outside affects<1.9.0; got outside=%v ok=%v", outside, ok)
	}
}

func TestNPMOutsideRange(t *testing.T) {
	cases := []struct {
		ver, upper       string
		wantOutside, wOK bool
	}{
		{"1.4.0", "1.4.0", true, true},           // == upper → outside (affects < upper)
		{"1.4.1", "1.4.0", true, true},           // > upper
		{"1.3.9", "1.4.0", false, true},          // < upper → inside affected
		{"2.0.0", "1.4.0", true, true},           // major bump
		{"1.4.0-rc.1", "1.4.0", false, true},     // prerelease orders below its release
		{"v1.4.0", "1.4.0", true, true},          // tolerate a leading v
		{"not.a.version", "1.4.0", false, false}, // unparseable → fail open
		{"1.4.0", "garbage", false, false},
	}
	for _, c := range cases {
		outside, ok := npmVersionOutsideRange(c.ver, c.upper)
		if outside != c.wantOutside || ok != c.wOK {
			t.Errorf("npmVersionOutsideRange(%q,%q)=(%v,%v) want (%v,%v)", c.ver, c.upper, outside, ok, c.wantOutside, c.wOK)
		}
	}
}

func TestNPMInRange_Operators(t *testing.T) {
	cases := []struct {
		ver, rng string
		want, ok bool
	}{
		// caret
		{"1.2.3", "^1.2.0", true, true},
		{"1.9.9", "^1.2.0", true, true},
		{"2.0.0", "^1.2.0", false, true},
		{"0.2.3", "^0.2.0", true, true},
		{"0.3.0", "^0.2.0", false, true}, // ^0.2.x caps at <0.3.0
		// caret 0.x edge cases (node-semver): ^0.0.3 → <0.0.4; ^0 → <1.0.0; ^0.0 → <0.1.0
		{"0.0.3", "^0.0.3", true, true},
		{"0.0.4", "^0.0.3", false, true}, // ^0.0.x caps at <0.0.(patch+1)
		{"0.5.0", "^0", true, true},      // ^0 admits all 0.x
		{"1.0.0", "^0", false, true},     // ^0 caps at <1.0.0
		{"0.0.9", "^0.0", true, true},
		{"0.1.0", "^0.0", false, true}, // ^0.0 caps at <0.1.0
		// tilde
		{"1.2.9", "~1.2.3", true, true},
		{"1.3.0", "~1.2.3", false, true},
		{"1.2.0", "~1.2", true, true},
		{"1.3.0", "~1.2", false, true},
		// x-range / partial
		{"1.5.0", "1.x", true, true},
		{"2.0.0", "1.x", false, true},
		{"1.2.9", "1.2", true, true},
		{"1.3.0", "1.2", false, true},
		// comparator conjunction
		{"1.5.0", ">=1.2.0 <2.0.0", true, true},
		{"2.0.0", ">=1.2.0 <2.0.0", false, true},
		{"1.1.0", ">=1.2.0 <2.0.0", false, true},
		// union ||
		{"3.0.0", "^1.0.0 || ^3.0.0", true, true},
		{"2.0.0", "^1.0.0 || ^3.0.0", false, true},
		// hyphen range
		{"1.3.0", "1.2.0 - 1.4.0", true, true},
		{"1.5.0", "1.2.0 - 1.4.0", false, true},
		// exact
		{"1.2.3", "1.2.3", true, true},
		{"1.2.4", "1.2.3", false, true},
		// star
		{"9.9.9", "*", true, true},
		// fail open on bad input
		{"bad", "^1.0.0", false, false},
	}
	for _, c := range cases {
		got, ok := npmVersionInRange(c.ver, c.rng)
		if got != c.want || ok != c.ok {
			t.Errorf("npmVersionInRange(%q,%q)=(%v,%v) want (%v,%v)", c.ver, c.rng, got, ok, c.want, c.ok)
		}
	}
}

func TestNPMInRange_PrereleaseIsolation(t *testing.T) {
	// A prerelease only satisfies a range when a comparator names the same tuple's
	// prereleases — node-semver's isolation rule. 1.2.3-beta does NOT satisfy ^1.0.0.
	got, ok := npmVersionInRange("1.2.3-beta", "^1.0.0")
	if !ok || got {
		t.Fatalf("1.2.3-beta must NOT satisfy ^1.0.0 (prerelease isolation); got=%v ok=%v", got, ok)
	}
	// It DOES satisfy a range that explicitly mentions that tuple's prereleases.
	got, ok = npmVersionInRange("1.2.3-beta.2", ">=1.2.3-beta.1 <2.0.0")
	if !ok || !got {
		t.Fatalf("1.2.3-beta.2 must satisfy >=1.2.3-beta.1 <2.0.0; got=%v ok=%v", got, ok)
	}
}

func TestNPMComparePrerelease(t *testing.T) {
	a, _ := parseNPMVersion("1.0.0-alpha.1")
	b, _ := parseNPMVersion("1.0.0-alpha.2")
	if compareNPMVersion(a, b) >= 0 {
		t.Fatal("1.0.0-alpha.1 < 1.0.0-alpha.2")
	}
	rel, _ := parseNPMVersion("1.0.0")
	if compareNPMVersion(a, rel) >= 0 {
		t.Fatal("1.0.0-alpha.1 < 1.0.0 (prerelease below release)")
	}
	// numeric identifier < alphanumeric identifier
	n, _ := parseNPMVersion("1.0.0-1")
	al, _ := parseNPMVersion("1.0.0-alpha")
	if compareNPMVersion(n, al) >= 0 {
		t.Fatal("1.0.0-1 < 1.0.0-alpha (numeric id has lower precedence)")
	}
}
