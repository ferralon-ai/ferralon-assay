// internal/pipeline/disqual_nuget_test.go
//
// Unit proof of the NuGet (NuGet.Versioning) comparator + interval matcher backing the
// .NET/C# disqualification axis. NuGet is the hardest scheme: FOUR numeric segments,
// bare-version-means-MINIMUM-INCLUSIVE (not exact), bracketed intervals ([ ] inclusive,
// ( ) exclusive, ±∞ on a missing endpoint), case-insensitive SemVer2 prerelease ordering,
// and floating tokens that must be declined. ANY input outside the modelled grammar must
// return ok=false so the disqualification predicate fails OPEN (inv.5) — never a fabricated
// not-affected.
package pipeline

import "testing"

// The four numeric segments: 1 == 1.0 == 1.0.0 == 1.0.0.0, and a non-zero Revision orders
// above the same core, NUMERICALLY (not lexically: 1.0.0.10 > 1.0.0.2).
func TestNuGetCompare_FourSegmentEquivalenceAndOrdering(t *testing.T) {
	equalForms := []string{"1", "1.0", "1.0.0", "1.0.0.0"}
	base, _ := parseNuGetVersion(equalForms[0])
	for _, f := range equalForms[1:] {
		v, ok := parseNuGetVersion(f)
		if !ok || compareNuGetVersion(base, v) != 0 {
			t.Errorf("%q must equal %q (missing segments default to 0)", f, equalForms[0])
		}
	}
	// Leading zeroes are insignificant; a zero-padded build is equal.
	if a, _ := parseNuGetVersion("1.01.1"); compareNuGetVersion(a, mustNuGet(t, "1.1.1")) != 0 {
		t.Error("1.01.1 must equal 1.1.1 (leading zeroes insignificant)")
	}
	// Build metadata never affects ordering.
	if a, _ := parseNuGetVersion("1.0.0+meta"); compareNuGetVersion(a, mustNuGet(t, "1.0.0")) != 0 {
		t.Error("build metadata must not affect ordering")
	}
	// Revision segment participates and is compared numerically.
	if compareNuGetVersion(mustNuGet(t, "1.0.0.5"), mustNuGet(t, "1.0.0")) <= 0 {
		t.Error("1.0.0.5 > 1.0.0 (revision)")
	}
	if compareNuGetVersion(mustNuGet(t, "1.0.0.10"), mustNuGet(t, "1.0.0.2")) <= 0 {
		t.Error("1.0.0.10 > 1.0.0.2 (numeric, not lexical, revision ordering)")
	}
}

// SemVer2 prerelease ordering: a release sorts ABOVE any prerelease; dotted identifiers
// compare left-to-right with numeric-vs-alphanumeric precedence; prerelease is
// CASE-INSENSITIVE.
func TestNuGetCompare_PrereleaseOrdering(t *testing.T) {
	if compareNuGetVersion(mustNuGet(t, "1.0.0-rc.1"), mustNuGet(t, "1.0.0")) >= 0 {
		t.Error("1.0.0-rc.1 < 1.0.0 (release sorts above prerelease)")
	}
	if compareNuGetVersion(mustNuGet(t, "1.0.1-rc.10"), mustNuGet(t, "1.0.1-rc.2")) <= 0 {
		t.Error("1.0.1-rc.10 > 1.0.1-rc.2 (numeric prerelease identifier ordering)")
	}
	// Case-insensitive: 1.0.0-Alpha == 1.0.0-alpha.
	if compareNuGetVersion(mustNuGet(t, "1.0.0-Alpha"), mustNuGet(t, "1.0.0-alpha")) != 0 {
		t.Error("prerelease comparison must be case-insensitive")
	}
	// Numeric identifier < alphanumeric identifier.
	if compareNuGetVersion(mustNuGet(t, "1.0.0-1"), mustNuGet(t, "1.0.0-alpha")) >= 0 {
		t.Error("1.0.0-1 < 1.0.0-alpha (numeric id has lower precedence)")
	}
}

// nugetVersionOutsideRange maps the advisory "affects < upper" bound: outside == ver>=upper.
func TestNuGetOutsideRange(t *testing.T) {
	cases := []struct {
		ver, upper       string
		wantOutside, wOK bool
	}{
		{"1.4.0", "1.4.0", true, true},       // == upper → outside (affects < upper)
		{"1.4.1", "1.4.0", true, true},       // > upper
		{"1.3.9", "1.4.0", false, true},      // < upper → inside affected
		{"2.0.0", "1.4.0", true, true},       // major bump
		{"1.0.0.5", "1.0.0", true, true},     // revision above core
		{"1.4.0-rc.1", "1.4.0", false, true}, // prerelease orders below its release
		{"not.a.version", "1.4.0", false, false},
		{"1.4.0", "garbage!", false, false}, // out-of-alphabet upper → fail open
		{"1.0.*", "1.4.0", false, false},    // floating ver → fail open
		{"1.4.0", "1.0.*", false, false},    // floating upper → fail open
	}
	for _, c := range cases {
		outside, ok := nugetVersionOutsideRange(c.ver, c.upper)
		if outside != c.wantOutside || ok != c.wOK {
			t.Errorf("nugetVersionOutsideRange(%q,%q)=(%v,%v) want (%v,%v)", c.ver, c.upper, outside, ok, c.wantOutside, c.wOK)
		}
	}
}

// The full §2b interval / bracket table. [ ] inclusive, ( ) exclusive, a missing endpoint
// = ±∞, a BARE version = minimum-inclusive (NOT exact), and "[1.0]" the only exact form.
func TestNuGetInRange_IntervalTable(t *testing.T) {
	cases := []struct {
		ver, rng string
		want, ok bool
	}{
		// bare "1.0" == minimum-inclusive x>=1.0 (the critical gotcha: NOT exact).
		{"1.0", "1.0", true, true},
		{"2.5", "1.0", true, true},
		{"0.9", "1.0", false, true},
		// "[1.0,)" == x>=1.0
		{"1.0", "[1.0,)", true, true},
		{"0.9", "[1.0,)", false, true},
		// "(1.0,)" == x>1.0
		{"1.0", "(1.0,)", false, true},
		{"1.0.1", "(1.0,)", true, true},
		// "[1.0]" == x==1.0 (the only exact form)
		{"1.0", "[1.0]", true, true},
		{"1.0.0", "[1.0]", true, true}, // 1.0.0 == 1.0
		{"1.0.1", "[1.0]", false, true},
		{"0.9", "[1.0]", false, true},
		// "(,1.0]" == x<=1.0
		{"1.0", "(,1.0]", true, true},
		{"1.0.1", "(,1.0]", false, true},
		// "(,1.0)" == x<1.0
		{"0.9", "(,1.0)", true, true},
		{"1.0", "(,1.0)", false, true},
		// "[1.0,2.0]" == 1.0<=x<=2.0
		{"1.0", "[1.0,2.0]", true, true},
		{"2.0", "[1.0,2.0]", true, true},
		{"2.0.1", "[1.0,2.0]", false, true},
		// "(1.0,2.0)" == 1.0<x<2.0
		{"1.0", "(1.0,2.0)", false, true},
		{"1.5", "(1.0,2.0)", true, true},
		{"2.0", "(1.0,2.0)", false, true},
		// "[1.0,2.0)" == 1.0<=x<2.0 (the common "affected < 2.0 fixed-in" shape)
		{"1.0", "[1.0,2.0)", true, true},
		{"1.9.9", "[1.0,2.0)", true, true},
		{"2.0", "[1.0,2.0)", false, true},
		// whitespace inside the interval is tolerated.
		{"1.5", "[1.0, 2.0)", true, true},
	}
	for _, c := range cases {
		got, ok := nugetVersionInRange(c.ver, c.rng)
		if got != c.want || ok != c.ok {
			t.Errorf("nugetVersionInRange(%q,%q)=(%v,%v) want (%v,%v)", c.ver, c.rng, got, ok, c.want, c.ok)
		}
	}
}

// Floating tokens are manifest-side resolution hints (§2c), not advisory ranges — the
// comparator recognizes them and DECLINES the ordering decision (fail open, §2e), never
// crashing.
func TestNuGetInRange_FloatingFailsOpen(t *testing.T) {
	for _, tok := range []string{"1.0.*", "1.*", "*", "[1.*,2.0)"} {
		if _, ok := nugetVersionInRange("1.5", tok); ok {
			t.Errorf("floating range %q must fail open (ok=false)", tok)
		}
		if _, ok := nugetVersionOutsideRange("1.5", tok); ok {
			t.Errorf("floating upper %q must fail open (ok=false)", tok)
		}
	}
	// A floating VERSION operand also fails open.
	if _, ok := nugetVersionInRange("1.0.*", "[1.0,2.0)"); ok {
		t.Error("floating version operand must fail open")
	}
}

// EVERY §2e fail-open case: the honesty guard. Each must return ok=false, never a confident
// (possibly wrong) match/ordering.
func TestNuGetInRange_FailOpenCases(t *testing.T) {
	failOpen := []string{
		"",              // empty string
		"(1.0)",         // single-value parens — invalid
		"(1.0]",         // mismatched single-value bracket
		"[1.0)",         // mismatched single-value bracket
		"[2.0,1.0]",     // inverted interval
		"(1.0,1.0)",     // empty interval (equal endpoints, exclusive)
		"[1.0,1.0)",     // empty interval (half-exclusive)
		"[,]",           // both endpoints missing
		"(,)",           // both endpoints missing
		"[1.0,2.0,3.0]", // more than one comma
		"[1.2.3.4.5,)",  // >4 segments in an endpoint
		"[1.x,)",        // non-numeric core segment
		"[1.0-,)",       // empty prerelease identifier
		"[1.0,)extra",   // trailing junk after close bracket
		"[1.0;2.0)",     // out-of-alphabet character
	}
	for _, rng := range failOpen {
		if _, ok := nugetVersionInRange("1.5", rng); ok {
			t.Errorf("range %q must FAIL OPEN (ok=false), got a confident answer", rng)
		}
	}
	// A version operand outside the grammar also fails open.
	badVers := []string{"", "1.2.3.4.5", "1.x", "1.0-", "1.0;0", "abc"}
	for _, v := range badVers {
		if _, ok := nugetVersionInRange(v, "[1.0,2.0)"); ok {
			t.Errorf("version %q must FAIL OPEN (ok=false)", v)
		}
		if _, ok := nugetVersionOutsideRange(v, "1.0"); ok {
			t.Errorf("version %q must FAIL OPEN in outside-range too", v)
		}
	}
}

func mustNuGet(t *testing.T, s string) nugetVersion {
	t.Helper()
	v, ok := parseNuGetVersion(s)
	if !ok {
		t.Fatalf("parseNuGetVersion(%q) failed", s)
	}
	return v
}
