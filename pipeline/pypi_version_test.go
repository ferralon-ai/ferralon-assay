// internal/pipeline/pypi_version_test.go
//
// Unit proof of the PEP 440 comparator + specifier matcher backing the Python (PyPI)
// disqualification axis. It exercises the gotchas that break a naive port: epochs
// ("1!" always wins), variable-length release with trailing-zero insignificance,
// pre/post/dev ordering (dev < pre < final < post), the "~=" compatible-release
// operator, "+local" ordering (numeric > alphabetic — the REVERSE of npm), and the
// fail-OPEN contract (ok=false on anything outside the grammar, so the predicate never
// fabricates a not-affected).
package pipeline

import "testing"

func TestPEP440Ordering(t *testing.T) {
	// Each pair is strictly-less: comparePEP440(lo, hi) must be < 0 (and the reverse > 0).
	pairs := []struct{ lo, hi string }{
		// variable-length release + trailing-zero insignificance
		{"1.0", "1.1"},
		{"1.9.0", "1.10.0"}, // numeric, not lexical
		{"1.0.1", "1.1"},
		// epoch always wins, regardless of release
		{"1.0", "1!0.1"},
		{"9999.0", "1!1.0"},
		// pre-release sorts BELOW its final release
		{"1.0a1", "1.0"},
		{"1.0a1", "1.0b1"},
		{"1.0b1", "1.0rc1"},
		{"1.0rc1", "1.0"},
		{"1.0a1", "1.0a2"},
		// post-release sorts ABOVE its final release
		{"1.0", "1.0.post1"},
		{"1.0.post1", "1.0.post2"},
		{"1.0rc1", "1.0.post1"},
		// dev sorts BELOW everything for the same release, even below a pre
		{"1.0.dev1", "1.0a1"},
		{"1.0.dev1", "1.0"},
		{"1.0a1.dev1", "1.0a1"},
		{"1.0.dev1", "1.0.dev2"},
		// full canonical chain: dev < a < b < rc < final < post
		{"1.0.dev0", "1.0a1"},
		{"1.0a1", "1.0"},
		{"1.0", "1.0.post0"},
		// local version sorts ABOVE the same version without one
		{"1.0", "1.0+local"},
		{"1.0+1", "1.0+2"},
		{"1.0+1.0", "1.0+1.1"},
	}
	for _, p := range pairs {
		lo, ok1 := parsePEP440(p.lo)
		hi, ok2 := parsePEP440(p.hi)
		if !ok1 || !ok2 {
			t.Fatalf("parse failed for %q/%q (ok=%v,%v)", p.lo, p.hi, ok1, ok2)
		}
		if c := comparePEP440(lo, hi); c >= 0 {
			t.Errorf("comparePEP440(%q,%q)=%d, want <0", p.lo, p.hi, c)
		}
		if c := comparePEP440(hi, lo); c <= 0 {
			t.Errorf("comparePEP440(%q,%q)=%d, want >0", p.hi, p.lo, c)
		}
	}
}

func TestPEP440Equality(t *testing.T) {
	// Normalization + trailing-zero + separator/alias equivalence: these must compare equal.
	equal := [][2]string{
		{"1.0", "1.0.0"},         // trailing zeros insignificant
		{"1.0a1", "1.0.a.1"},     // separators ('.') equivalent
		{"1.0a1", "1.0-alpha-1"}, // alpha alias + dash separators
	}
	for _, e := range equal {
		a, ok1 := parsePEP440(e[0])
		b, ok2 := parsePEP440(e[1])
		if !ok1 || !ok2 {
			t.Fatalf("parse failed for %q/%q", e[0], e[1])
		}
		if c := comparePEP440(a, b); c != 0 {
			t.Errorf("comparePEP440(%q,%q)=%d, want 0 (equal)", e[0], e[1], c)
		}
	}
	// pre-alias c/pre/preview all normalize to rc; alpha→a; beta→b.
	for _, e := range [][2]string{{"1.0c1", "1.0rc1"}, {"1.0preview1", "1.0rc1"}, {"1.0beta2", "1.0b2"}} {
		a, _ := parsePEP440(e[0])
		b, _ := parsePEP440(e[1])
		if c := comparePEP440(a, b); c != 0 {
			t.Errorf("alias %q must equal %q; got %d", e[0], e[1], c)
		}
	}
}

func TestPEP440LocalNumericAboveAlpha(t *testing.T) {
	// The REVERSE of npm: a numeric local segment sorts ABOVE an alphabetic one.
	a, _ := parsePEP440("1.0+1")
	b, _ := parsePEP440("1.0+abc")
	if c := comparePEP440(a, b); c <= 0 {
		t.Fatalf("1.0+1 must sort ABOVE 1.0+abc (numeric > alpha in PEP440 local); got %d", c)
	}
}

func TestPEP440ImplicitPost(t *testing.T) {
	// The implicit post form "1.0-1" == "1.0.post1", and a post-release sorts ABOVE its
	// final release. Asserted behaviorally (via comparePEP440) so the test does not couple
	// to the parsed struct's unexported fields, which now live in the shared pep440 package.
	a, ok := parsePEP440("1.0-1")
	if !ok {
		t.Fatalf("1.0-1 must parse")
	}
	post1, _ := parsePEP440("1.0.post1")
	if c := comparePEP440(a, post1); c != 0 {
		t.Fatalf("1.0-1 must equal 1.0.post1; got %d", c)
	}
	final, _ := parsePEP440("1.0")
	if c := comparePEP440(a, final); c <= 0 {
		t.Fatalf("1.0-1 (post-release) must sort ABOVE 1.0; got %d", c)
	}
}

func TestPypiOutsideRange(t *testing.T) {
	cases := []struct {
		ver, upper       string
		wantOutside, wOK bool
	}{
		{"1.4.0", "1.4.0", true, true},           // == upper → outside (affects < upper)
		{"1.4.1", "1.4.0", true, true},           // > upper
		{"1.3.9", "1.4.0", false, true},          // < upper → inside affected
		{"2.0.0", "1.4.0", true, true},           // major bump
		{"1.10.0", "1.9.0", true, true},          // numeric ordering, not lexical
		{"1.4.0a1", "1.4.0", false, true},        // prerelease sorts below its release → inside
		{"1.4.0.post1", "1.4.0", true, true},     // post sorts above → outside
		{"1!0.1", "1.4.0", true, true},           // epoch wins
		{"1.4", "1.4.0", true, true},             // trailing-zero equality → == upper → outside
		{"v1.4.0", "1.4.0", true, true},          // tolerate a leading v
		{"not.a.version", "1.4.0", false, false}, // unparseable → fail open
		{"1.4.0", "garbage", false, false},       // unparseable bound → fail open
		{"1.0.0+deadbeef", "1.0.0", true, true},  // local sorts above → outside
	}
	for _, c := range cases {
		outside, ok := pypiVersionOutsideRange(c.ver, c.upper)
		if outside != c.wantOutside || ok != c.wOK {
			t.Errorf("pypiVersionOutsideRange(%q,%q)=(%v,%v) want (%v,%v)", c.ver, c.upper, outside, ok, c.wantOutside, c.wOK)
		}
	}
}

func TestPypiInRange(t *testing.T) {
	cases := []struct {
		ver, spec string
		want, ok  bool
	}{
		// comparators + AND conjunction
		{"1.5.0", ">=1.2.0,<2.0.0", true, true},
		{"2.0.0", ">=1.2.0,<2.0.0", false, true},
		{"1.1.0", ">=1.2.0,<2.0.0", false, true},
		{"1.2.0", ">=1.2.0", true, true},
		{"1.2.0", ">1.2.0", false, true},
		{"1.2.0", "<=1.2.0", true, true},
		// ~= compatible-release
		{"1.4.9", "~=1.4.5", true, true},
		{"1.5.0", "~=1.4.5", false, true}, // ~=1.4.5 caps at <1.5.0
		{"1.4.4", "~=1.4.5", false, true}, // below floor
		{"1.9.0", "~=1.4", true, true},    // ~=1.4 admits all 1.x
		{"2.0.0", "~=1.4", false, true},   // ~=1.4 caps at <2.0
		{"1.4", "~=1", false, false},      // single-component operand → fail open
		// == prefix match
		{"1.4.7", "==1.4.*", true, true},
		{"1.5.0", "==1.4.*", false, true},
		{"1.4", "==1.4.*", true, true},
		// == exact + != exclusion
		{"1.4.0", "==1.4.0", true, true},
		{"1.4.1", "==1.4.0", false, true},
		{"1.4.1", "!=1.4.0", true, true},
		{"1.4.7", "!=1.4.*", false, true}, // excluded by prefix
		{"1.5.0", "!=1.4.*", true, true},
		// === arbitrary string equality
		{"1.0+ubuntu1", "===1.0+ubuntu1", true, true},
		{"1.0", "===1.0.0", false, true}, // string-exact, not normalized
		// epoch-aware
		{"1!1.0", ">=1!0", true, true},
		{"1.0", "<1!0", true, true},
		// fail open on bad input
		{"bad", ">=1.0", false, false},
		{"1.0", ">=bad", false, false},
	}
	for _, c := range cases {
		got, ok := pypiVersionInRange(c.ver, c.spec)
		if got != c.want || ok != c.ok {
			t.Errorf("pypiVersionInRange(%q,%q)=(%v,%v) want (%v,%v)", c.ver, c.spec, got, ok, c.want, c.ok)
		}
	}
}
