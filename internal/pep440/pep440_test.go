package pep440

import "testing"

// mustParse parses a version the test author asserts is valid, failing loudly otherwise so a
// grammar regression cannot masquerade as a comparison bug.
func mustParse(t *testing.T, s string) Version {
	t.Helper()
	v, ok := Parse(s)
	if !ok {
		t.Fatalf("Parse(%q) ok=false, want a valid version", s)
	}
	return v
}

// TestParse covers the grammar surface directly (until now pep440 rode only the pythonanalysis
// pipeline battery via forwarders; the extraction lands in the platform PR, so it needs its own
// package-local coverage). Valid PEP 440 spellings parse; anything outside the grammar fails
// OPEN (ok=false) so a caller never gets a confident ordering on an unmodelled string.
func TestParse(t *testing.T) {
	valid := []string{
		"1", "1.0", "1.0.0", "2.3.4",
		"1!1.0", // epoch
		"1.0a1", "1.0b2", "1.0rc3", "1.0.dev4", "1.0.post5",
		"1.0alpha1", "1.0.beta.2", "1.0-1", // alias spellings + implicit post
		"1.0+abc.1", "1.0+ubuntu.20.04", // local
		"v1.2.3", "  1.2.3  ", // leading v, surrounding space
	}
	for _, s := range valid {
		if _, ok := Parse(s); !ok {
			t.Errorf("Parse(%q) ok=false, want valid", s)
		}
	}

	invalid := []string{
		"", "abc", "1.0.x", "1..0", "not-a-version", "1.0.0-foo", "1,0",
	}
	for _, s := range invalid {
		if _, ok := Parse(s); ok {
			t.Errorf("Parse(%q) ok=true, want fail-open (invalid)", s)
		}
	}
}

// TestCompare exercises PEP 440's non-obvious ordering sentinels directly: trailing-zero
// insignificance, epoch dominance, pre < final, post > final, dev below everything for a
// release, and the reversed local-segment rule (numeric > alphabetic).
func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0.0", 0}, // trailing zeros insignificant
		{"1.0", "1.0.1", -1},
		{"2!1.0", "1.0", 1},       // epoch dominates
		{"1.0a1", "1.0", -1},      // pre sorts below final
		{"1.0", "1.0.post1", -1},  // post sorts above final
		{"1.0.dev1", "1.0a1", -1}, // dev-only sorts below any pre
		{"1.0.dev1", "1.0", -1},   // dev sorts below its release
		{"1.0a1", "1.0a2", -1},    // pre number
		{"1.0a1", "1.0b1", -1},    // pre kind a<b
		{"1.0b1", "1.0rc1", -1},   // pre kind b<rc
		{"1.0.post1", "1.0.post2", -1},
		{"1.0+1", "1.0", 1},      // a local sorts above no local
		{"1.0+abc", "1.0+1", -1}, // numeric local segment sorts ABOVE alphabetic (reverse of npm)
		{"1.0", "1.0", 0},
	}
	for _, c := range cases {
		got := Compare(mustParse(t, c.a), mustParse(t, c.b))
		if got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		// Antisymmetry: reversing the operands negates the result.
		if rev := Compare(mustParse(t, c.b), mustParse(t, c.a)); rev != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, rev, -c.want)
		}
	}
}

// TestSatisfies covers each specifier operator, the "==X.Y.*" prefix form, and the fail-open
// contract: an unparseable operator or operand yields ok=false so the caller never fabricates a
// confident match.
func TestSatisfies(t *testing.T) {
	cases := []struct {
		ver, clause string
		wantSat     bool
		wantOK      bool
	}{
		{"1.2.3", "==1.2.3", true, true},
		{"1.2.3", "==1.2.4", false, true},
		{"1.2.3", "!=1.2.3", false, true},
		{"1.2.3", "!=2.0.0", true, true},
		{"1.2.3", ">=1.0.0", true, true},
		{"1.2.3", ">=2.0.0", false, true},
		{"1.2.3", "<=1.2.3", true, true},
		{"1.2.3", ">1.2.3", false, true},
		{"1.2.3", "<2.0.0", true, true},
		{"1.4.0", "==1.4.*", true, true},  // prefix match
		{"1.5.0", "==1.4.*", false, true}, // prefix mismatch
		{"1.4.5", "~=1.4.0", true, true},  // compatible: >=1.4.0,<1.5
		{"1.5.0", "~=1.4.0", false, true}, // compatible ceiling
		{"1.2.3", "===1.2.3", true, true}, // arbitrary-string equality
		{"1.2.3", "===1.2.3.0", false, true},
		{"1.2.3", "~=1", false, false},             // ~= needs >=2 release components -> fail open
		{"1.2.3", "@@1.2.3", false, false},         // unknown operator -> fail open
		{"1.2.3", ">=not-a-version", false, false}, // unparseable operand -> fail open
	}
	for _, c := range cases {
		v := mustParse(t, c.ver)
		sat, ok := Satisfies(v, c.ver, c.clause)
		if sat != c.wantSat || ok != c.wantOK {
			t.Errorf("Satisfies(%q, %q) = (%v, %v), want (%v, %v)", c.ver, c.clause, sat, ok, c.wantSat, c.wantOK)
		}
	}
}
