package pipeline

import "testing"

// TestParityShape_OutOfRange is the PLAN-070 out-of-range fixture arm. The fixture
// corpus/testdata/repros/TEGRON-PY-JINJA2-SSTI-0001-OUTOFRANGE declares Jinja2==3.1.2
// (requirements.txt) against advisory TEGRON-PY-JINJA2-SSTI-0001 (affects < 2.11.3). The
// exercised arm is the PyPI disqualification comparator (pypi_version.go:42): a declared
// version provably >= the advisory upper bound must return (outside=true, ok=true), the
// version-disqualified arm. Both operands must parse as PEP 440 -- an un-parseable operand
// fails OPEN to (false,false), which would be the WRONG arm, so the control rows assert
// that too. This test lives in package pipeline because the arm is the unexported
// pipeline-side comparator, not the pythonanalysis scanner.
func TestParityShape_OutOfRange(t *testing.T) {
	// From the fixture metadata: declared installed version and advisory upper bound.
	const (
		installed = "3.1.2"  // requirements.txt: Jinja2==3.1.2
		upper     = "2.11.3" // advisory: affects < 2.11.3
	)

	cases := []struct {
		name        string
		ver, upper  string
		wantOutside bool
		wantOK      bool
	}{
		// The fixture's arm: 3.1.2 is provably >= 2.11.3 -> disqualified, ok.
		{"fixture_out_of_range", installed, upper, true, true},
		// Control: a version inside the affected range is NOT disqualified (ok, not outside).
		{"inside_range_not_disqualified", "2.10.0", upper, false, true},
		// Control: equal to the upper bound is still >= upper -> outside (bound is exclusive: affects < upper).
		{"equal_to_upper_is_outside", upper, upper, true, true},
		// Control: an un-parseable operand fails OPEN to (false,false) -- the wrong arm the
		// fixture must NOT accidentally land on.
		{"unparseable_fails_open", "not-a-version", upper, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outside, ok := pypiVersionOutsideRange(tc.ver, tc.upper)
			if outside != tc.wantOutside || ok != tc.wantOK {
				t.Fatalf("pypiVersionOutsideRange(%q,%q) = (%v,%v); want (%v,%v)",
					tc.ver, tc.upper, outside, ok, tc.wantOutside, tc.wantOK)
			}
		})
	}
}
