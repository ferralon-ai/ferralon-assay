package dotnetanalysis

import "testing"

// nugetRange must put a PackageReference version and the lock's "requested" for it in the same
// form, or a current lock reads as stale; a spec it can't normalize must never match.
func TestNugetRange(t *testing.T) {
	cases := []struct{ spec, want string }{
		{"13.0.1", "[13.0.1, )"},
		{"[13.0.1]", "[13.0.1, 13.0.1]"},
		{"[13.0.1, 13.0.1]", "[13.0.1, 13.0.1]"},
		{"[1.0,2.0)", "[1.0.0, 2.0.0)"},
		{"(,2.0]", "(, 2.0.0]"},
		{"13.0", "[13.0.0, )"},
		{"1.0.0.0", "[1.0.0, )"},
		{"1.0.0.4", "[1.0.0.4, )"},
		{"01.2.3", "[1.2.3, )"},
		{"1.0-Beta+build", "[1.0.0-beta, )"},
		{"1.*", ""},
		{"[1.0", ""},
		{"(1.0)", ""},
		{"[,]", ""},
		{"$(V)", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got, ok := nugetRange(tc.spec)
		if ok != (tc.want != "") || got != tc.want {
			t.Errorf("nugetRange(%q) = %q, %v; want %q", tc.spec, got, ok, tc.want)
		}
	}
}
