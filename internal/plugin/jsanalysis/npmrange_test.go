package jsanalysis

import "testing"

func TestRangeSatisfied(t *testing.T) {
	tests := []struct {
		version, spec string
		want          bool
	}{
		{"1.2.3", "1.2.3", true},
		{"1.2.3", "=1.2.3", true},
		{"1.2.4", "1.2.3", false},
		{"1.2.3", ">=1.2.3", true},
		{"1.2.2", ">=1.2.3", false},
		{"1.2.3", ">1.2.3", false},
		{"1.2.4", ">1.2.3", true},
		{"1.9.9", "<2.0.0", true},
		{"2.0.0", "<2.0.0", false},
		{"2.0.0", "<=2.0.0", true},
		{"1.5.0", ">=1.2.3 <2.0.0", true},
		{"2.0.0", ">=1.2.3 <2.0.0", false},
		{"1.0.0", ">=1.2.3 <2.0.0", false},

		// Caret: below the next release of the left-most non-zero part.
		{"1.2.3", "^1.2.3", true},
		{"1.9.0", "^1.2.3", true},
		{"2.0.0", "^1.2.3", false},
		{"1.2.2", "^1.2.3", false},
		{"0.2.5", "^0.2.3", true},
		{"0.3.0", "^0.2.3", false},
		{"0.2.2", "^0.2.3", false},
		{"0.0.3", "^0.0.3", true},
		{"0.0.4", "^0.0.3", false},
		{"0.1.0", "^0.0.3", false},
		{"0.0.0", "^0.0.0", true},
		{"0.0.1", "^0.0.0", false},
		{"1.0.0", "^0.9.0", false},
		{"1.2.5", "^0.2.3", false},
		{"1.0.3", "^0.0.3", false},

		// Tilde: below the next minor.
		{"1.2.9", "~1.2.3", true},
		{"1.3.0", "~1.2.3", false},
		{"1.2.2", "~1.2.3", false},
		{"0.2.9", "~0.2.3", true},

		// Prerelease and build metadata, either side: withheld.
		{"1.3.0-rc.1", "^1.2.3", false},
		{"1.2.3-beta", "1.2.3-beta", false},
		{"1.2.3", "^1.2.3-beta", false},
		{"1.2.4", ">=1.2.3-0", false},
		{"1.2.3+build", "1.2.3", false},
		{"1.2.3", "1.2.3+build", false},

		// Forms not modelled: withheld.
		{"1.2.3", "", false},
		{"1.2.3", "*", false},
		{"1.2.3", "x", false},
		{"1.2.3", "latest", false},
		{"1.2.3", "1", false},
		{"1.2.3", "1.2", false},
		{"1.2.3", "1.x", false},
		{"1.2.3", "1.2.x", false},
		{"1.2.3", "^1.2", false},
		{"1.2.3", "~1", false},
		{"1.2.3", "1.0.0 - 2.0.0", false},
		{"1.2.3", "^1.0.0 || ^2.0.0", false},
		{"1.2.3", "v1.2.3", false},
		{"1.2.3", ">= 1.2.3", false},
		{"1.2.3", "~>1.2.3", false},
		{"1.2.3", "npm:other@^1.2.3", false},
		{"1.2.3", "workspace:^1.2.3", false},
		{"1.2.3", "file:../x", false},
		{"1.2.3", "github:user/repo#v1.2.3", false},
		{"1.2.3", "git+https://example.com/x.git#1.2.3", false},
		{"1.2.3", "https://example.com/x-1.2.3.tgz", false},
		{"1.2.3", "^01.2.3", false},
		{"01.2.3", "^1.2.3", false},
		{"9007199254740992.0.0", ">=1.0.0", false},
		{"npm:other@1.2.3", "^1.2.3", false},
		{"", "^1.2.3", false},
		{"1.2", "^1.2.3", false},
	}
	for _, tt := range tests {
		if got := rangeSatisfied(tt.version, tt.spec); got != tt.want {
			t.Errorf("rangeSatisfied(%q, %q) = %v, want %v", tt.version, tt.spec, got, tt.want)
		}
	}
}
