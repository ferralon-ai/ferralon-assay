package pipeline

import "testing"

// Go corpus records publish bounds as OSV writes them: no "v" prefix, pre-release and
// pseudo-versions, and Docker-style leading zeros. Installed versions come from go.mod, "v"-prefixed.
func TestVersionOutsideRange_GoModPublishedBoundShapes(t *testing.T) {
	tests := []struct {
		name        string
		ver         string
		rng         affectedRange
		wantOutside bool
		wantOK      bool
	}{
		{"unprefixed fixed", "v0.33.0", affectedRange{LowerInclusive: "0", UpperExclusive: "0.17.0"}, true, true},
		{"pseudo-version fixed", "v0.33.0", affectedRange{LowerInclusive: "0", UpperExclusive: "0.0.0-20190813141303-74dc4d7220e7"}, true, true},
		{"pre-release introduced and fixed", "v0.31.1", affectedRange{LowerInclusive: "0.20.0-alpha.0", UpperExclusive: "0.20.0-alpha.2"}, true, true},
		{"docker leading zero fixed", "v27.1.1+incompatible", affectedRange{LowerInclusive: "0", UpperExclusive: "18.09.8"}, true, true},
		{"docker -ce fixed", "v27.1.1+incompatible", affectedRange{LowerInclusive: "0", UpperExclusive: "17.06.0-ce"}, true, true},
		{"unprefixed fixed, installed below", "v1.7.20", affectedRange{LowerInclusive: "0", UpperExclusive: "1.7.29"}, false, true},
		{"inside rc introduced range", "v27.1.1+incompatible", affectedRange{LowerInclusive: "26.0.0-rc1", UpperExclusive: "28.0.0"}, false, true},
		{"own module past beta fixed", "v3.3.2", affectedRange{LowerInclusive: "0", UpperExclusive: "3.0.0-beta5"}, true, true},
		{"installed pseudo-version fails open", "v0.0.0-20210101000000-abcdef123456", affectedRange{LowerInclusive: "0", UpperExclusive: "1.5.0"}, false, false},
		{"unprefixed installed fails open", "2.4.0", affectedRange{LowerInclusive: "0", UpperExclusive: "2.3.2"}, false, false},
		{"garbage bound fails open", "v1.0.0", affectedRange{LowerInclusive: "0", UpperExclusive: "not-a-version"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outside, ok := versionOutsideRange(tt.ver, tt.rng)
			if outside != tt.wantOutside || ok != tt.wantOK {
				t.Fatalf("versionOutsideRange(%q, %+v) = (%v, %v), want (%v, %v)", tt.ver, tt.rng, outside, ok, tt.wantOutside, tt.wantOK)
			}
		})
	}
}

func TestCanonicalGoModVersion(t *testing.T) {
	tests := []struct{ in, want string }{
		{"0.17.0", "v0.17.0"},
		{"v1.2.3", "v1.2.3"},
		{"18.09.8", "v18.9.8"},
		{"17.06.0-ce", "v17.6.0-ce"},
		{"0.0.0-20190813141303-74dc4d7220e7", "v0.0.0-20190813141303-74dc4d7220e7"},
		{"3.0.0-beta5", "v3.0.0-beta5"},
		{"", ""},
		{"garbage", ""},
	}
	for _, tt := range tests {
		got, ok := canonicalGoModVersion(tt.in)
		if got != tt.want && !(tt.want == "" && !ok) {
			t.Errorf("canonicalGoModVersion(%q) = %q, %v; want %q", tt.in, got, ok, tt.want)
		}
	}
}
