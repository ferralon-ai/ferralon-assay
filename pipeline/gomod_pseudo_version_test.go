package pipeline

import "testing"

func TestCompareGoModVersions_InstalledPseudoVersion(t *testing.T) {
	const (
		untagged2021 = "v0.0.0-20210101000000-abcdef123456"
		untagged2022 = "v0.0.0-20220101000000-123456abcdef"
		after123     = "v1.2.4-0.20220101000000-abcdef123456"
		afterPre     = "v1.3.0-rc.1.0.20220101000000-abcdef123456"
	)
	tests := []struct {
		name   string
		a, b   string
		want   int
		wantOK bool
	}{
		{name: "untagged after an untagged bound", a: untagged2022, b: "0.0.0-20210101000000-abcdef123456", want: 1, wantOK: true},
		{name: "untagged before an untagged bound", a: untagged2021, b: "0.0.0-20220101000000-123456abcdef", want: -1, wantOK: true},
		{name: "same commit", a: untagged2021, b: "0.0.0-20210101000000-abcdef123456", want: 0, wantOK: true},
		{name: "same time, another revision", a: untagged2021, b: "0.0.0-20210101000000-ffffff123456", wantOK: false},
		{name: "untagged against a release bound", a: untagged2022, b: "1.5.0", wantOK: false},
		{name: "untagged against the zero release", a: untagged2022, b: "0.0.0", wantOK: false},
		{name: "untagged against a pre-release bound", a: untagged2022, b: "0.0.0-alpha.1", wantOK: false},
		{name: "untagged bounds under different majors", a: "v2.0.0-20220101000000-abcdef123456", b: "0.0.0-20210101000000-abcdef123456", wantOK: false},
		{name: "untagged against a based pseudo bound", a: untagged2022, b: "1.2.4-0.20210101000000-abcdef123456", wantOK: false},
		{name: "based against an untagged pseudo bound", a: after123, b: "0.0.0-20210101000000-abcdef123456", wantOK: false},
		{name: "based, bound at its base", a: after123, b: "1.2.3", want: 1, wantOK: true},
		{name: "based, bound below its base", a: after123, b: "1.2.0", want: 1, wantOK: true},
		{name: "based, bound a pre-release of its base", a: after123, b: "1.2.3-rc.1", want: 1, wantOK: true},
		{name: "based, bound the next patch", a: after123, b: "1.2.4", wantOK: false},
		{name: "based, bound a later minor", a: after123, b: "1.3.0", wantOK: false},
		{name: "based, same base later bound", a: after123, b: "1.2.4-0.20230101000000-abcdef123456", want: -1, wantOK: true},
		{name: "based, same base earlier bound", a: after123, b: "1.2.4-0.20210101000000-abcdef123456", want: 1, wantOK: true},
		{name: "based, another base", a: after123, b: "1.2.5-0.20210101000000-abcdef123456", wantOK: false},
		{name: "pre-release base, bound at that pre-release", a: afterPre, b: "1.3.0-rc.1", want: 1, wantOK: true},
		{name: "pre-release base, bound the release", a: afterPre, b: "1.3.0", wantOK: false},
		{name: "incompatible based past the bound", a: "v2.0.1-0.20220101000000-abcdef123456+incompatible", b: "2.0.0", want: 1, wantOK: true},
		{name: "tagged pre-release stays unordered", a: "v1.3.0-rc.1", b: "1.2.0", wantOK: false},
		{name: "release against a pseudo bound", a: "v0.33.0", b: "0.0.0-20190813141303-74dc4d7220e7", want: 1, wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := compareGoModVersions(tt.a, tt.b)
			if ok != tt.wantOK || (ok && got != tt.want) {
				t.Fatalf("compareGoModVersions(%q, %q) = (%d, %v), want (%d, %v)", tt.a, tt.b, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// A range's verdict on an installed pseudo-version: the knative.dev/pkg shape (untagged module,
// pseudo-version fix) and a module pinned to a commit after a tagged fix.
func TestVersionOutsideRange_InstalledPseudoVersion(t *testing.T) {
	tests := []struct {
		name        string
		ver         string
		rng         affectedRange
		wantOutside bool
		wantOK      bool
	}{
		{"untagged, past the pseudo fix", "v0.0.0-20260727151759-521cb33b33dd", affectedRange{LowerInclusive: "0", UpperExclusive: "0.0.0-20260531000007-52dbd5ece63f"}, true, true},
		{"untagged, before the pseudo fix", "v0.0.0-20260120122510-4a022ed9999a", affectedRange{LowerInclusive: "0", UpperExclusive: "0.0.0-20260531000007-52dbd5ece63f"}, false, true},
		{"untagged, before a pseudo introduced", "v0.0.0-20210101000000-abcdef123456", affectedRange{LowerInclusive: "0.0.0-20220101000000-abcdef123456", UpperExclusive: "0.0.0-20230101000000-abcdef123456"}, true, true},
		{"untagged, release fix", "v0.0.0-20260727151759-521cb33b33dd", affectedRange{LowerInclusive: "0", UpperExclusive: "1.5.0"}, false, false},
		{"commit after the fixed tag", "v1.5.1-0.20220101000000-abcdef123456", affectedRange{LowerInclusive: "0", UpperExclusive: "1.5.0"}, true, true},
		{"commit between the tags around the fix", "v1.4.10-0.20220101000000-abcdef123456", affectedRange{LowerInclusive: "0", UpperExclusive: "1.5.0"}, false, false},
		{"commit before a release introduced", "v1.2.4-0.20220101000000-abcdef123456", affectedRange{LowerInclusive: "1.3.0", UpperExclusive: "1.5.0"}, false, false},
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
