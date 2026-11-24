package pipeline

import (
	"strings"
	"testing"
)

const (
	untagged2021 = "v0.0.0-20210101000000-abcdef123456"
	untagged2022 = "v0.0.0-20220101000000-123456abcdef"
	after123     = "v1.2.4-0.20220101000000-abcdef123456"
	afterRC      = "v1.3.0-rc.1.0.20220101000000-abcdef123456"
)

// The installed version is ordered by semver.Compare, as govulncheck orders it. The order of an
// installed pseudo-version follows from its base above a release at or below that base, carries an
// assumption against a pseudo-version on the same base, and is unordered otherwise.
func TestCompareGoModVersionsAssuming(t *testing.T) {
	tests := []struct {
		name    string
		a, b    string
		want    int
		wantOK  bool
		assumes bool
	}{
		{name: "release below a release", a: "v1.2.3", b: "1.2.4", want: -1, wantOK: true},
		{name: "tagged pre-release below its release", a: "v1.3.0-rc.1", b: "1.3.0", want: -1, wantOK: true},
		{name: "tagged pre-release at a pre-release bound", a: "v1.3.0-rc.1", b: "1.3.0-rc.1", want: 0, wantOK: true},
		{name: "tagged pre-release above the previous release", a: "v1.3.0-rc.1", b: "1.2.0", want: 1, wantOK: true},
		{name: "tagged pre-release below a later pre-release", a: "v1.3.0-rc.1", b: "1.3.0-rc.2", want: -1, wantOK: true},
		{name: "release against a pseudo bound", a: "v0.33.0", b: "0.0.0-20190813141303-74dc4d7220e7", want: 1, wantOK: true},

		{name: "pseudo, bound at its base", a: after123, b: "1.2.3", want: 1, wantOK: true},
		{name: "pseudo, bound below its base", a: after123, b: "1.2.0", want: 1, wantOK: true},
		{name: "pseudo, bound a pre-release of its base", a: after123, b: "1.2.3-rc.1", want: 1, wantOK: true},
		{name: "pseudo on a pre-release base, bound at that pre-release", a: afterRC, b: "1.3.0-rc.1", want: 1, wantOK: true},
		{name: "incompatible pseudo past its base", a: "v2.0.1-0.20220101000000-abcdef123456+incompatible", b: "2.0.0", want: 1, wantOK: true},

		{name: "pseudo, bound the next patch", a: after123, b: "1.2.4", wantOK: false},
		{name: "pseudo, bound a later minor", a: after123, b: "1.3.0", wantOK: false},
		{name: "pseudo on a pre-release base, bound the release", a: afterRC, b: "1.3.0", wantOK: false},
		{name: "untagged against a release", a: untagged2022, b: "1.5.0", wantOK: false},
		{name: "untagged against a pre-release", a: untagged2022, b: "0.0.0-alpha.1", wantOK: false},
		{name: "untagged against the zero release", a: untagged2022, b: "0.0.0", wantOK: false},
		{name: "pseudo above a pre-release above its base is unordered", a: after123, b: "1.2.4-0", wantOK: false},

		{name: "untagged after an untagged bound", a: untagged2022, b: "0.0.0-20210101000000-abcdef123456", want: 1, wantOK: true, assumes: true},
		{name: "untagged before an untagged bound", a: untagged2021, b: "0.0.0-20220101000000-123456abcdef", want: -1, wantOK: true, assumes: true},
		{name: "same base, later bound", a: after123, b: "1.2.4-0.20230101000000-0123456789ab", want: -1, wantOK: true, assumes: true},
		{name: "same base, earlier bound", a: after123, b: "1.2.4-0.20210101000000-0123456789ab", want: 1, wantOK: true, assumes: true},
		{name: "another base", a: after123, b: "1.2.5-0.20210101000000-0123456789ab", wantOK: false},
		{name: "another base, committed earlier", a: "v1.2.5-0.20210101000000-aaaaaaaaaaaa", b: "1.2.4-0.20220101000000-bbbbbbbbbbbb", wantOK: false},
		{name: "untagged against a tagged base", a: untagged2022, b: "1.2.4-0.20210101000000-0123456789ab", wantOK: false},
		{name: "same commit", a: untagged2021, b: "0.0.0-20210101000000-abcdef123456", want: 0, wantOK: true},
		{name: "same revision, another time", a: untagged2021, b: "0.0.0-20220101000000-abcdef123456", wantOK: false},
		{name: "same time, another revision", a: untagged2021, b: "0.0.0-20210101000000-ffffff123456", wantOK: false},

		{name: "installed version without its v", a: "1.2.3", b: "1.2.4", wantOK: false},
		{name: "unparseable bound", a: "v1.2.3", b: "not-a-version", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, assumption, ok := compareGoModVersionsAssuming(tt.a, tt.b)
			if ok != tt.wantOK || (ok && got != tt.want) || (assumption != "") != tt.assumes {
				t.Fatalf("compareGoModVersionsAssuming(%q, %q) = (%d, %q, %v), want (%d, assumption %v, %v)", tt.a, tt.b, got, assumption, ok, tt.want, tt.assumes, tt.wantOK)
			}
			strict, strictOK := compareGoModVersions(tt.a, tt.b)
			if wantStrict := tt.wantOK && !tt.assumes; strictOK != wantStrict || (strictOK && strict != tt.want) {
				t.Fatalf("compareGoModVersions(%q, %q) = (%d, %v), want ok %v", tt.a, tt.b, strict, strictOK, wantStrict)
			}
		})
	}
}

// An assumption names both revisions, the commit-time order it rests on, and what the pin is assumed
// to contain.
func TestCompareGoModVersionsAssuming_NamesBothRevisions(t *testing.T) {
	_, later, _ := compareGoModVersionsAssuming(after123, "1.2.4-0.20210101000000-0123456789ab")
	for _, want := range []string{"abcdef123456", after123, "0123456789ab", " contains ", "committed later on the same base", "does not prove ancestry"} {
		if !strings.Contains(later, want) {
			t.Errorf("assumption %q does not contain %q", later, want)
		}
	}
	_, earlier, _ := compareGoModVersionsAssuming(after123, "1.2.4-0.20230101000000-0123456789ab")
	if !strings.Contains(earlier, "does not contain revision 0123456789ab") || !strings.Contains(earlier, "committed earlier") {
		t.Errorf("assumption %q does not say the pin lacks the bound's revision", earlier)
	}
}

// Pseudo-version and pre-release installed versions below, at and above each kind of bound.
// assumes is whether the placement outside rests on an assumption; the strict reading
// (versionOutsideRange) then leaves the range unplaced.
func TestVersionOutsideRangeAssuming_PseudoAndPreRelease(t *testing.T) {
	tests := []struct {
		name        string
		ver         string
		rng         affectedRange
		wantOutside bool
		wantOK      bool
		assumes     bool
	}{
		{"pre-release below introduced", "v1.3.0-rc.1", affectedRange{LowerInclusive: "1.3.0", UpperExclusive: "1.5.0"}, true, true, false},
		{"pre-release equal to a pre-release introduced", "v1.3.0-rc.1", affectedRange{LowerInclusive: "1.3.0-rc.1", UpperExclusive: "1.5.0"}, false, true, false},
		{"pre-release inside", "v1.4.0-rc.1", affectedRange{LowerInclusive: "1.3.0", UpperExclusive: "1.5.0"}, false, true, false},
		{"pre-release below fixed", "v1.5.0-rc.1", affectedRange{LowerInclusive: "1.3.0", UpperExclusive: "1.5.0"}, false, true, false},
		{"pre-release equal to a pre-release fixed", "v1.5.0-rc.1", affectedRange{LowerInclusive: "1.3.0", UpperExclusive: "1.5.0-rc.1"}, true, true, false},
		{"pre-release above fixed", "v1.6.0-rc.1", affectedRange{LowerInclusive: "1.3.0", UpperExclusive: "1.5.0"}, true, true, false},
		{"pre-release at last_affected", "v1.4.0-rc.1", affectedRange{LowerInclusive: "1.3.0", LastAffected: "1.4.0-rc.1"}, false, true, false},
		{"pre-release past last_affected stays inside", "v1.4.0", affectedRange{LowerInclusive: "1.3.0", LastAffected: "1.4.0-rc.1"}, false, true, false},
		{"pre-release below introduced of a last_affected range", "v1.3.0-rc.1", affectedRange{LowerInclusive: "1.3.0", LastAffected: "1.4.0"}, true, true, false},

		{"pseudo past the fixed tag", "v1.5.1-0.20220101000000-abcdef123456", affectedRange{LowerInclusive: "0", UpperExclusive: "1.5.0"}, true, true, false},
		{"pseudo between the tags around the fix is unplaced", "v1.4.10-0.20220101000000-abcdef123456", affectedRange{LowerInclusive: "0", UpperExclusive: "1.5.0"}, false, false, false},
		{"pseudo based at introduced is unplaced below fixed", "v1.3.1-0.20220101000000-abcdef123456", affectedRange{LowerInclusive: "1.3.0", UpperExclusive: "1.5.0"}, false, false, false},
		{"pseudo before a release introduced is unplaced", after123, affectedRange{LowerInclusive: "1.3.0", UpperExclusive: "1.5.0"}, false, false, false},
		{"pseudo before a release introduced of a last_affected range is unplaced", after123, affectedRange{LowerInclusive: "1.3.0", LastAffected: "1.4.0"}, false, false, false},
		{"pseudo past last_affected stays inside", "v1.4.1-0.20220101000000-abcdef123456", affectedRange{LowerInclusive: "1.3.0", LastAffected: "1.4.0"}, false, true, false},

		{"untagged past the pseudo fix", "v0.0.0-20260727151759-521cb33b33dd", affectedRange{LowerInclusive: "0", UpperExclusive: "0.0.0-20260531000007-52dbd5ece63f"}, true, true, true},
		{"untagged before the pseudo fix", "v0.0.0-20260120122510-4a022ed9999a", affectedRange{LowerInclusive: "0", UpperExclusive: "0.0.0-20260531000007-52dbd5ece63f"}, false, true, false},
		{"untagged at the pseudo fix", "v0.0.0-20260531000007-52dbd5ece63f", affectedRange{LowerInclusive: "0", UpperExclusive: "0.0.0-20260531000007-52dbd5ece63f"}, true, true, false},
		{"untagged before a pseudo introduced", untagged2021, affectedRange{LowerInclusive: "0.0.0-20220101000000-0123456789ab", UpperExclusive: "0.0.0-20230101000000-fedcba987654"}, true, true, true},
		{"untagged at a pseudo introduced", "v0.0.0-20220101000000-0123456789ab", affectedRange{LowerInclusive: "0.0.0-20220101000000-0123456789ab", UpperExclusive: "0.0.0-20230101000000-fedcba987654"}, false, true, false},
		{"untagged, release fix is unplaced", "v0.0.0-20260727151759-521cb33b33dd", affectedRange{LowerInclusive: "0", UpperExclusive: "1.5.0"}, false, false, false},
		{"untagged before a pseudo last_affected stays inside", untagged2021, affectedRange{LowerInclusive: "0", LastAffected: "0.0.0-20220101000000-0123456789ab"}, false, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outside, assumption, ok := versionOutsideRangeAssuming(tt.ver, tt.rng)
			if outside != tt.wantOutside || ok != tt.wantOK || (assumption != "") != tt.assumes {
				t.Fatalf("versionOutsideRangeAssuming(%q, %+v) = (%v, %q, %v), want (%v, assumption %v, %v)", tt.ver, tt.rng, outside, assumption, ok, tt.wantOutside, tt.assumes, tt.wantOK)
			}
			strictOutside, strictOK := versionOutsideRange(tt.ver, tt.rng)
			wantStrictOutside, wantStrictOK := tt.wantOutside && !tt.assumes, tt.wantOK && !tt.assumes
			if strictOutside != wantStrictOutside || strictOK != wantStrictOK {
				t.Fatalf("versionOutsideRange(%q, %+v) = (%v, %v), want (%v, %v)", tt.ver, tt.rng, strictOutside, strictOK, wantStrictOutside, wantStrictOK)
			}
		})
	}
}

// The version axis refutes an installed pseudo-version placed outside under an assumption, and
// carries every such assumption, each once, across ranges, versions and the other affected packages.
func TestDisqualifyEvery_CarriesPseudoVersionAssumptions(t *testing.T) {
	pseudoFix := affectedRange{LowerInclusive: "0", UpperExclusive: "0.0.0-20210101000000-0123456789ab"}
	releaseFix := affectedRange{LowerInclusive: "0", UpperExclusive: "1.5.0"}
	t.Run("pseudo past a pseudo fix", func(t *testing.T) {
		disq, reason, assumptions := disqualifyEvery([]affectedRange{pseudoFix}, true, versionAxis{Versions: []string{untagged2022}, Complete: true}, true, nil, "", false)
		if !disq || reason != ReasonVersionNotInRange || len(assumptions) != 1 || !strings.Contains(assumptions[0], "0123456789ab") {
			t.Fatalf("got (%v, %s, %q), want a version refute carrying the bound's revision", disq, reason, assumptions)
		}
	})
	t.Run("ordinary order carries none", func(t *testing.T) {
		disq, _, assumptions := disqualifyEvery([]affectedRange{releaseFix}, true, versionAxis{Versions: []string{"v1.5.1-0.20220101000000-abcdef123456", "v1.6.0"}, Complete: true}, true, nil, "", false)
		if !disq || assumptions != nil {
			t.Fatalf("got (%v, %q), want a refute with no assumption", disq, assumptions)
		}
	})
	t.Run("each version's assumption once", func(t *testing.T) {
		vers := []string{untagged2022, untagged2022, "v0.0.0-20230101000000-fedcba987654"}
		disq, _, assumptions := disqualifyEvery([]affectedRange{pseudoFix}, true, versionAxis{Versions: vers, Complete: true}, true, nil, "", false)
		if !disq || len(assumptions) != 2 || !strings.Contains(assumptions[0], "123456abcdef") || !strings.Contains(assumptions[1], "fedcba987654") {
			t.Fatalf("got (%v, %q), want the two installed revisions' assumptions in order", disq, assumptions)
		}
	})
	t.Run("another affected package's assumption", func(t *testing.T) {
		others := []presentRanges{{presentPackage: presentPackage{Versions: []string{untagged2022}, Complete: true}, Ranges: []affectedRange{pseudoFix}, RangeKnown: true}}
		disq, _, assumptions := disqualifyEvery([]affectedRange{releaseFix}, true, versionAxis{Versions: []string{"v1.6.0"}, Complete: true}, true, others, "", false)
		if !disq || len(assumptions) != 1 || !strings.Contains(assumptions[0], "123456abcdef") {
			t.Fatalf("got (%v, %q), want the other package's assumption", disq, assumptions)
		}
	})
	t.Run("one version inside keeps the advisory", func(t *testing.T) {
		vers := []string{untagged2022, "v0.0.0-20200101000000-aaaaaaaaaaaa"}
		disq, _, assumptions := disqualifyEvery([]affectedRange{pseudoFix}, true, versionAxis{Versions: vers, Complete: true}, true, nil, "", false)
		if disq || assumptions != nil {
			t.Fatalf("got (%v, %q), want no refute", disq, assumptions)
		}
	})
	t.Run("symbol axis carries none", func(t *testing.T) {
		disq, reason, assumptions := disqualifyEvery([]affectedRange{pseudoFix}, true, versionAxis{Versions: []string{untagged2022}, Complete: true}, true, nil, "absent", true)
		if !disq || reason != ReasonSymbolAbsent || assumptions != nil {
			t.Fatalf("got (%v, %s, %q), want a symbol refute with no assumption", disq, reason, assumptions)
		}
	})
}

// Readers that cannot disclose an assumption keep failing open on one.
func TestPseudoVersionAssumption_StrictReadersFailOpen(t *testing.T) {
	rngs := []affectedRange{{LowerInclusive: "0", UpperExclusive: "0.0.0-20210101000000-0123456789ab"}}
	if outside, ok := versionOutsideRanges(untagged2022, rngs); outside || ok {
		t.Fatalf("versionOutsideRanges = (%v, %v), want unplaced", outside, ok)
	}
	if outside, ok := VersionOutsideRange(untagged2022, "0.0.0-20210101000000-0123456789ab", "gomod"); outside || ok {
		t.Fatalf("VersionOutsideRange = (%v, %v), want unplaced", outside, ok)
	}
	if everyVersionOutside([]string{untagged2022}, true, rngs, true) {
		t.Fatal("everyVersionOutside placed an assumption-laden version outside")
	}
	capped := capOpenLastAffected([]affectedRange{
		{LowerInclusive: "v0.0.0-20200101000000-aaaaaaaaaaaa", LastAffected: "v0.0.0-20210101000000-bbbbbbbbbbbb"},
		{LowerInclusive: "v0.0.0-20220101000000-cccccccccccc", UpperExclusive: "v0.0.0-20230101000000-dddddddddddd"},
	})
	if capped[0].UpperExclusive != "" {
		t.Fatalf("capOpenLastAffected capped at %q on a pseudo-version order", capped[0].UpperExclusive)
	}
}
