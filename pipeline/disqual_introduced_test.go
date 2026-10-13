package pipeline

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// The introduced lower bound on the version axis. A version below every range's introduced is not
// affected; every bound the scheme cannot order, and every range type that is not a version
// ordering, leaves the advisory admitted.

func TestVersionOutsideRange_Introduced(t *testing.T) {
	npm := func(intro, fixed string) affectedRange {
		return affectedRange{Introduced: intro, UpperExclusive: fixed, Scheme: "npm"}
	}
	tests := []struct {
		name        string
		ver         string
		rng         affectedRange
		wantOutside bool
		wantOK      bool
	}{
		// npm prerelease ordering on [2.0.0-alpha.1, 2.2.0).
		{"npm release below a prerelease introduced is outside", "1.4.2", npm("2.0.0-alpha.1", "2.2.0"), true, true},
		{"npm introduced prerelease itself is inside", "2.0.0-alpha.1", npm("2.0.0-alpha.1", "2.2.0"), false, true},
		{"npm release above a prerelease introduced is inside", "2.0.0", npm("2.0.0-alpha.1", "2.2.0"), false, true},
		{"npm earlier prerelease of the same release is outside", "2.0.0-alpha.0", npm("2.0.0-alpha.1", "2.2.0"), true, true},

		// Absent and OSV "0" introduced are unbounded below and still place the version.
		{"absent introduced is unbounded below", "1.4.2", npm("", "2.2.0"), false, true},
		{"zero introduced is unbounded below", "1.4.2", npm("0", "2.2.0"), false, true},

		// An introduced the scheme cannot parse proves nothing about the lower end.
		{"unparseable introduced admits unplaced", "1.4.2", npm("garbage", "2.2.0"), false, false},

		// Range type: only SEMVER and ECOSYSTEM order their bounds as versions.
		{"GIT range proves nothing", "1.4.2", affectedRange{Introduced: "2.0.0", UpperExclusive: "2.2.0", Scheme: "npm", Type: "GIT"}, false, false},
		{"unknown range type proves nothing", "1.4.2", affectedRange{Introduced: "2.0.0", UpperExclusive: "2.2.0", Scheme: "npm", Type: "FOO"}, false, false},
		{"ECOSYSTEM range orders", "1.4.2", affectedRange{Introduced: "2.0.0", UpperExclusive: "2.2.0", Scheme: "npm", Type: "ECOSYSTEM"}, true, true},
		{"SEMVER range orders", "1.4.2", affectedRange{Introduced: "2.0.0", UpperExclusive: "2.2.0", Scheme: "npm", Type: "SEMVER"}, true, true},

		// An introduced with no upper bound affects every version from introduced on.
		{"introduced-only excludes below", "1.4.2", affectedRange{Introduced: "2.0.0", Scheme: "npm"}, true, true},
		{"introduced-only admits far above", "5.0.0", affectedRange{Introduced: "2.0.0", Scheme: "npm"}, false, true},
		{"gomod introduced-only admits far above", "v5.0.0", affectedRange{Introduced: "v2.0.0", Scheme: "gomod"}, false, true},

		// last_affected is inclusive.
		{"last_affected itself is inside", "1.4.2", affectedRange{Introduced: "1.0.0", LastAffected: "1.4.2", Scheme: "npm"}, false, true},
		{"past last_affected is outside", "1.4.3", affectedRange{Introduced: "1.0.0", LastAffected: "1.4.2", Scheme: "npm"}, true, true},

		// One row per comparator.
		{"pypi beta below an rc introduced is outside", "2.0.0b1", affectedRange{Introduced: "2.0.0rc1", UpperExclusive: "2.1", Scheme: "pypi"}, true, true},
		{"pypi rc introduced itself is inside", "2.0.0rc1", affectedRange{Introduced: "2.0.0rc1", UpperExclusive: "2.1", Scheme: "pypi"}, false, true},
		{"maven orders 1.10 above 1.9", "1.10", affectedRange{Introduced: "1.9", UpperExclusive: "2.0", Scheme: "maven"}, false, true},
		{"maven below introduced is outside", "1.8", affectedRange{Introduced: "1.9", UpperExclusive: "2.0", Scheme: "maven"}, true, true},
		{"nuget release below a prerelease introduced is outside", "1.9.9", affectedRange{Introduced: "2.0.0-beta", UpperExclusive: "3.0.0", Scheme: "nuget"}, true, true},
		{"nuget floating version is unplaced", "1.*", affectedRange{Introduced: "2.0.0-beta", UpperExclusive: "3.0.0", Scheme: "nuget"}, false, false},
		{"go toolchain below introduced is outside", "go1.20.14", affectedRange{Introduced: "1.21.0", UpperExclusive: "1.21.3", Scheme: "go-toolchain"}, true, true},
		{"gomod below introduced is outside", "v1.4.2", affectedRange{Introduced: "v2.0.0", UpperExclusive: "v2.2.0", Scheme: "gomod"}, true, true},
		{"scheme with no comparator is unplaced", "v1.4.2", affectedRange{Introduced: "v2.0.0", UpperExclusive: "v2.2.0", Scheme: "cargo"}, false, false},
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

// A Go pseudo-version is a prerelease to the default Go comparator, so it is never placed against
// an introduced bound: a range's verdict on it is the one the upper bound alone gave.
func TestVersionOutsideRange_GoPseudoVersionUnchanged(t *testing.T) {
	const pseudo = "v0.0.0-20210101000000-abcdef123456"
	tests := []struct {
		name string
		ver  string
		rng  affectedRange
	}{
		{"pseudo version below a release introduced", pseudo, affectedRange{Introduced: "v1.0.0", UpperExclusive: "v1.5.0"}},
		{"pseudo version against a pseudo introduced", pseudo, affectedRange{Introduced: "v0.0.0-20220101000000-abcdef123456", UpperExclusive: "v1.5.0"}},
		{"release past the upper of a pseudo introduced", "v1.6.0", affectedRange{Introduced: "v0.0.0-20220101000000-abcdef123456", UpperExclusive: "v1.5.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outside, _ := versionOutsideRange(tt.ver, tt.rng)
			wantOutside, _ := versionOutsideUpper(tt.ver, tt.rng)
			if outside != wantOutside {
				t.Fatalf("versionOutsideRange(%q, %+v) outside = %v, upper bound alone gives %v", tt.ver, tt.rng, outside, wantOutside)
			}
		})
	}
}

// multerRanges is CVE-2026-5038's affected set: [2.0.0-alpha.1, 2.2.0) and
// [3.0.0-alpha.1, 3.0.0-alpha.2), with a gap between them.
func multerRanges() []map[string]string {
	return []map[string]string{
		{"introduced": "2.0.0-alpha.1", "upper_exclusive": "2.2.0", "scheme": "npm"},
		{"introduced": "3.0.0-alpha.1", "upper_exclusive": "3.0.0-alpha.2", "scheme": "npm"},
	}
}

func TestDisqual_IntroducedBound(t *testing.T) {
	tests := []struct {
		name       string
		ranges     []map[string]string
		ver        string
		wantDisq   bool
		wantReason string
	}{
		{"below every introduced disqualifies", multerRanges(), "1.4.2", true, ReasonVersionNotInRange},
		{"in the gap between ranges disqualifies", multerRanges(), "2.5.0", true, ReasonVersionNotInRange},
		{"inside the first range is admitted", multerRanges(), "2.1.0", false, ""},
		{"inside the second range is admitted", multerRanges(), "3.0.0-alpha.1", false, ""},
		{"unparseable introduced is admitted", []map[string]string{{"introduced": "garbage", "upper_exclusive": "2.2.0", "scheme": "npm"}}, "1.4.2", false, ""},
		{"introduced-only range disqualifies below", []map[string]string{{"introduced": "2.0.0", "scheme": "npm"}}, "1.4.2", true, ReasonVersionNotInRange},
		{"last_affected-only range disqualifies above", []map[string]string{{"last_affected": "1.4.2", "scheme": "npm"}}, "1.5.0", true, ReasonVersionNotInRange},
		{"GIT range is admitted", []map[string]string{{"introduced": "2.0.0", "upper_exclusive": "2.2.0", "scheme": "npm", "type": "GIT"}}, "1.4.2", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := runMultiRangeDisqual(t, tt.ranges, tt.ver)
			if res.Disqualified != tt.wantDisq {
				t.Fatalf("Disqualified = %v, want %v (%+v)", res.Disqualified, tt.wantDisq, res)
			}
			if tt.wantDisq && res.Reason != tt.wantReason {
				t.Fatalf("Reason = %q, want %q", res.Reason, tt.wantReason)
			}
		})
	}
}

// multerDoc is CVE-2026-5038 as the published corpus carries it: affected[] with introduced, and the
// legacy affected_ranges without.
const multerDoc = `{
  "schema_version": "ferralon.normalized_advisory.v3",
  "vuln_id": "CVE-2026-5038",
  "version_scheme": "npm",
  "coordinate": "multer",
  "purl": "pkg:npm/multer",
  "affected_ranges": [
    {"fixed": "2.2.0", "fixed_version": "2.2.0"},
    {"fixed": "3.0.0-alpha.2", "fixed_version": "3.0.0-alpha.2"}
  ],
  "affected": [{
    "coordinate": "multer",
    "purl": "pkg:npm/multer",
    "version_scheme": "npm",
    "fixed_versions": ["2.2.0", "3.0.0-alpha.2"],
    "ranges": [
      {"introduced": "2.0.0-alpha.1", "upper_exclusive": "2.2.0", "fixed": "2.2.0"RANGE_TYPE},
      {"introduced": "3.0.0-alpha.1", "upper_exclusive": "3.0.0-alpha.2", "fixed": "3.0.0-alpha.2"}
    ]
  }]
}`

// The corpus decode carries introduced and the range type from affected[] through to the element
// the version axis reads.
func TestCorpusDecode_IntroducedReachesAxis(t *testing.T) {
	tests := []struct {
		name        string
		rangeType   string
		wantOutside bool
		wantOK      bool
	}{
		{"untyped ranges exclude a version below introduced", "", true, true},
		{"a GIT range admits", `, "type": "GIT"`, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(strings.Replace(multerDoc, "RANGE_TYPE", tt.rangeType, 1))
			var d advisoryDoc
			if err := json.Unmarshal(raw, &d); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			facts, ok := d.toFacts("CVE-2026-5038")
			if !ok || len(facts.AffectedPackages) != 1 {
				t.Fatalf("toFacts ok=%v packages=%d, want one element", ok, len(facts.AffectedPackages))
			}
			p := facts.AffectedPackages[0]
			rngs := withDisagreeingLegacyRanges(buildAffectedRanges(p.AffectedRanges, p.UpperExclusive, "npm"), p, facts, "npm")
			outside, gotOK := versionOutsideRanges("1.4.2", rngs)
			if outside != tt.wantOutside || gotOK != tt.wantOK {
				t.Fatalf("versionOutsideRanges(1.4.2, %+v) = (%v, %v), want (%v, %v)", rngs, outside, gotOK, tt.wantOutside, tt.wantOK)
			}
		})
	}
}

// fakeRangesSource serves one advisory as the corpus would, with affected[] read into elems and the
// legacy affected_ranges into the scalar ranges.
type fakeRangesSource struct {
	legacy []Range
	elems  []AffectedPackage
}

func (s fakeRangesSource) Lookup(string) (AdvisoryFacts, bool) {
	return AdvisoryFacts{
		VersionScheme:    "npm",
		Coordinate:       "multer",
		PURL:             "pkg:npm/multer",
		AffectedRanges:   s.legacy,
		AffectedPackages: s.elems,
		Provenance:       Provenance{TrustTier: TrustFirstParty},
	}, true
}

// runLegacyUnionDisqual runs the real intake stage over src, selects coordinate in the inventory with the
// resolved version ver, and runs the version axis.
func runLegacyUnionDisqual(t *testing.T, src AdvisorySource, coordinate, ver string) DisqualResult {
	t.Helper()
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-legacy-union", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-2026-5038", Source: "corpus"},
	}}
	if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("intake: %v", err)
	}
	putJSON(t, store, c.ID, artifact.TypeInventory, map[string]any{
		"resolved_version":    ver,
		"selected_coordinate": coordinate,
	})
	return runDisqual(t, store, c.ID)
}

// A record whose affected[] and legacy affected_ranges disagree admits wherever either admits.
func TestIntake_DisagreeingLegacyRangesAdmit(t *testing.T) {
	elem := func(coordinate string, rngs ...Range) AffectedPackage {
		return AffectedPackage{Coordinate: coordinate, PURL: "pkg:npm/" + coordinate, AffectedRanges: rngs}
	}
	multer := []Range{{Introduced: "2.0.0-alpha.1", Fixed: "2.2.0"}, {Introduced: "3.0.0-alpha.1", Fixed: "3.0.0-alpha.2"}}
	tests := []struct {
		name       string
		src        fakeRangesSource
		coordinate string
		ver        string
		wantDisq   bool
	}{
		{
			name:       "legacy agreeing but for the introduced it cannot carry keeps the lower bound",
			src:        fakeRangesSource{legacy: []Range{{Fixed: "2.2.0"}, {Fixed: "3.0.0-alpha.2"}}, elems: []AffectedPackage{elem("multer", multer...)}},
			coordinate: "multer", ver: "1.4.2", wantDisq: true,
		},
		{
			name:       "legacy with a different upper bound is unioned in and admits",
			src:        fakeRangesSource{legacy: []Range{{Fixed: "2.3.0"}, {Fixed: "3.0.0-alpha.2"}}, elems: []AffectedPackage{elem("multer", multer...)}},
			coordinate: "multer", ver: "1.4.2", wantDisq: false,
		},
		{
			name:       "legacy with fewer ranges is unioned in and admits",
			src:        fakeRangesSource{legacy: []Range{{Fixed: "2.2.0"}}, elems: []AffectedPackage{elem("multer", multer...)}},
			coordinate: "multer", ver: "1.4.2", wantDisq: false,
		},
		{
			name:       "legacy with a different introduced is unioned in and admits",
			src:        fakeRangesSource{legacy: []Range{{Introduced: "1.0.0", Fixed: "2.2.0"}, {Fixed: "3.0.0-alpha.2"}}, elems: []AffectedPackage{elem("multer", multer...)}},
			coordinate: "multer", ver: "1.4.2", wantDisq: false,
		},
		{
			name: "legacy ranges describe the primary package only",
			src: fakeRangesSource{
				legacy: []Range{{Fixed: "2.3.0"}},
				elems:  []AffectedPackage{elem("multer", multer...), elem("busboy", Range{Introduced: "2.0.0", Fixed: "2.2.0"})},
			},
			coordinate: "busboy", ver: "1.4.2", wantDisq: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := runLegacyUnionDisqual(t, tt.src, tt.coordinate, tt.ver)
			if res.Disqualified != tt.wantDisq {
				t.Fatalf("Disqualified = %v, want %v (%+v)", res.Disqualified, tt.wantDisq, res)
			}
		})
	}
}

// A last_affected bound decoded from affected[] reaches the axis as an inclusive upper end.
func TestCorpusDecode_LastAffectedReachesAxis(t *testing.T) {
	const doc = `{
  "schema_version": "ferralon.normalized_advisory.v3",
  "vuln_id": "CVE-2026-0001",
  "version_scheme": "npm",
  "coordinate": "left-pad",
  "purl": "pkg:npm/left-pad",
  "affected": [{
    "coordinate": "left-pad",
    "purl": "pkg:npm/left-pad",
    "version_scheme": "npm",
    "ranges": [{"introduced": "1.0.0", "last_affected": "1.4.2"}]
  }]
}`
	var d advisoryDoc
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	facts, ok := d.toFacts("CVE-2026-0001")
	if !ok || len(facts.AffectedPackages) != 1 {
		t.Fatalf("toFacts ok=%v packages=%d, want one element", ok, len(facts.AffectedPackages))
	}
	p := facts.AffectedPackages[0]
	rngs := buildAffectedRanges(p.AffectedRanges, p.UpperExclusive, "npm")
	if outside, ok := versionOutsideRanges("1.5.0", rngs); !outside || !ok {
		t.Fatalf("versionOutsideRanges(1.5.0, %+v) = (%v, %v), want (true, true)", rngs, outside, ok)
	}
}

// The exported single-bound helper reads exactly as the upper-only check did, including for an
// empty bound, which node-semver reads as any version.
func TestVersionOutsideRange_ExportedUpperOnlyUnchanged(t *testing.T) {
	tests := []struct{ ver, upper, scheme string }{
		{"1.4.2", "", "npm"},
		{"1.4.2", "2.2.0", "npm"},
		{"2.2.0", "2.2.0", "npm"},
		{"v1.4.2", "", ""},
		{"v1.21.3", "v1.21.3", ""},
		{"1.10", "1.9", "maven"},
		{"2.0.0b1", "2.0.0", "pypi"},
	}
	for _, tt := range tests {
		t.Run(tt.scheme+" "+tt.ver+" vs "+tt.upper, func(t *testing.T) {
			outside, ok := VersionOutsideRange(tt.ver, tt.upper, tt.scheme)
			wantOutside, wantOK := versionOutsideUpper(tt.ver, affectedRange{UpperExclusive: tt.upper, Scheme: tt.scheme})
			if outside != wantOutside || ok != wantOK {
				t.Fatalf("VersionOutsideRange = (%v, %v), upper-only check gives (%v, %v)", outside, ok, wantOutside, wantOK)
			}
		})
	}
}
