package pipeline

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

func TestAncestorReleaseTag(t *testing.T) {
	const app = "example.com/app"
	nested := map[string]string{"sub/go.mod": "module example.com/app/sub\n"}
	type tagAt struct {
		name      string
		at        func(h fixHistory) string
		annotated bool
	}
	base := func(h fixHistory) string { return h.base }
	fix := func(h fixHistory) string { return h.fix }
	later := func(h fixHistory) string { return h.later }
	side := func(h fixHistory) string { return h.side }
	cases := []struct {
		name    string
		files   map[string]string
		sub     string
		mod     string
		head    func(h fixHistory) string
		tags    []tagAt
		wantTag string
	}{
		{name: "no tags", mod: app},
		{name: "a tag at an ancestor", mod: app, tags: []tagAt{{"v1.2.0", base, false}}, wantTag: "v1.2.0"},
		{name: "a tag at HEAD", mod: app, tags: []tagAt{{"v1.2.0", later, false}}, wantTag: "v1.2.0"},
		{name: "the highest of several", mod: app, tags: []tagAt{{"v1.3.0", base, false}, {"v1.2.9", fix, false}}, wantTag: "v1.3.0"},
		{name: "an annotated tag", mod: app, tags: []tagAt{{"v1.2.0", base, true}}, wantTag: "v1.2.0"},
		{name: "a prerelease above the release", mod: app, tags: []tagAt{{"v1.2.0", base, false}, {"v1.3.0-rc.1", fix, false}}, wantTag: "v1.3.0-rc.1"},
		{name: "a tag on a branch HEAD does not contain", mod: app, tags: []tagAt{{"v1.2.0", base, false}, {"v1.9.0", side, false}}, wantTag: "v1.2.0"},
		{name: "a tag after HEAD", mod: app, head: fix, tags: []tagAt{{"v1.2.0", base, false}, {"v1.9.0", later, false}}, wantTag: "v1.2.0"},
		{name: "a tag without the v", mod: app, tags: []tagAt{{"1.2.0", base, false}}},
		{name: "a tag that is not canonical", mod: app, tags: []tagAt{{"v1.2", base, false}}},
		{name: "a tag shaped like a pseudo-version", mod: app, tags: []tagAt{{"v0.0.0-20240101000000-abcdefabcdef", base, false}}},
		{name: "a major the module path does not allow", mod: app, tags: []tagAt{{"v1.2.0", base, false}, {"v2.0.0", fix, false}}, wantTag: "v1.2.0"},
		{name: "a v2 module's own major", mod: app + "/v2", tags: []tagAt{{"v1.9.0", base, false}, {"v2.1.0", fix, false}}, wantTag: "v2.1.0"},
		{name: "a nested module's prefixed tag", files: nested, sub: "sub", mod: app + "/sub", tags: []tagAt{{"sub/v1.2.0", base, false}, {"v1.9.0", fix, false}}, wantTag: "sub/v1.2.0"},
		{name: "a nested module and only the root's tag", files: nested, sub: "sub", mod: app + "/sub", tags: []tagAt{{"v1.9.0", fix, false}}},
		{name: "no module path", tags: []tagAt{{"v1.2.0", base, false}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFixHistory(t, tc.files)
			for _, tg := range tc.tags {
				args := []string{"-c", "tag.gpgsign=false", "tag"}
				if tg.annotated {
					args = append(args, "-a", "-m", tg.name)
				}
				fixtureGit(t, h.dir, append(args, tg.name, tg.at(h))...)
			}
			if tc.head != nil {
				h.at(t, tc.head(h))
			}
			tag, version, ok := ancestorReleaseTag(context.Background(), filepath.Join(h.dir, tc.sub), tc.mod)
			if tag != tc.wantTag || ok != (tc.wantTag != "") {
				t.Fatalf("ancestorReleaseTag = %q, %q, %v; want %q", tag, version, ok, tc.wantTag)
			}
		})
	}
}

func TestAncestorReleaseClears(t *testing.T) {
	fixed := func(lower, upper string) affectedRange {
		return affectedRange{LowerInclusive: lower, UpperExclusive: upper}
	}
	outsideDep := presentRanges{presentPackage: presentPackage{Module: "example.com/dep", Versions: []string{"v1.5.0"}, Complete: true},
		Ranges: []affectedRange{fixed("", "1.4.0")}, RangeKnown: true}
	insideDep := outsideDep
	insideDep.Versions = []string{"v1.3.0"}
	cases := []struct {
		name       string
		rngs       []affectedRange
		rangeKnown bool
		versions   []string
		others     []presentRanges
		release    string
		want       bool
		wantAsked  bool
	}{
		{name: "the release is the fixed version", rngs: []affectedRange{fixed("", "1.2.0")}, rangeKnown: true, release: "v1.2.0", want: true, wantAsked: true},
		{name: "the release is past the fixed version", rngs: []affectedRange{fixed("", "1.2.0")}, rangeKnown: true, release: "v1.3.0", want: true, wantAsked: true},
		{name: "the release is inside the range", rngs: []affectedRange{fixed("", "1.2.0")}, rangeKnown: true, release: "v1.1.9", wantAsked: true},
		{name: "a prerelease of the fixed version", rngs: []affectedRange{fixed("", "1.2.0")}, rangeKnown: true, release: "v1.2.0-rc.1", wantAsked: true},
		{name: "every range closed before the release", rngs: []affectedRange{fixed("", "1.2.0"), fixed("1.3.0", "1.3.4")}, rangeKnown: true, release: "v1.4.0", want: true, wantAsked: true},
		{name: "a later range open at the release", rngs: []affectedRange{fixed("", "1.2.0"), fixed("1.3.0", "1.3.4")}, rangeKnown: true, release: "v1.3.2", wantAsked: true},
		{name: "a later range that starts above the release", rngs: []affectedRange{fixed("", "1.2.0"), fixed("1.5.0", "1.5.2")}, rangeKnown: true, release: "v1.4.0", wantAsked: true},
		{name: "an open range", rngs: []affectedRange{{LowerInclusive: "1.0.0"}}, rangeKnown: true, release: "v9.0.0"},
		{name: "a last_affected range", rngs: []affectedRange{{LastAffected: "1.1.0"}}, rangeKnown: true, release: "v9.0.0"},
		{name: "another scheme", rngs: []affectedRange{{UpperExclusive: "1.2.0", Scheme: "npm"}}, rangeKnown: true, release: "v9.0.0"},
		{name: "a bound the comparator cannot read", rngs: []affectedRange{fixed("", "deadbeef")}, rangeKnown: true, release: "v9.0.0", wantAsked: true},
		{name: "a range not known", rngs: []affectedRange{fixed("", "1.2.0")}, release: "v9.0.0"},
		{name: "no ranges", rangeKnown: true, release: "v9.0.0"},
		{name: "a resolved version", rngs: []affectedRange{fixed("", "1.2.0")}, rangeKnown: true, versions: []string{"v1.1.0"}, release: "v9.0.0"},
		{name: "another package outside", rngs: []affectedRange{fixed("", "1.2.0")}, rangeKnown: true, others: []presentRanges{outsideDep}, release: "v1.3.0", want: true, wantAsked: true},
		{name: "another package inside", rngs: []affectedRange{fixed("", "1.2.0")}, rangeKnown: true, others: []presentRanges{insideDep}, release: "v1.3.0"},
		{name: "no release", rngs: []affectedRange{fixed("", "1.2.0")}, rangeKnown: true, wantAsked: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asked := false
			got := ancestorReleaseClears(tc.rngs, tc.rangeKnown, tc.versions, tc.others, func() (string, bool) {
				asked = true
				return tc.release, tc.release != ""
			})
			if got != tc.want || asked != tc.wantAsked {
				t.Fatalf("ancestorReleaseClears = %v (asked %v), want %v (asked %v)", got, asked, tc.want, tc.wantAsked)
			}
		})
	}
}

func TestDisqualification_AncestorRelease(t *testing.T) {
	const gomod = "module example.com/app\n\ngo 1.22\n"
	own := map[string]string{"go.mod": gomod, "main.go": "package main\n"}
	fixedRange := []Range{{Introduced: "0", Fixed: "1.2.0"}}
	facts := func(module string, rngs []Range) AdvisoryFacts {
		return AdvisoryFacts{Module: module, PURL: "pkg:golang/" + module, AffectedRanges: rngs}
	}
	assumption := ancestorReleaseAssumption("v1.3.0")
	cases := []struct {
		name   string
		files  map[string]string
		facts  AdvisoryFacts
		tagAt  func(h fixHistory) string
		tag    string
		fix    func(h fixHistory) string
		strict bool
		want   string
	}{
		{name: "a release past the fix", files: own, facts: facts("example.com/app", fixedRange), tag: "v1.3.0",
			tagAt: func(h fixHistory) string { return h.fix }, want: ReasonAncestorReleaseOutsideRange},
		{name: "a package of the project", files: own, facts: facts("example.com/app/internal/x", fixedRange), tag: "v1.3.0",
			tagAt: func(h fixHistory) string { return h.fix }, want: ReasonAncestorReleaseOutsideRange},
		{name: "strict", files: own, facts: facts("example.com/app", fixedRange), tag: "v1.3.0",
			tagAt: func(h fixHistory) string { return h.fix }, strict: true},
		{name: "a release inside the range", files: own, facts: facts("example.com/app", fixedRange), tag: "v1.1.0",
			tagAt: func(h fixHistory) string { return h.fix }},
		{name: "a release on a branch HEAD does not contain", files: own, facts: facts("example.com/app", fixedRange), tag: "v1.3.0",
			tagAt: func(h fixHistory) string { return h.side }},
		{name: "no release", files: own, facts: facts("example.com/app", fixedRange)},
		{name: "HEAD tagged past the fix", files: own, facts: facts("example.com/app", fixedRange), tag: "v1.3.0",
			tagAt: func(h fixHistory) string { return h.later }, want: ReasonVersionNotInRange},
		{name: "the fix commit in history as well", files: own, facts: facts("example.com/app", fixedRange), tag: "v1.3.0",
			tagAt: func(h fixHistory) string { return h.fix }, fix: func(h fixHistory) string { return h.fix }, want: ReasonFixCommitInHistory},
		{name: "a dependency's advisory",
			files: map[string]string{"go.mod": gomod + "\nrequire example.com/dep v1.0.0\n", "main.go": "package main\n"},
			facts: facts("example.com/dep", fixedRange), tag: "v1.3.0", tagAt: func(h fixHistory) string { return h.fix }},
		{name: "a path another module may supply",
			files: map[string]string{"go.mod": gomod, "go.sum": "example.com/app/old v0.1.0/go.mod h1:y=\n", "main.go": "package main\n"},
			facts: facts("example.com/app/old/pkg", fixedRange), tag: "v1.3.0", tagAt: func(h fixHistory) string { return h.fix }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFixHistory(t, tc.files)
			if tc.tag != "" {
				fixtureGit(t, h.dir, "-c", "tag.gpgsign=false", "tag", tc.tag, tc.tagAt(h))
			}
			if tc.fix != nil {
				tc.facts.Fix = FixHint{UpstreamCommit: tc.fix(h)}
			}
			res := runRootDisqualMode(t, h.dir, tc.facts, tc.strict)
			if tc.want == "" {
				if res.Disqualified {
					t.Fatalf("cleared as %+v, want no clearance", res)
				}
				return
			}
			if !res.Disqualified || res.Reason != tc.want || res.Source == nil {
				t.Fatalf("got %+v, want %s with its source", res, tc.want)
			}
			if tc.want != ReasonAncestorReleaseOutsideRange {
				if len(res.Assumptions) > 0 || res.AncestorRelease != "" {
					t.Fatalf("%s carries an ancestor release: %+v", tc.want, res)
				}
				return
			}
			if res.AncestorRelease != tc.tag || !slices.Equal(res.Assumptions, []string{assumption}) {
				t.Fatalf("release %q assumptions %q, want %q and %q", res.AncestorRelease, res.Assumptions, tc.tag, assumption)
			}
		})
	}

	// The same history cloned: a full clone with tags answers, a shallow clone that did not fetch
	// the release's commit does not.
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{name: "a full clone", want: true},
		{name: "a shallow clone", args: []string{"--depth", "1"}},
		{name: "a full clone without tags", args: []string{"--no-tags"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFixHistory(t, own)
			fixtureGit(t, h.dir, "-c", "tag.gpgsign=false", "tag", "v1.3.0", h.fix)
			clone := t.TempDir()
			args := append([]string{"clone", "-q", "--single-branch", "--branch", "main"}, tc.args...)
			fixtureGit(t, clone, append(args, "file://"+h.dir, ".")...)
			res := runRootDisqualMode(t, clone, facts("example.com/app", fixedRange), false)
			if got := res.Reason == ReasonAncestorReleaseOutsideRange; got != tc.want || res.Disqualified != tc.want {
				t.Fatalf("got %+v, want cleared %v", res, tc.want)
			}
		})
	}

	t.Run("an npm project's own package", func(t *testing.T) {
		h := newFixHistory(t, map[string]string{"package.json": `{"name":"next","dependencies":{"left-pad":"^1.0.0"}}`, "index.js": "module.exports = 1\n"})
		fixtureGit(t, h.dir, "-c", "tag.gpgsign=false", "tag", "v1.3.0", h.fix)
		f := AdvisoryFacts{Coordinate: "next", PURL: "pkg:npm/next", AffectedRanges: fixedRange}
		if res := runRootDisqualMode(t, h.dir, f, false); res.Disqualified {
			t.Fatalf("cleared on a tag convention npm does not define: %+v", res)
		}
	})
}

// runRootDisqualMode is runRootDisqual with disqualification run in strict or practical mode.
func runRootDisqualMode(t *testing.T, dir string, facts AdvisoryFacts, strict bool) DisqualResult {
	t.Helper()
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-ancestor-release", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "GHSA-ancestor-release", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:        "acme/app",
			Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir},
		},
	}}
	src := rootAdvisorySource{facts: facts}
	ctx := context.Background()
	if err := (advisoryIntake{src: src}).Run(ctx, c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	if err := (codebaseInventory{src: src, strict: strict}).Run(ctx, c, store); err != nil {
		t.Fatalf("codebase_inventory: %v", err)
	}
	if err := (disqualificationDiscovery{strict: strict}).Run(ctx, c, store); err != nil {
		t.Fatalf("disqualification_discovery: %v", err)
	}
	arts, err := store.Query(c.ID, artifact.TypeDiscovery)
	if err != nil || len(arts) != 1 {
		t.Fatalf("discovery artifacts: %d, %v", len(arts), err)
	}
	var res DisqualResult
	if err := json.Unmarshal(arts[0].Payload, &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return res
}
