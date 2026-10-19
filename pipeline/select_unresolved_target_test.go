package pipeline

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// A target that declares an affected package without a resolvable version must stop the
// select-by-target walk at that package. Moving on to the next package would adjudicate the advisory
// on that package's ranges and refute it, while the first package may sit inside its own.
func TestSelectByTarget_FoundUnresolvedPackageStopsTheWalk(t *testing.T) {
	reactor := `<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>root</artifactId><version>1.0.0</version><packaging>pom</packaging><modules><module>a</module><module>b</module></modules></project>`
	module := func(name string, deps ...[2]string) string {
		body := `<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>` + name + `</artifactId><version>1.0.0</version><dependencies>`
		for _, d := range deps {
			body += `<dependency><groupId>org.example</groupId><artifactId>` + d[0] + `</artifactId><version>` + d[1] + `</version></dependency>`
		}
		return body + `</dependencies></project>`
	}
	affected := []AffectedPackage{
		{Coordinate: "org.example:aaa", PURL: "pkg:maven/org.example/aaa", VersionScheme: "maven", FixedVersion: "1.5.0", AffectedRanges: []Range{{Fixed: "1.5.0"}}},
		{Coordinate: "org.example:bbb", PURL: "pkg:maven/org.example/bbb", VersionScheme: "maven", FixedVersion: "2.0.0", AffectedRanges: []Range{{Fixed: "2.0.0"}}},
	}
	cases := []struct {
		name         string
		files        map[string]string
		wantSelected string
		wantRefuted  bool
	}{
		{"copies of the first package disagree", map[string]string{
			"pom.xml":   reactor,
			"a/pom.xml": module("a", [2]string{"aaa", "1.0.0"}, [2]string{"bbb", "2.0.0"}),
			"b/pom.xml": module("b", [2]string{"aaa", "1.5.0"}, [2]string{"bbb", "2.0.0"}),
		}, "org.example:aaa", false},
		{"first package versioned only by property", map[string]string{
			"pom.xml":   reactor,
			"a/pom.xml": module("a", [2]string{"aaa", "${aaa.version}"}, [2]string{"bbb", "2.0.0"}),
			"b/pom.xml": module("b", [2]string{"aaa", "${aaa.version}"}, [2]string{"bbb", "2.0.0"}),
		}, "org.example:aaa", false},
		{"first package absent", map[string]string{
			"pom.xml":   reactor,
			"a/pom.xml": module("a", [2]string{"bbb", "2.0.0"}),
			"b/pom.xml": module("b", [2]string{"bbb", "2.0.0"}),
		}, "org.example:bbb", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTreeFixture(t, tc.files)
			src := selectionStubSource{facts: AdvisoryFacts{
				Coordinate:       "org.example:aaa",
				PURL:             "pkg:maven/org.example/aaa",
				VersionScheme:    "maven",
				AffectedRanges:   []Range{{Fixed: "1.5.0"}},
				AffectedPackages: affected,
				Provenance:       Provenance{Source: "synthetic", TrustTier: TrustFirstParty},
			}}
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "select-unresolved", Request: assessment.Request{
				Vulnerability: assessment.VulnRef{ID: "GHSA-test-0001", Source: "corpus"},
				Codebase:      assessment.CodebaseRef{Repo: "example.com/target", Revision: "v1", Acquisition: assessment.Acquisition{Mode: "git"}},
			}}
			if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("advisory_intake: %v", err)
			}
			inv := codebaseInventory{checkout: dirCheckout{dir: dir, lang: "java"}, plugin: realResolverPlugin{lang: "java"}, src: src}
			if err := inv.Run(context.Background(), c, store); err != nil {
				t.Fatalf("codebase_inventory: %v", err)
			}
			sel, ok := extractSelectedPackage(store, c.ID)
			if !ok || sel.Coordinate != tc.wantSelected {
				t.Fatalf("selected = %+v (ok %v), want %s", sel, ok, tc.wantSelected)
			}
			res := runDisqual(t, store, c.ID)
			if refuted := res.Disqualified && res.Reason == ReasonVersionNotInRange; refuted != tc.wantRefuted {
				t.Fatalf("disqualification = %+v, want refuted %v", res, tc.wantRefuted)
			}
		})
	}
}
