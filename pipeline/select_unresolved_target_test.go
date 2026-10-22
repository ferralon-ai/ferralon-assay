package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// A target that declares an affected package without a resolvable version must stop the
// select-by-target walk at that package. Moving on to the next package would adjudicate the advisory
// on that package's ranges and refute it, while the first package may sit inside its own.
func TestSelectByTarget_FoundUnresolvedPackageStopsTheWalk(t *testing.T) {
	affected := []AffectedPackage{
		{Coordinate: "org.example:aaa", PURL: "pkg:maven/org.example/aaa", VersionScheme: "maven", FixedVersion: "1.5.0", AffectedRanges: []Range{{Fixed: "1.5.0"}}},
		{Coordinate: "org.example:bbb", PURL: "pkg:maven/org.example/bbb", VersionScheme: "maven", FixedVersion: "2.0.0", AffectedRanges: []Range{{Fixed: "2.0.0"}}},
	}
	deps := func(aaa string) map[string]string {
		d := map[string]string{"org.example:bbb": "2.0.0"}
		if aaa != "" {
			d["org.example:aaa"] = aaa
		}
		return d
	}
	cases := []struct {
		name         string
		graph        []graphModule
		wantSelected string
		wantRefuted  bool
	}{
		{"copies of the first package disagree", []graphModule{{"a", deps("1.0.0")}, {"b", deps("1.5.0")}}, "org.example:aaa", false},
		{"first package absent", []graphModule{{"a", deps("")}, {"b", deps("")}}, "org.example:bbb", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
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
			inv := codebaseInventory{checkout: dirCheckout{dir: dir, lang: "java"}, plugin: realResolverPlugin{lang: "java", java: mavenGraph(t, tc.graph...)}, src: src}
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

// erroringCoordinatePlugin reports every coordinate found and unresolved, except one, which fails.
type erroringCoordinatePlugin struct {
	plugin.StubPlugin
	failing string
}

func (erroringCoordinatePlugin) Language() string { return "java" }

func (s erroringCoordinatePlugin) ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	if req.Coordinate == s.failing {
		return plugin.DependencyVersionResult{}, errors.New("resolver failed")
	}
	return plugin.DependencyVersionResult{Partiality: plugin.Complete(), Found: true, Match: plugin.ResolvedDependency{Coordinate: req.Coordinate}}, nil
}

// Once a package is selected, looking up the advisory's own package only feeds the malicious-package
// presence scan, so a resolver error there must not fail the inventory. Before a package is
// selected, the same error still does.
func TestSelectByTarget_PresenceFallbackErrorAfterSelection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pkgs    []AffectedPackage
		wantErr bool
	}{
		{"package selected", []AffectedPackage{{Coordinate: "org.example:aaa", PURL: "pkg:maven/org.example/aaa"}}, false},
		{"nothing selected", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := selectionStubSource{facts: AdvisoryFacts{
				Coordinate:       "org.example:zzz",
				PURL:             "pkg:maven/org.example/zzz",
				AffectedPackages: tc.pkgs,
				Provenance:       Provenance{Source: "synthetic", TrustTier: TrustFirstParty},
			}}
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "select-fallback-error", Request: assessment.Request{
				Vulnerability: assessment.VulnRef{ID: "GHSA-test-0002", Source: "corpus"},
				Codebase:      assessment.CodebaseRef{Repo: "example.com/target", Revision: "v1", Acquisition: assessment.Acquisition{Mode: "git"}},
			}}
			if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("advisory_intake: %v", err)
			}
			dir := writeTreeFixture(t, map[string]string{"pom.xml": "<project/>"})
			inv := codebaseInventory{checkout: dirCheckout{dir: dir, lang: "java"}, plugin: erroringCoordinatePlugin{failing: "org.example:zzz"}, src: src}
			if err := inv.Run(context.Background(), c, store); (err != nil) != tc.wantErr {
				t.Fatalf("codebase_inventory error = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}
