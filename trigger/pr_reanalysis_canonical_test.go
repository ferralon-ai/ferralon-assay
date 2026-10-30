package trigger

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// canonicalAdvisory names its package in the advisory's own spelling, not the SBOM's. Its range is
// above every version these tests use, so a fresh row is a settled disqualification.
var canonicalAdvisory = assessment.VulnRef{ID: "FERRALON-TEST-CANON", Source: "corpus"}

type canonicalSource struct{ coordinate, purlType string }

func (s canonicalSource) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	if id != canonicalAdvisory.ID {
		return pipeline.NewTableSource().Lookup(id)
	}
	return pipeline.AdvisoryFacts{
		Coordinate:     s.coordinate,
		PURL:           "pkg:" + s.purlType + "/" + s.coordinate,
		VersionScheme:  s.purlType,
		AffectedRanges: []pipeline.Range{{Introduced: "90.0.0", Fixed: "90.1.0"}},
		Symbols:        []string{s.coordinate + ".vulnerable"},
		Provenance:     pipeline.Provenance{Source: "test", TrustTier: pipeline.TrustFirstParty},
	}, true
}

// headVersionPlugin resolves the one dependency the head declares, under the SBOM's own spelling.
type headVersionPlugin struct {
	plugin.StubPlugin
	lang, purlType, name, version string
}

func (p headVersionPlugin) Language() string { return p.lang }

func (p headVersionPlugin) ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	return plugin.DependencyVersionResult{
		Partiality: plugin.Complete(),
		Found:      true,
		Match:      plugin.ResolvedDependency{Coordinate: req.Coordinate, Version: p.version, Resolved: true, Source: p.purlType},
	}, nil
}

func (p headVersionPlugin) ResolveInventory(context.Context, plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return plugin.DependencyInventory{
		Partiality: plugin.Complete(),
		Nodes: []plugin.DependencyNode{{
			ID: p.name + "@" + p.version, PURL: "pkg:" + p.purlType + "/" + p.name + "@" + p.version, Version: p.version, Direct: true,
		}},
	}, nil
}

// TestReanalyzeSlice_ChangedPackageMatchedCanonically: the changed set carries the SBOM's names,
// PEP 503 normalised for PyPI and lower-cased for NuGet, while the selected package and the
// advisory keep the advisory's spelling. A PR that moves django under an advisory naming Django has
// changed the advisory's package, so the baseline's row must not stand.
func TestReanalyzeSlice_ChangedPackageMatchedCanonically(t *testing.T) {
	cases := []struct {
		name, lang, ecosystem, purlType, coordinate, sbomName, from, to string
		inherited                                                       bool
	}{
		{"PyPI: Django advisory, django bumped", "python", "PyPI", "pypi", "Django", "django", "4.2.0", "4.2.5", false},
		{"PyPI: typing_extensions advisory, typing-extensions bumped", "python", "PyPI", "pypi", "typing_extensions", "typing-extensions", "4.7.0", "4.8.0", false},
		{"NuGet: Newtonsoft.Json advisory, newtonsoft.json bumped", "dotnet", "NuGet", "nuget", "Newtonsoft.Json", "newtonsoft.json", "13.0.1", "13.0.3", false},
		{"control: Django advisory, django unchanged", "python", "PyPI", "pypi", "Django", "django", "4.2.0", "4.2.0", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := func(v string) report.Package {
				return report.Package{Ecosystem: tc.ecosystem, Name: tc.sbomName, Version: v, PURL: "pkg:" + tc.purlType + "/" + tc.sbomName + "@" + v}
			}
			base := pkg(tc.from)
			other := report.Package{Ecosystem: tc.ecosystem, Name: "unrelated", Version: "1.0.0"}
			baseline := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
				AddPackages(base).
				NotExploitable(report.Advisory{ID: canonicalAdvisory.ID, Source: canonicalAdvisory.Source}, &base, "vulnerable_symbol_absent", baselineDetail).
				WithProvenance(report.Provenance{CommitSHA: "base-sha"}).
				Build()
			store := &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM}}
			res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
				Subject:    Subject{Repo: "r", ResolvedCommit: "pr-sha"},
				Codebase:   assessment.CodebaseRef{Repo: "r", Revision: "main"},
				PRSBOM:     report.SBOM{Packages: []report.Package{pkg(tc.to), other}},
				Advisories: []assessment.VulnRef{canonicalAdvisory},
				AssessOptions: []pipeline.AssessOption{
					pipeline.WithCheckout(fixedCheckout{dir: t.TempDir(), lang: tc.lang}),
					pipeline.WithPlugin(headVersionPlugin{lang: tc.lang, purlType: tc.purlType, name: tc.sbomName, version: tc.to}),
					pipeline.WithAdvisorySource(canonicalSource{coordinate: tc.coordinate, purlType: tc.purlType}),
				},
			})
			if err != nil {
				t.Fatalf("RunPRInherit: %v", err)
			}
			rows := rowsFor(res.Report, canonicalAdvisory.ID)
			if len(rows) != 1 {
				t.Fatalf("%d rows for %s, want 1: %+v", len(rows), canonicalAdvisory.ID, rows)
			}
			if inherited := rows[0].Evidence.Detail == baselineDetail; inherited != tc.inherited {
				t.Fatalf("inherited the baseline's row = %v, want %v (row: %s, %q, pkg %+v; changed = %q)",
					inherited, tc.inherited, rows[0].Verdict, rows[0].Evidence.Detail, rows[0].Package, res.ChangedPackages)
			}
		})
	}
}

// TestAffectedPackageChanged_UnreadableSetCountsAsChanged: an advisory whose package set cannot be
// read cannot be shown unchanged, so the baseline's row must not stand. The last row is the
// control: a set that names its packages, none of them changed.
func TestAffectedPackageChanged_UnreadableSetCountsAsChanged(t *testing.T) {
	django := &report.Package{Ecosystem: "PyPI", Name: "Django", Version: "4.2.0"}
	unchanged := map[string]struct{}{"PyPI\x00flask": {}}
	cases := []struct {
		name      string
		advisory  string // the normalized advisory payload; "" stores none
		inventory string // the inventory payload; "" stores none
		pkg       *report.Package
		changed   map[string]struct{}
		want      bool
	}{
		{"no normalized advisory", "", "", django, unchanged, true},
		{"a malformed advisory payload", `{`, "", django, unchanged, true},
		{"no package selected: the inventory's ecosystem names it", `{"coordinate":"Django"}`, `{"language":"python"}`, nil,
			map[string]struct{}{"PyPI\x00django": {}}, true},
		{"no package selected: the same name in another ecosystem is not it", `{"coordinate":"Django"}`, `{"language":"python"}`, nil,
			map[string]struct{}{"npm\x00Django": {}}, false},
		{"a nameless affected package beside a readable unchanged one", `{"coordinate":"Django","affected_packages":[{"coordinate":"Django"},{}]}`, "", django, unchanged, true},
		{"a payload naming no package", `{"affected_packages":[]}`, "", django, unchanged, true},
		{"control: every package named, none changed", `{"coordinate":"Django","affected_packages":[{"coordinate":"Django"}]}`, "", django, unchanged, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			for typ, payload := range map[artifact.Type]string{artifact.TypeNormalizedAdvisory: tc.advisory, artifact.TypeInventory: tc.inventory} {
				if payload == "" {
					continue
				}
				if _, err := store.Put(&artifact.Artifact{AssessmentID: "a1", Type: typ, Payload: []byte(payload)}); err != nil {
					t.Fatalf("put %s: %v", typ, err)
				}
			}
			if got := affectedPackageChanged(store, "a1", tc.pkg, tc.changed); got != tc.want {
				t.Fatalf("affectedPackageChanged = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestReanalyzeSlice_MigratedV1RowWithNoSourceInherits: a baseline row migrated from v1 carries no
// source, so the advisory's row is found by id alone. Its package did not change, so it inherits.
func TestReanalyzeSlice_MigratedV1RowWithNoSourceInherits(t *testing.T) {
	text, other := goPkg("golang.org/x/text", "v0.3.6"), goPkg("example.org/other", "v1.0.0")
	baseline := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
		AddPackages(text).
		NotExploitable(report.Advisory{ID: wiringAdvisory.ID}, &text, "vulnerable_symbol_absent", baselineDetail).
		WithProvenance(report.Provenance{CommitSHA: "base-sha"}).
		Build()
	store := &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM}}
	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:    Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		Codebase:   assessment.CodebaseRef{Repo: "r", Revision: "main"},
		PRSBOM:     report.SBOM{Packages: []report.Package{text, other}},
		Advisories: []assessment.VulnRef{wiringAdvisory},
		AssessOptions: []pipeline.AssessOption{
			pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, goModRequiring("golang.org/x/text v0.3.6", "example.org/other v1.0.0")), lang: "go"}),
			pipeline.WithPlugin(refutingGoPlugin{inventory: plugin.Complete()}),
		},
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	rows := rowsFor(res.Report, wiringAdvisory.ID)
	if len(rows) != 1 {
		t.Fatalf("%d rows for %s, want 1: %+v", len(rows), wiringAdvisory.ID, rows)
	}
	if rows[0].Evidence.Detail != baselineDetail {
		t.Fatalf("row is fresh (%s, %q), want the baseline's v1 row inherited (changed = %q)", rows[0].Verdict, rows[0].Evidence.Detail, res.ChangedPackages)
	}
}
