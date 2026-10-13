package trigger

import (
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// The corpus keys every non-Go advisory by its ecosystem coordinate and gives it no module, so the
// finding's package must be named from the coordinate or no non-Go advisory reaches G1 with one.
func TestAdvisoryFromArtifacts_NamesPackageInEveryEcosystem(t *testing.T) {
	cases := []struct {
		name     string
		advisory map[string]any
		inv      map[string]any
		want     *report.Package
	}{
		{
			name:     "go module",
			advisory: map[string]any{"module": "golang.org/x/net", "coordinate": "golang.org/x/net", "purl": "pkg:golang/golang.org/x/net"},
			inv:      map[string]any{"language": "go", "resolved_version": "v0.1.0"},
			want:     &report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.1.0", PURL: "pkg:golang/golang.org/x/net"},
		},
		{
			name:     "nuget coordinate",
			advisory: map[string]any{"coordinate": "Newtonsoft.Json", "purl": "pkg:nuget/Newtonsoft.Json"},
			inv:      map[string]any{"language": "dotnet", "resolved_version": "12.0.3"},
			want:     &report.Package{Ecosystem: "NuGet", Name: "Newtonsoft.Json", Version: "12.0.3", PURL: "pkg:nuget/Newtonsoft.Json"},
		},
		{
			name:     "maven coordinate",
			advisory: map[string]any{"coordinate": "org.yaml:snakeyaml", "purl": "pkg:maven/org.yaml/snakeyaml"},
			inv:      map[string]any{"language": "java", "resolved_version": "1.33"},
			want:     &report.Package{Ecosystem: "Maven", Name: "org.yaml:snakeyaml", Version: "1.33", PURL: "pkg:maven/org.yaml/snakeyaml"},
		},
		{
			name:     "npm scoped coordinate",
			advisory: map[string]any{"coordinate": "@babel/traverse", "purl": "pkg:npm/%40babel/traverse"},
			inv:      map[string]any{"language": "js", "resolved_version": "7.22.0"},
			want:     &report.Package{Ecosystem: "npm", Name: "@babel/traverse", Version: "7.22.0", PURL: "pkg:npm/%40babel/traverse"},
		},
		{
			name:     "pypi coordinate",
			advisory: map[string]any{"coordinate": "PyYAML", "purl": "pkg:pypi/pyyaml"},
			inv:      map[string]any{"language": "python", "resolved_version": "5.3"},
			want:     &report.Package{Ecosystem: "PyPI", Name: "PyYAML", Version: "5.3", PURL: "pkg:pypi/pyyaml"},
		},
		{
			name: "selected secondary package names the package its version came from",
			advisory: map[string]any{
				"coordinate": "org.springframework:spring-core", "purl": "pkg:maven/org.springframework/spring-core",
				"affected_packages": []map[string]any{
					{"coordinate": "org.springframework:spring-core", "purl": "pkg:maven/org.springframework/spring-core"},
					{"coordinate": "org.springframework:spring-web", "purl": "pkg:maven/org.springframework/spring-web"},
				},
			},
			inv: map[string]any{"language": "java", "resolved_version": "5.3.1", "selected_coordinate": "org.springframework:spring-web"},
			want: &report.Package{
				Ecosystem: "Maven", Name: "org.springframework:spring-web", Version: "5.3.1",
				PURL: "pkg:maven/org.springframework/spring-web",
			},
		},
		{
			name:     "no resolved version",
			advisory: map[string]any{"coordinate": "Newtonsoft.Json", "purl": "pkg:nuget/Newtonsoft.Json"},
			inv:      map[string]any{"language": "dotnet"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			putJSON(t, store, "a1", artifact.TypeNormalizedAdvisory, tc.advisory)
			seedInventory(t, store, "a1", tc.inv)
			_, got := advisoryFromArtifacts(store, "a1", assessment.Request{Vulnerability: assessment.VulnRef{ID: "CVE-test"}}, nil)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("package = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// FuGetGallery, CVE-2024-21907 on Newtonsoft.Json 12.0.3: main emitted not_exploitable because
// the .NET lane matched JObject.Parse by name in the app's own source and found it unreached. With
// the package named from its coordinate the advisory reaches the gate, and a sink with no origin in
// Newtonsoft.Json is not grounds.
func TestFinding_FuGetGalleryNewtonsoftIsNotGroundedOnFirstPartySource(t *testing.T) {
	const appSink = "scip-dotnet nuget FuGetGallery 1.0 FuGetGallery/Json#Parse()."
	store := artifact.NewMemStore()
	const aid = "fuget"
	putJSON(t, store, aid, artifact.TypeNormalizedAdvisory, map[string]any{
		"coordinate": "Newtonsoft.Json", "purl": "pkg:nuget/Newtonsoft.Json",
		"advisory_symbols": []string{"Newtonsoft.Json.Linq.JObject.Parse"},
	})
	seedInventory(t, store, aid, map[string]any{"language": "dotnet", "resolved_version": "12.0.3"})
	putJSON(t, store, aid, artifact.TypeVulnerableSymbol, plugin.SymbolResolutionResult{
		Partiality: plugin.Complete(),
		Resolved:   []plugin.Symbol{{SCIP: appSink}},
		Matched:    map[string][]string{"Newtonsoft.Json.Linq.JObject.Parse": {appSink}},
	})
	seedReachArtifact(t, store, aid, plugin.CallGraphResult{
		Partiality: plugin.Complete(),
		Edges:      []plugin.CallEdge{depEdge("main", "lib")},
	}, plugin.ReachabilityResult{Partiality: plugin.Complete(), Searched: []string{appSink}})

	adv, pkg := advisoryFromArtifacts(store, aid, assessment.Request{Vulnerability: assessment.VulnRef{ID: "CVE-2024-21907"}}, nil)
	if pkg == nil {
		t.Fatal("no package for a NuGet advisory with a resolved version")
	}
	f := finding(store, aid, adv, pkg)
	if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != report.ReasonVulnerableSymbolUnresolved {
		t.Fatalf("got %s/%q, want undetermined/%q", f.Verdict, f.UndeterminedReason, report.ReasonVulnerableSymbolUnresolved)
	}
}

// A C/C++ advisory's package carries the inventory's pin only when exactly one version of the name
// is in the SBOM and the assessment declared it source_unpinned. Every shape is one G1 rejects.
func TestCFamilyObservedPackage(t *testing.T) {
	zlib := func(v string) report.Package {
		return report.Package{Ecosystem: "cfamily", Name: "zlib", Version: v, PURL: "pkg:conan/zlib@" + v}
	}
	for _, tc := range []struct {
		name          string
		flags         []string
		sbom          []report.Package
		version, part string
	}{
		{"one pin", []string{cfamilySoleSourceUnproven}, []report.Package{zlib("1.2.11")}, "1.2.11", cfamilySoleSourceUnproven},
		{"one pin, two instances", []string{cfamilySoleSourceUnproven}, []report.Package{zlib("1.2.11"), zlib("1.2.11")}, "1.2.11", cfamilySoleSourceUnproven},
		{"two pins", []string{plugin.PartialReasonLockfileAmbiguous, cfamilySoleSourceUnproven}, []report.Package{zlib("1.2.11"), zlib("1.3")}, "", cfamilySoleSourceUnproven},
		{"no pin in the SBOM", []string{plugin.PartialReasonSourceUnpinned}, nil, "", plugin.PartialReasonSourceUnpinned},
		{"another ecosystem's pin", []string{cfamilySoleSourceUnproven}, []report.Package{{Ecosystem: "Go", Name: "zlib", Version: "v1.0.0"}}, "", cfamilySoleSourceUnproven},
		{"not declared source_unpinned", []string{plugin.PartialReasonNoManifest}, []report.Package{zlib("1.2.11")}, "", plugin.PartialReasonNoManifest},
		{"no declaration", nil, []report.Package{zlib("1.2.11")}, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cfamilyObservedPackage("zlib", "pkg:conan/zlib", inventoryFacts{Language: "cfamily", PartialityFlags: tc.flags}, tc.sbom)
			want := report.Package{Ecosystem: "cfamily", Name: "zlib", PURL: "pkg:conan/zlib", Version: tc.version, PartialReason: tc.part}
			if *got != want {
				t.Errorf("package = %+v, want %+v", *got, want)
			}
			if _, _, ok := admittedPackage(artifact.NewMemStore(), "a1", got); ok {
				t.Errorf("G1 admits %+v", *got)
			}
		})
	}
}
