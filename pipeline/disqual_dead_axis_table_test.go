// disqual_dead_axis_table_test.go
//
// The durable dead-axis regression. For EVERY scheme versionOutsideRange
// dispatches on, run the REAL codebase_inventory stage over a representative fixture tree and assert
// the resolved_version it produces is one that scheme's comparator can actually adjudicate.
//
// Why this table and not more per-scheme unit tests. The go-toolchain axis was dark for three weeks
// behind a comparator with full unit coverage, a passing "end-to-end" test, and a guard test
// defending its emptiness — because every version the comparator ever saw had been hand-written into
// the inventory artifact by a test (disqual_versionscheme_u5_test.go:87), and the production resolver
// returned "" unconditionally. Unit-testing a comparator proves the comparator; only enumerating the
// dispatch and demanding a live PRODUCER for each arm proves the axis. A scheme whose production
// resolver cannot produce a parseable input fails this table, in any ecosystem, whether or not anyone
// remembered to write a test for it.
//
// Provenance discipline: nothing is seeded between the stages. Every case runs advisory_intake and
// codebase_inventory for real, against real manifests on disk, through the real per-language
// resolver, and reads resolved_version back off the artifact the stage actually wrote.
package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/goanalysis"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/jsanalysis"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/pythonanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// realResolverPlugin is a plugin whose BuildManifest and ResolveDependencyVersions are the REAL
// per-language implementations. Only the analysis ops (symbols, call graph, ingresses) stay stubbed —
// the subject of this table is where a version comes from, not what is reachable from it.
type realResolverPlugin struct {
	plugin.StubPlugin
	lang string
}

func (p realResolverPlugin) Language() string { return p.lang }

func (p realResolverPlugin) BuildManifest(ctx context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	if p.lang == "go" {
		return goanalysis.BuildManifest(ctx, req)
	}
	return plugin.BuildManifestResult{Partiality: plugin.Unsupported()}, nil
}

func (p realResolverPlugin) ResolveDependencyVersions(ctx context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	switch p.lang {
	case "java":
		return javaanalysis.ResolveDependencyVersions(ctx, req)
	case "js":
		return jsanalysis.ResolveDependencyVersions(ctx, req)
	case "python":
		return pythonanalysis.ResolveDependencyVersions(ctx, req)
	case "dotnet":
		return dotnetanalysis.ResolveDependencyVersions(ctx, req)
	default:
		// Go resolves in-pipeline off go.mod (the real Go plugin declares this op Unsupported).
		return plugin.DependencyVersionResult{Found: false}, nil
	}
}

// writeTreeFixture materializes a manifest tree on disk. Keys are paths relative to the root.
func writeTreeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// defaultSchemeSource is the representative advisory for the "" (no derivable scheme) arm of the
// dispatch. No AdvisoryTable entry produces it: schemeFromPURL yields "" only for a PURL type it does
// not recognize, and every corpus advisory carries a recognized one. So the arm gets a synthetic
// advisory whose PURL type is unrecognized and whose Module is a real go.mod require — the version
// still comes from the real in-pipeline resolver, only the scheme selection is synthetic.
type defaultSchemeSource struct{}

func (defaultSchemeSource) Lookup(string) (AdvisoryFacts, bool) {
	return AdvisoryFacts{
		Module:         "example.com/dep",
		PURL:           "pkg:cargo/example-dep", // unrecognized type ⇒ schemeFromPURL == ""
		AffectedRanges: []Range{{Fixed: "v1.5.0", FixedVersion: "v1.5.0"}},
		Provenance:     Provenance{Source: "synthetic", TrustTier: TrustFirstParty},
	}, true
}

// TestVersionAxis_EveryDispatchedSchemeHasALiveProducer is the dead-axis guard.
//
// For each scheme the dispatch branches on, it asserts three things in order, because they fail
// differently and the diagnostic matters:
//
//  1. the intake stage stamped the expected scheme onto the affected range set (the comparator that
//     will run is the one this case claims to cover);
//  2. the REAL inventory stage produced a non-empty resolved_version (the axis has an input at all —
//     this is the assertion go-toolchain failed before M3);
//  3. the scheme's comparator ADJUDICATED that version against that advisory's real range set —
//     ok=true, i.e. settled rather than failed open. A resolver that produces a string the
//     comparator cannot order is a dead axis wearing a live one's clothes.
func TestVersionAxis_EveryDispatchedSchemeHasALiveProducer(t *testing.T) {
	for _, tc := range deadAxisCases() {
		name := tc.scheme
		if name == "" {
			name = "default(empty)"
		}
		t.Run(name, func(t *testing.T) {
			buildDir := writeTreeFixture(t, tc.files)
			store := artifact.NewMemStore()
			caseID := "case-dead-axis-" + name
			c := &assessment.Assessment{ID: caseID, Request: assessment.Request{
				Vulnerability: assessment.VulnRef{ID: tc.vulnID, Source: "corpus"},
				Codebase: assessment.CodebaseRef{
					Repo:        "example.com/target",
					Revision:    "v1",
					Acquisition: assessment.Acquisition{Mode: "git"},
				},
			}}

			if err := (advisoryIntake{src: tc.src}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("advisory_intake: %v", err)
			}
			stage := codebaseInventory{
				checkout: dirCheckout{dir: buildDir, lang: tc.lang},
				plugin:   realResolverPlugin{lang: tc.lang},
				src:      tc.src,
			}
			if err := stage.Run(context.Background(), c, store); err != nil {
				t.Fatalf("codebase_inventory: %v", err)
			}

			// 1. The comparator this case claims to cover is the one that will run.
			rngs, rangeKnown := extractAffectedRange(store, caseID)
			if !rangeKnown {
				t.Fatalf("no usable affected range for %s — the fixture cannot exercise the %q comparator", tc.vulnID, tc.scheme)
			}
			for i, r := range rngs {
				if r.Scheme != tc.scheme {
					t.Fatalf("affected_ranges[%d].scheme = %q, want %q", i, r.Scheme, tc.scheme)
				}
			}

			// 2. The real production resolver produced an input for the axis.
			ver, verKnown := extractResolvedVersion(store, caseID)
			if !verKnown {
				t.Fatalf("the real codebase_inventory stage resolved NO version for scheme %q: the version axis is DEAD for this scheme — %s has no production writer of resolved_version",
					tc.scheme, tc.vulnID)
			}

			// 3. The comparator settled on it, rather than failing open on an unorderable string.
			if _, ok := versionOutsideRanges(ver, rngs); !ok {
				t.Fatalf("the %q comparator could not adjudicate resolved_version %q against %v: the production resolver emits a value its own comparator fails OPEN on",
					tc.scheme, ver, rngs)
			}
		})
	}
}

// deadAxisCase is one dispatch arm plus the real fixture tree that exercises its production producer.
type deadAxisCase struct {
	scheme string
	vulnID string
	lang   string
	src    AdvisorySource // nil ⇒ the real corpus AdvisoryTable
	files  map[string]string
}

func deadAxisTableSchemes() []string {
	var out []string
	for _, tc := range deadAxisCases() {
		out = append(out, tc.scheme)
	}
	return out
}

func deadAxisCases() []deadAxisCase {
	return []deadAxisCase{
		{
			scheme: "",
			vulnID: "CVE-TEST-DEFAULT-SCHEME",
			lang:   "go",
			src:    defaultSchemeSource{},
			files: map[string]string{
				"go.mod": "module example.com/target\n\ngo 1.21\n\nrequire example.com/dep v1.4.2\n",
			},
		},
		{
			scheme: "gomod",
			vulnID: "GO-2021-0113", // golang.org/x/text, fixed v0.3.7
			lang:   "go",
			files: map[string]string{
				"go.mod": "module example.com/target\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.6\n",
			},
		},
		{
			scheme: "maven",
			vulnID: "TEGRON-JAVA-DEP-0001", // com.example.lib:widget, fixed 1.4.0
			lang:   "java",
			files: map[string]string{
				"pom.xml": `<project>
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>1.3.9</version></dependency>
  </dependencies>
</project>`,
			},
		},
		{
			scheme: "npm",
			vulnID: "TEGRON-JS-DEP-0001", // left-pad, fixed 1.4.0
			lang:   "js",
			files: map[string]string{
				"package-lock.json": `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/left-pad": { "version": "1.3.0" }
  }
}`,
			},
		},
		{
			scheme: "pypi",
			vulnID: "TEGRON-PY-DEP-0001", // flask, fixed 2.3.2
			lang:   "python",
			files: map[string]string{
				"requirements.txt": "flask==2.3.1\n",
			},
		},
		{
			scheme: "nuget",
			vulnID: "TEGRON-NET-DEP-0001", // Newtonsoft.Json, fixed 13.0.1
			lang:   "dotnet",
			files: map[string]string{
				"App.csproj": `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.0" />
  </ItemGroup>
</Project>`,
			},
		},
		{
			// The arm this table was written for. Before M3 the production resolver returned ""
			// unconditionally here, so assertion 2 failed and no version ever reached the U7
			// comparator. The subject declares only a floor, which is all a go.mod can ever say.
			scheme: "go-toolchain",
			vulnID: "CVE-2023-39325", // stdlib, fixed go1.20.10 / go1.21.3
			lang:   "go",
			files: map[string]string{
				"go.mod": "module example.com/target\n\ngo 1.20\n",
			},
		},
	}

}

// TestVersionAxis_DeadAxisTableCoversTheWholeDispatch keeps the table honest against the code. A
// scheme admitted at intake with no row above is an axis with no producer proof — exactly the state
// go-toolchain shipped in — so adding one to recognizedVersionSchemes without a fixture fails here.
func TestVersionAxis_DeadAxisTableCoversTheWholeDispatch(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range deadAxisTableSchemes() {
		covered[tc] = true
	}
	for _, scheme := range recognizedVersionSchemes {
		if !covered[scheme] {
			t.Errorf("version scheme %q is admitted at intake but has no dead-axis table row: it dispatches a comparator whose production producer of resolved_version is unproven", scheme)
		}
	}
	for scheme := range covered {
		if !schemeRecognized(scheme) {
			t.Errorf("scheme %q has a dead-axis table row but is no longer an admitted version scheme — drop the row", scheme)
		}
	}
}
