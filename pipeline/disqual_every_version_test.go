package pipeline

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// runRealDisqual runs advisory_intake, codebase_inventory (with the real per-language version
// resolver) and disqualification_discovery over a manifest tree on disk.
func runRealDisqual(t *testing.T, vulnID, lang string, src AdvisorySource, files map[string]string) DisqualResult {
	t.Helper()
	buildDir := writeTreeFixture(t, files)
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-every-version", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: vulnID, Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:        "example.com/target",
			Revision:    "v1",
			Acquisition: assessment.Acquisition{Mode: "git"},
		},
	}}
	if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	stage := codebaseInventory{checkout: dirCheckout{dir: buildDir, lang: lang}, plugin: realResolverPlugin{lang: lang}, src: src}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory: %v", err)
	}
	return runDisqual(t, store, c.ID)
}

func pomDeclaring(version string) string {
	return `<project>
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>` + version + `</version></dependency>
  </dependencies>
</project>`
}

func csprojReferencing(version string) string {
	return `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="` + version + `" />
  </ItemGroup>
</Project>`
}

func lockWithLeftPads(top, nested string) string {
	return `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/left-pad": { "version": "` + top + `" },
    "node_modules/wrapper": { "version": "2.0.0" },
    "node_modules/wrapper/node_modules/left-pad": { "version": "` + nested + `" }
  }
}`
}

// TestDisqualify_EveryResolvedVersion: a codebase can carry several versions of one package (a
// module per version in a multi-project build, a nested node_modules install, one requirements file
// per service). The version axis disqualifies only when every one of them is outside the affected
// range; one affected version anywhere keeps the advisory in analysis.
func TestDisqualify_EveryResolvedVersion(t *testing.T) {
	cases := []struct {
		name   string
		vulnID string
		lang   string
		files  map[string]string
		want   bool
	}{
		{"maven: one module patched, another affected", "FERRALON-JAVA-DEP-0001", "java", map[string]string{
			"pom.xml": pomDeclaring("1.4.0"), "service/pom.xml": pomDeclaring("1.3.9"),
		}, false},
		{"maven: every module patched", "FERRALON-JAVA-DEP-0001", "java", map[string]string{
			"pom.xml": pomDeclaring("1.4.0"), "service/pom.xml": pomDeclaring("1.5.0"),
		}, true},
		{"npm: top-level patched, nested install affected", "FERRALON-JS-DEP-0001", "js", map[string]string{
			"package-lock.json": lockWithLeftPads("1.4.0", "1.3.0"),
		}, false},
		{"npm: nested install patched, top-level affected", "FERRALON-JS-DEP-0001", "js", map[string]string{
			"package-lock.json": lockWithLeftPads("1.3.0", "1.4.0"),
		}, false},
		{"npm: every install patched", "FERRALON-JS-DEP-0001", "js", map[string]string{
			"package-lock.json": lockWithLeftPads("1.4.0", "1.5.0"),
		}, true},
		{"pypi: one requirements file patched, another affected", "FERRALON-PY-DEP-0001", "python", map[string]string{
			"requirements.txt": "flask==2.3.2\n", "worker/requirements.txt": "flask==2.3.1\n",
		}, false},
		{"pypi: every requirements file patched", "FERRALON-PY-DEP-0001", "python", map[string]string{
			"requirements.txt": "flask==2.3.2\n", "worker/requirements.txt": "flask==2.3.3\n",
		}, true},
		{"nuget: one project patched, another affected", "FERRALON-NET-DEP-0001", "dotnet", map[string]string{
			"Api/Api.csproj": csprojReferencing("13.0.1"), "Worker/Worker.csproj": csprojReferencing("13.0.0"),
		}, false},
		{"nuget: every project patched", "FERRALON-NET-DEP-0001", "dotnet", map[string]string{
			"Api/Api.csproj": csprojReferencing("13.0.1"), "Worker/Worker.csproj": csprojReferencing("13.0.2"),
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runRealDisqual(t, tc.vulnID, tc.lang, nil, tc.files)
			if res.Disqualified != tc.want {
				t.Fatalf("disqualified = %v (%s), want %v", res.Disqualified, res.Reason, tc.want)
			}
		})
	}
}

// twoPresentPackagesSource is a two-package advisory whose packages the target both depends on.
type twoPresentPackagesSource struct{}

func (twoPresentPackagesSource) Lookup(string) (AdvisoryFacts, bool) {
	pkg := func(module, fixed string) AffectedPackage {
		return AffectedPackage{
			Module: module, VersionScheme: "gomod", PURL: "pkg:golang/" + module,
			AffectedRanges: []Range{{Fixed: fixed, FixedVersion: fixed}},
			Symbols:        []string{module + ".Sink"},
		}
	}
	a, b := pkg("example.com/a", "v1.2.0"), pkg("example.com/b", "v1.5.0")
	return AdvisoryFacts{
		Module: a.Module, VersionScheme: a.VersionScheme, PURL: a.PURL,
		AffectedRanges: a.AffectedRanges, Symbols: a.Symbols,
		AffectedPackages: []AffectedPackage{a, b},
		Provenance:       Provenance{Source: "synthetic", TrustTier: TrustFirstParty},
	}, true
}

// TestDisqualify_EveryPresentAffectedPackage: an advisory naming several packages is disqualified
// on version only when every package the codebase carries is outside its own range. A patched
// first package does not clear an affected second one.
func TestDisqualify_EveryPresentAffectedPackage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		aVersion string
		bVersion string
		want     bool
	}{
		{"first patched, second affected", "v1.3.0", "v1.0.0", false},
		{"first affected, second patched", "v1.0.0", "v1.6.0", false},
		{"both patched", "v1.3.0", "v1.6.0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := runRealDisqual(t, "CVE-TEST-TWO-PRESENT", "go", twoPresentPackagesSource{}, map[string]string{
				"go.mod": "module example.com/target\n\ngo 1.21\n\nrequire (\n\texample.com/a " + tc.aVersion + "\n\texample.com/b " + tc.bVersion + "\n)\n",
			})
			if res.Disqualified != tc.want {
				t.Fatalf("disqualified = %v (%s), want %v", res.Disqualified, res.Reason, tc.want)
			}
		})
	}
}
