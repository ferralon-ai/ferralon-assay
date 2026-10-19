package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// runRealDisqual runs advisory_intake, codebase_inventory (with the real per-language version
// resolver) and disqualification_discovery over a manifest tree on disk.
func runRealDisqual(t *testing.T, vulnID, lang string, src AdvisorySource, files map[string]string) DisqualResult {
	t.Helper()
	return runDisqualWith(t, vulnID, lang, src, files, realResolverPlugin{lang: lang})
}

// runDisqualWith is runRealDisqual with the version resolver supplied by the caller.
func runDisqualWith(t *testing.T, vulnID, lang string, src AdvisorySource, files map[string]string, p plugin.LanguagePlugin) DisqualResult {
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
	stage := codebaseInventory{checkout: dirCheckout{dir: buildDir, lang: lang}, plugin: p, src: src}
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

func aggregatorOf(modules ...string) string {
	var b strings.Builder
	b.WriteString(`<project><groupId>com.example</groupId><artifactId>root</artifactId><version>1.0.0</version><packaging>pom</packaging><modules>`)
	for _, m := range modules {
		b.WriteString("<module>" + m + "</module>")
	}
	b.WriteString(`</modules></project>`)
	return b.String()
}

func moduleWithParent(g, a, v string) string {
	return `<project><parent><groupId>` + g + `</groupId><artifactId>` + a + `</artifactId><version>` + v + `</version></parent><artifactId>b</artifactId></project>`
}

func csprojReferencing(version string) string {
	return `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="` + version + `" />
  </ItemGroup>
</Project>`
}

func poetryLockOf(flask string) string {
	return "[[package]]\nname = \"flask\"\nversion = \"" + flask + "\"\n"
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
// range and the resolver vouches that it read every version the build can install; one affected
// version anywhere, or a source that could add another, keeps the advisory in analysis.
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
		{"maven: every declaration patched, a Gradle build beside them", "FERRALON-JAVA-DEP-0001", "java", map[string]string{
			"pom.xml": pomDeclaring("1.4.0"), "svc/build.gradle": "dependencies {\n  implementation 'com.example.lib:widget:1.5.0'\n}\n",
		}, false},
		// The parent POM supplies dependencies to a module that declares none; one outside the tree
		// can supply widget at any version.
		{"maven: module inheriting a parent outside the tree", "FERRALON-JAVA-DEP-0001", "java", map[string]string{
			"pom.xml": aggregatorOf("a", "b"), "a/pom.xml": pomDeclaring("1.4.0"), "b/pom.xml": moduleWithParent("com.corp", "corp-parent", "7"),
		}, false},
		{"maven: module inheriting the tree's root", "FERRALON-JAVA-DEP-0001", "java", map[string]string{
			"pom.xml": aggregatorOf("a", "b"), "a/pom.xml": pomDeclaring("1.4.0"), "b/pom.xml": moduleWithParent("com.example", "root", "1.0.0"),
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
		{"pypi: one service lock patched, another affected", "FERRALON-PY-DEP-0001", "python", map[string]string{
			"poetry.lock": poetryLockOf("2.3.2"), "worker/poetry.lock": poetryLockOf("2.3.1"),
		}, false},
		{"pypi: every service lock patched", "FERRALON-PY-DEP-0001", "python", map[string]string{
			"poetry.lock": poetryLockOf("2.3.2"), "worker/poetry.lock": poetryLockOf("2.3.3"),
		}, true},
		{"pypi: every requirements pin patched, nothing locked", "FERRALON-PY-DEP-0001", "python", map[string]string{
			"requirements.txt": "flask==2.3.2\n", "worker/requirements.txt": "flask==2.3.3\n",
		}, false},
		{"nuget: one project patched, another affected", "FERRALON-NET-DEP-0001", "dotnet", map[string]string{
			"Api/Api.csproj": csprojReferencing("[13.0.1]"), "Worker/Worker.csproj": csprojReferencing("[13.0.0]"),
		}, false},
		{"nuget: every project pinned patched, which the lane does not vouch for", "FERRALON-NET-DEP-0001", "dotnet", map[string]string{
			"Api/Api.csproj": csprojReferencing("[13.0.1]"), "Worker/Worker.csproj": csprojReferencing("[13.0.2]"),
		}, false},
		{"nuget: every minimum patched", "FERRALON-NET-DEP-0001", "dotnet", map[string]string{
			"Api/Api.csproj": csprojReferencing("13.0.1"), "Worker/Worker.csproj": csprojReferencing("13.0.2"),
		}, false},
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

// resultStub answers ResolveDependencyVersions with a fixed result, so the pipeline's reading of
// the contract is tested apart from any one resolver.
type resultStub struct {
	realResolverPlugin
	res plugin.DependencyVersionResult
}

func (s resultStub) ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	r := s.res
	if r.Found {
		r.Match.Coordinate = req.Coordinate
	}
	r.Matches = nil
	for _, m := range s.res.Matches {
		m.Coordinate = req.Coordinate
		r.Matches = append(r.Matches, m)
	}
	return r, nil
}

// TestDisqualify_VersionSetMustBeVouchedFor: the version axis disqualifies only on a resolved,
// complete result whose Matches the resolver marked complete. Every other shape keeps the
// advisory in analysis even when each version it shows is patched.
func TestDisqualify_VersionSetMustBeVouchedFor(t *testing.T) {
	patched := plugin.ResolvedDependency{Version: "1.5.0", Resolved: true, Source: "npm"}
	unresolved := plugin.ResolvedDependency{Source: "npm"}
	for _, tc := range []struct {
		name string
		res  plugin.DependencyVersionResult
		want bool
	}{
		{"complete and vouched for", plugin.DependencyVersionResult{
			Partiality: plugin.Complete(), Found: true, Match: patched, Matches: []plugin.ResolvedDependency{patched}, MatchesComplete: true,
		}, true},
		{"not vouched for", plugin.DependencyVersionResult{
			Partiality: plugin.Complete(), Found: true, Match: patched, Matches: []plugin.ResolvedDependency{patched},
		}, false},
		{"a patched match with no set", plugin.DependencyVersionResult{
			Partiality: plugin.Complete(), Found: true, Match: patched,
		}, false},
		{"vouched for with no set", plugin.DependencyVersionResult{
			Partiality: plugin.Complete(), Found: true, Match: patched, MatchesComplete: true,
		}, false},
		{"an unresolved copy in the set", plugin.DependencyVersionResult{
			Partiality: plugin.Complete(), Found: true, Match: patched, Matches: []plugin.ResolvedDependency{patched, unresolved}, MatchesComplete: true,
		}, false},
		{"a partial result", plugin.DependencyVersionResult{
			Partiality: plugin.Partial(plugin.PartialReasonToolFailure), Found: true, Match: patched,
			Matches: []plugin.ResolvedDependency{patched}, MatchesComplete: true,
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := runDisqualWith(t, "FERRALON-JS-DEP-0001", "js", nil, map[string]string{"package.json": `{"name":"app"}`},
				resultStub{realResolverPlugin: realResolverPlugin{lang: "js"}, res: tc.res})
			if res.Disqualified != tc.want {
				t.Fatalf("disqualified = %v (%s), want %v", res.Disqualified, res.Reason, tc.want)
			}
		})
	}
}

// An inventory written before the version set existed carries resolved_version alone: that is one
// version, never a complete set.
func TestExtractVersionAxis_LegacyInventoryIsIncomplete(t *testing.T) {
	store := artifact.NewMemStore()
	putRaw(t, store, "a1", artifact.TypeInventory, `{"resolved_version":"1.5.0"}`)
	axis, ok := extractVersionAxis(store, "a1")
	if !ok || axis.Complete || len(axis.Versions) != 1 || axis.Versions[0] != "1.5.0" {
		t.Fatalf("axis = %+v (ok %v), want 1.5.0 alone, incomplete", axis, ok)
	}
}

// maliciousLeftPad declares left-pad 1.3.0 a malicious release.
type maliciousLeftPad struct{}

func (maliciousLeftPad) Lookup(string) (AdvisoryFacts, bool) {
	return AdvisoryFacts{
		Coordinate: "left-pad", VersionScheme: "npm", PURL: "pkg:npm/left-pad",
		MaliciousPackage: MaliciousPackageFacts{Declared: true, AffectedVersions: []string{"1.3.0"}},
	}, true
}

// A malicious release installed only as a nested copy is present: the disagreeing copies leave no
// single resolved version, and the set still carries the nested one.
func TestMaliciousPresence_NestedCopyBesideAClean(t *testing.T) {
	buildDir := writeTreeFixture(t, map[string]string{"package-lock.json": lockWithLeftPads("1.4.0", "1.3.0")})
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-mal-nested", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "MAL-2024-1", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo: "example.com/target", Revision: "v1", Acquisition: assessment.Acquisition{Mode: "git"},
		},
	}}
	src := maliciousLeftPad{}
	if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	stage := codebaseInventory{checkout: dirCheckout{dir: buildDir, lang: "js"}, plugin: realResolverPlugin{lang: "js"}, src: src}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory: %v", err)
	}
	if err := (maliciousPresence{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("malicious_presence: %v", err)
	}
	res, ok := queryMaliciousPresence(t, store, c.ID)
	if !ok || !res.Present || res.MatchedVersion != "1.3.0" {
		t.Fatalf("presence = %+v (emitted=%v), want present at 1.3.0", res, ok)
	}
}
