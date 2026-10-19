package javaanalysis

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// writeTree writes files (path→content, paths relative to a fresh temp dir) and returns the
// dir. A trivial .java file is always added so the tree is a recognizable Java source tree.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["src/App.java"] = "package x;\nclass App {}\n"
	for rel, content := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func resolve(t *testing.T, dir, coord string) plugin.DependencyVersionResult {
	t.Helper()
	res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: coord})
	if err != nil {
		t.Fatalf("ResolveDependencyVersions: %v", err)
	}
	return res
}

// --- pom.xml ----------------------------------------------------------------

const pomLiteral = `<project>
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>1.4.0</version></dependency>
    <dependency><groupId>org.other</groupId><artifactId>thing</artifactId><version>2.1.3</version></dependency>
  </dependencies>
</project>`

func TestParsePOM_LiteralVersionResolves(t *testing.T) {
	dir := writeTree(t, map[string]string{"pom.xml": pomLiteral})
	res := resolve(t, dir, "com.example.lib:widget")
	if !res.Found {
		t.Fatal("widget declaration must be Found")
	}
	if !res.Match.Resolved || res.Match.Version != "1.4.0" {
		t.Fatalf("widget = %+v, want resolved 1.4.0", res.Match)
	}
	if res.Match.Source != "pom" {
		t.Errorf("source = %q, want pom", res.Match.Source)
	}
}

const pomProperty = `<project>
  <groupId>com.example</groupId><artifactId>app</artifactId><version>3.2.1</version>
  <properties>
    <widget.version>1.5.0</widget.version>
  </properties>
  <dependencies>
    <dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>${widget.version}</version></dependency>
    <dependency><groupId>com.example.lib</groupId><artifactId>core</artifactId><version>${project.version}</version></dependency>
  </dependencies>
</project>`

// All reports a ${prop} version as the POM interpolates it, but the Match leaves it unresolved: a
// -Dprop on the command line or in .mvn/maven.config overrides the POM's value.
func TestParsePOM_PropertyInterpolation(t *testing.T) {
	dir := writeTree(t, map[string]string{"pom.xml": pomProperty})
	for coord, ver := range map[string]string{"com.example.lib:widget": "1.5.0", "com.example.lib:core": "3.2.1"} {
		res := resolve(t, dir, coord)
		if !res.Found || res.Match.Resolved || res.Match.Version != "" {
			t.Fatalf("%s match = %+v, want found and unresolved", coord, res.Match)
		}
		if !hasDep(res.All, coord, ver) {
			t.Fatalf("%s: All = %+v, want it resolved at %s", coord, res.All, ver)
		}
	}
}

func hasDep(all []plugin.ResolvedDependency, coord, ver string) bool {
	for _, d := range all {
		if d.Coordinate == coord && d.Resolved && d.Version == ver {
			return true
		}
	}
	return false
}

const pomBOMManaged = `<project>
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>9.9.9</version></dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId></dependency>
  </dependencies>
</project>`

// A BOM/dependencyManagement-managed dependency with no inline <version> is UNRESOLVED — we
// do NOT read dependencyManagement for the version, and we NEVER guess one. This is the
// fail-open input the disqualification predicate must not treat as not-affected.
func TestParsePOM_BOMManagedIsUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{"pom.xml": pomBOMManaged})
	res := resolve(t, dir, "com.example.lib:widget")
	if !res.Found {
		t.Fatal("the <dependencies> declaration must be Found (it exists, just versionless)")
	}
	if res.Match.Resolved || res.Match.Version != "" {
		t.Fatalf("BOM-managed widget must be UNRESOLVED, got %+v", res.Match)
	}
}

const pomUnresolvedProp = `<project>
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>${missing.version}</version></dependency>
  </dependencies>
</project>`

// A ${prop} that does not resolve to a literal property is UNRESOLVED, never guessed.
func TestParsePOM_UnresolvedPropertyIsUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{"pom.xml": pomUnresolvedProp})
	res := resolve(t, dir, "com.example.lib:widget")
	if res.Match.Resolved {
		t.Fatalf("unresolved ${missing.version} must be UNRESOLVED, got %+v", res.Match)
	}
}

func TestParsePOM_CoordinateNotDeclaredNotFound(t *testing.T) {
	dir := writeTree(t, map[string]string{"pom.xml": pomLiteral})
	res := resolve(t, dir, "com.nope:absent")
	if res.Found {
		t.Fatalf("absent coordinate must not be Found, got %+v", res.Match)
	}
}

// --- build.gradle -----------------------------------------------------------

const gradleStringNotationFile = `dependencies {
    implementation 'com.example.lib:widget:1.4.0'
    api "org.other:thing:2.1.3"
    testImplementation('com.test:helper:3.0.0')
    implementation 'no.version:dep'            // versionless → UNRESOLVED
    implementation "interp:olated:$libVersion" // interpolated → UNRESOLVED
}`

func TestParseGradle_StringNotation(t *testing.T) {
	dir := writeTree(t, map[string]string{"build.gradle": gradleStringNotationFile})

	if res := resolve(t, dir, "com.example.lib:widget"); !res.Match.Resolved || res.Match.Version != "1.4.0" {
		t.Fatalf("widget = %+v, want 1.4.0", res.Match)
	}
	if res := resolve(t, dir, "com.test:helper"); !res.Match.Resolved || res.Match.Version != "3.0.0" {
		t.Fatalf("helper = %+v, want 3.0.0", res.Match)
	}
	if res := resolve(t, dir, "no.version:dep"); !res.Found || res.Match.Resolved {
		t.Fatalf("versionless dep must be Found but UNRESOLVED, got %+v", res.Match)
	}
	if res := resolve(t, dir, "interp:olated"); !res.Found || res.Match.Resolved {
		t.Fatalf("interpolated version must be Found but UNRESOLVED, got %+v", res.Match)
	}
}

const gradleMapNotationFile = `dependencies {
    implementation group: 'com.example.lib', name: 'widget', version: '1.4.0'
    implementation group: 'no.ver', name: 'thing'
}`

func TestParseGradle_MapNotation(t *testing.T) {
	dir := writeTree(t, map[string]string{"build.gradle": gradleMapNotationFile})
	if res := resolve(t, dir, "com.example.lib:widget"); !res.Match.Resolved || res.Match.Version != "1.4.0" {
		t.Fatalf("map-notation widget = %+v, want 1.4.0", res.Match)
	}
	if res := resolve(t, dir, "no.ver:thing"); !res.Found || res.Match.Resolved {
		t.Fatalf("map-notation no-version must be Found but UNRESOLVED, got %+v", res.Match)
	}
}

func TestParseGradle_KotlinDSL(t *testing.T) {
	dir := writeTree(t, map[string]string{"build.gradle.kts": `dependencies {
    implementation("com.example.lib:widget:1.4.0")
}`})
	if res := resolve(t, dir, "com.example.lib:widget"); !res.Match.Resolved || res.Match.Version != "1.4.0" {
		t.Fatalf("kotlin-dsl widget = %+v, want 1.4.0", res.Match)
	}
}

// --- no build files: declared-partial degrade / hard errors ------------------

// A tree with no pom.xml/build.gradle degrades to declared-partial (no_manifest) — a normal
// repo shape must not turn the run red. pom.xml/build.gradle ARE the declaration, so there is
// nothing to seed; the partiality is the entire soundness guarantee.
func TestResolveVersions_NoBuildFilesDegradesToPartial(t *testing.T) {
	dir := writeTree(t, map[string]string{}) // only src/App.java, no pom/gradle
	res := resolve(t, dir, "x:y")            // resolve t.Fatals on a hard error

	if res.Partiality.Complete {
		t.Fatal("no build file must never report Complete — it must be distinguishable from a clean scan")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoManifest) {
		t.Fatalf("Reasons = %v, want %q", res.Partiality.Reasons, plugin.PartialReasonNoManifest)
	}
	if len(res.All) != 0 {
		t.Fatalf("nothing is declared, so nothing may be reported; All=%+v", res.All)
	}
	if res.Found {
		t.Fatalf("no build file cannot make a coordinate Found; got %+v", res.Match)
	}
}

func TestResolveVersions_MissingBuildDirIsHardError(t *testing.T) {
	_, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: filepath.Join(t.TempDir(), "nope"), Coordinate: "x:y"})
	if err == nil {
		t.Fatal("a missing build dir must be a hard error")
	}
}

// --- against the real corpus repro fixtures ---------------------------------

// TestResolveVersions_CorpusRepros proves the pure-Go resolver produces, against the ACTUAL
// FERRALON-JAVA-DEP-0001 repro poms, the exact (version, resolved) the pipeline disqualification
// path consumes: patched=1.4.0 resolved, vulnerable=1.3.9 resolved, unresolved=UNRESOLVED.
func TestResolveVersions_CorpusRepros(t *testing.T) {
	const coord = "com.example.lib:widget"
	cases := []struct {
		repro        string
		wantVer      string
		wantResolved bool
	}{
		{"FERRALON-JAVA-DEP-0001-patched", "1.4.0", true},
		{"FERRALON-JAVA-DEP-0001-vulnerable", "1.3.9", true},
		{"FERRALON-JAVA-DEP-0001-unresolved", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.repro, func(t *testing.T) {
			dir := filepath.Join("..", "..", "..", "corpus", "testdata", "repros", tc.repro)
			res := resolve(t, dir, coord)
			if !res.Found {
				t.Fatalf("%s: widget declaration must be Found", tc.repro)
			}
			if res.Match.Resolved != tc.wantResolved || res.Match.Version != tc.wantVer {
				t.Fatalf("%s: got %+v, want version=%q resolved=%v", tc.repro, res.Match, tc.wantVer, tc.wantResolved)
			}
		})
	}
}

// A coordinate that ALSO appears versionless elsewhere leaves the Match unresolved: the build may
// ship the copy whose version this reader can't see.
func TestResolveVersions_UnresolvedCopyLeavesMatchUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a/pom.xml": `<project><dependencies><dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId></dependency></dependencies></project>`,
		"b/pom.xml": pomLiteral,
	})
	res := resolve(t, dir, "com.example.lib:widget")
	if !res.Found || res.Match.Resolved || res.Match.Version != "" {
		t.Fatalf("match = %+v, want found and unresolved", res.Match)
	}
}

// A build file that doesn't parse could declare the coordinate at any version, so it leaves the
// Match unresolved, and Found even where no readable file names the coordinate.
func TestResolveVersions_UnparseableBuildFileLeavesMatchUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{"a/pom.xml": "<project", "b/pom.xml": pomLiteral})
	if res := resolve(t, dir, "com.example.lib:widget"); !res.Found || res.Match.Resolved || res.Match.Version != "" {
		t.Fatalf("match = %+v, want found and unresolved", res.Match)
	}
	if res := resolve(t, dir, "com.example:undeclared"); !res.Found || res.Match.Resolved || res.Match.Coordinate != "com.example:undeclared" {
		t.Fatalf("match = %+v, want found and unresolved", res.Match)
	}
}

// widgetPOM is a module POM declaring com.example.lib:widget at version, with extra spliced in at
// the top level.
func widgetPOM(version, extra string) string {
	return `<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>m</artifactId><version>1.0.0</version>` + extra +
		`<dependencies><dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>` + version + `</version></dependency></dependencies></project>`
}

const reactorPOM = `<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>root</artifactId><version>1.0.0</version><packaging>pom</packaging><modules><module>a</module><module>b</module></modules></project>`

// reactorOf is an aggregator POM whose reactor holds modules.
func reactorOf(modules ...string) string {
	body := `<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>root</artifactId><version>1.0.0</version><packaging>pom</packaging><modules>`
	for _, m := range modules {
		body += `<module>` + m + `</module>`
	}
	return body + `</modules></project>`
}

// TestResolveVersions_MavenAllowList pins which Maven builds the Match resolves in. Every copy of
// the coordinate must be a literal pin in a POM this reader models whole, and all copies must
// agree. The reactor and profile rows are builds where one copy alone would put the version
// outside the range while another copy sits inside it.
func TestResolveVersions_MavenAllowList(t *testing.T) {
	const coord = "com.example.lib:widget"
	cases := []struct {
		name    string
		files   map[string]string
		wantVer string
	}{
		{"reactor modules agree", map[string]string{"pom.xml": reactorPOM, "a/pom.xml": widgetPOM("1.4.0", ""), "b/pom.xml": widgetPOM("1.4.0", "")}, "1.4.0"},
		{"module in a skipped directory agrees", map[string]string{"pom.xml": reactorOf("a", "build"), "a/pom.xml": widgetPOM("1.4.0", ""), "build/pom.xml": widgetPOM("1.4.0", "")}, "1.4.0"},
		{"module in a skipped directory disagrees", map[string]string{"pom.xml": reactorOf("a", "build"), "a/pom.xml": widgetPOM("1.4.0", ""), "build/pom.xml": widgetPOM("1.3.9", "")}, ""},
		{"module only a profile lists", map[string]string{"pom.xml": strings.Replace(reactorOf(), "<modules></modules>", "<profiles><profile><id>p</id><modules><module>build</module></modules></profile></profiles>", 1),
			"build/pom.xml": widgetPOM("1.4.0", "")}, ""},
		{"module file not named pom.xml", map[string]string{"pom.xml": reactorOf("a", "b/b-pom.xml"), "a/pom.xml": widgetPOM("1.4.0", ""), "b/b-pom.xml": widgetPOM("1.3.9", "")}, ""},
		{"nested module in a skipped directory", map[string]string{"pom.xml": reactorOf("a", "out"), "a/pom.xml": widgetPOM("1.4.0", ""),
			"out/pom.xml": reactorOf("build"), "out/build/pom.xml": widgetPOM("1.3.9", "")}, ""},
		{"module that is not there", map[string]string{"pom.xml": reactorOf("a", "gone"), "a/pom.xml": widgetPOM("1.4.0", "")}, ""},
		{"module outside the build directory", map[string]string{"pom.xml": reactorOf("a", "../elsewhere"), "a/pom.xml": widgetPOM("1.4.0", "")}, ""},
		{"reactor patched module first", map[string]string{"pom.xml": reactorPOM, "a/pom.xml": widgetPOM("1.4.0", ""), "b/pom.xml": widgetPOM("1.3.9", "")}, ""},
		{"reactor affected module first", map[string]string{"pom.xml": reactorPOM, "a/pom.xml": widgetPOM("1.3.9", ""), "b/pom.xml": widgetPOM("1.4.0", "")}, ""},
		{"profile overrides the version", map[string]string{"pom.xml": widgetPOM("1.4.0",
			`<profiles><profile><id>p</id><activation><activeByDefault>true</activeByDefault></activation><dependencies><dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>1.3.9</version></dependency></dependencies></profile></profiles>`)}, ""},
		{"sibling module ships it transitively", map[string]string{"pom.xml": reactorPOM, "a/pom.xml": widgetPOM("1.4.0", ""),
			"b/pom.xml": `<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>b</artifactId><version>1.0.0</version>` +
				`<dependencies><dependency><groupId>com.example.lib</groupId><artifactId>widget-client</artifactId><version>2.0.0</version></dependency></dependencies></project>`}, ""},
		{"sibling module without dependencies", map[string]string{"pom.xml": reactorPOM, "a/pom.xml": widgetPOM("1.4.0", ""),
			"b/pom.xml": `<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>b</artifactId><version>1.0.0</version></project>`}, "1.4.0"},
		{"profile elsewhere in the reactor", map[string]string{"pom.xml": reactorPOM, "a/pom.xml": widgetPOM("1.4.0", ""), "b/pom.xml": widgetPOM("1.4.0", "<profiles/>")}, ""},
		{"profile in the reactor root", map[string]string{"pom.xml": strings.Replace(reactorPOM, "<modules>",
			`<profiles><profile><id>p</id><dependencies><dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>1.3.9</version></dependency></dependencies></profile></profiles><modules>`, 1),
			"a/pom.xml": widgetPOM("1.4.0", ""), "b/pom.xml": widgetPOM("1.4.0", "")}, ""},
		{"build extension", map[string]string{"pom.xml": widgetPOM("1.4.0", `<build><extensions><extension><groupId>x</groupId><artifactId>y</artifactId><version>1</version></extension></extensions></build>`)}, ""},
		{"plain build section", map[string]string{"pom.xml": widgetPOM("1.4.0", `<build><plugins/></build>`)}, "1.4.0"},
		{"core extensions file", map[string]string{"pom.xml": widgetPOM("1.4.0", ""), ".mvn/extensions.xml": "<extensions/>"}, ""},
		{"maven.config extension class path", map[string]string{"pom.xml": widgetPOM("1.4.0", ""), ".mvn/maven.config": "-Dmaven.ext.class.path=x.jar\n"}, ""},
		{"property version", map[string]string{"pom.xml": widgetPOM("${w}", "<properties><w>1.4.0</w></properties>")}, ""},
		{"reactor literal beside a property version", map[string]string{"pom.xml": strings.Replace(reactorPOM, "<modules>", "<properties><w>1.3.9</w></properties><modules>", 1),
			"a/pom.xml": widgetPOM("1.4.0", ""), "b/pom.xml": widgetPOM("${w}", "")}, ""},
		{"RELEASE", map[string]string{"pom.xml": widgetPOM("RELEASE", "")}, ""},
		{"LATEST", map[string]string{"pom.xml": widgetPOM("LATEST", "")}, ""},
		{"exact range", map[string]string{"pom.xml": widgetPOM("[1.4.0]", "")}, ""},
		{"qualified literal", map[string]string{"pom.xml": widgetPOM("1.4.0.Final", "")}, "1.4.0.Final"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := resolve(t, writeTree(t, tc.files), coord)
			if !res.Found {
				t.Fatalf("widget must be Found; got %+v", res)
			}
			if res.Match.Resolved != (tc.wantVer != "") || res.Match.Version != tc.wantVer {
				t.Fatalf("match = %+v, want version %q resolved %v", res.Match, tc.wantVer, tc.wantVer != "")
			}
		})
	}
}

// A subtree the walk can't list could hold a copy at any version: the run is partial and the
// Match unresolved, not complete on the copies the walk did reach.
func TestResolveVersions_UnlistableSubtreeLeavesMatchUnresolved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	// No reactor names b, so only the walk can reach it.
	dir := writeTree(t, map[string]string{"a/pom.xml": widgetPOM("1.4.0", ""), "b/pom.xml": widgetPOM("1.4.0", "")})
	if res := resolve(t, dir, "com.example.lib:widget"); !res.Match.Resolved || res.Match.Version != "1.4.0" {
		t.Fatalf("control: match = %+v, want 1.4.0", res.Match)
	}
	locked := filepath.Join(dir, "B")
	if _, err := os.Stat(filepath.Join(dir, "b")); err == nil {
		locked = filepath.Join(dir, "b")
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	res := resolve(t, dir, "com.example.lib:widget")
	if res.Partiality.Complete {
		t.Errorf("partiality = %+v, want partial", res.Partiality)
	}
	if !res.Found || res.Match.Resolved || res.Match.Version != "" {
		t.Fatalf("match = %+v, want found and unresolved", res.Match)
	}
}

// A module that points outside the analyzed tree is a copy this run does not read, even when the
// file is there and agrees.
func TestResolveVersions_ModuleOutsideTheBuildDirectory(t *testing.T) {
	dir := writeTree(t, map[string]string{"build/pom.xml": reactorOf("a", "../elsewhere"), "build/a/pom.xml": widgetPOM("1.4.0", ""),
		"elsewhere/pom.xml": widgetPOM("1.4.0", "")})
	res := resolve(t, filepath.Join(dir, "build"), "com.example.lib:widget")
	if !res.Found || res.Match.Resolved || res.Match.Version != "" {
		t.Fatalf("match = %+v, want found and unresolved", res.Match)
	}
}

// TestResolveVersions_ParentOutsideTheTree: a module inherits every dependency of its parent that it
// doesn't declare itself. A parent Maven reads from a repository is read from the local caches; one
// they don't hold, or can't vouch for, withholds the Match of a module that doesn't declare the
// coordinate. Maven takes the parent from the tree only when the POM at its relativePath carries the
// parent's coordinates.
func TestResolveVersions_ParentOutsideTheTree(t *testing.T) {
	parent := func(g, a, v, extra string) string {
		return `<parent><groupId>` + g + `</groupId><artifactId>` + a + `</artifactId><version>` + v + `</version>` + extra + `</parent>`
	}
	corp := parent("com.corp", "corp-parent", "7", "")
	root := parent("com.example", "root", "1.0.0", "")
	module := func(parent, deps string) string {
		return `<project><modelVersion>4.0.0</modelVersion>` + parent + `<artifactId>b</artifactId><dependencies>` + deps + `</dependencies></project>`
	}
	widget := func(v string) string {
		return `<dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>` + v + `</version></dependency>`
	}
	other := `<dependency><groupId>org.other</groupId><artifactId>thing</artifactId><version>2.1.3</version></dependency>`
	// cached is a POM in a local repository: its path under the repository root, and its body.
	cached := func(g, a, v, parent, deps string) map[string]string {
		path := strings.ReplaceAll(g, ".", "/") + "/" + a + "/" + v + "/" + a + "-" + v + ".pom"
		return map[string]string{path: `<project><modelVersion>4.0.0</modelVersion>` + parent + `<groupId>` + g + `</groupId><artifactId>` + a +
			`</artifactId><version>` + v + `</version><packaging>pom</packaging><dependencies>` + deps + `</dependencies></project>`}
	}
	merge := func(ms ...map[string]string) map[string]string {
		out := map[string]string{}
		for _, m := range ms {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}
	grand := parent("com.corp", "grand", "3", "")
	corpEmpty := cached("com.corp", "corp-parent", "7", "", "")
	tests := []struct {
		name  string
		files map[string]string
		// repo is the user's local repository (~/.m2/repository), by path under it, or under the home
		// directory with a "~/" prefix.
		repo map[string]string
		want string
		// complete is MatchesComplete: every copy the build can install was read.
		complete bool
	}{
		{"remote parent in the cache, no dependencies", map[string]string{"b/pom.xml": module(corp, "")}, corpEmpty, "1.4.0", true},
		{"remote parent in the cache declares the same version", map[string]string{"b/pom.xml": module(corp, "")},
			cached("com.corp", "corp-parent", "7", "", widget("1.4.0")), "1.4.0", false},
		{"remote parent in the cache declares another version", map[string]string{"b/pom.xml": module(corp, "")},
			cached("com.corp", "corp-parent", "7", "", widget("1.3.0")), "", false},
		{"remote parent in the cache declares an interpolated version", map[string]string{"b/pom.xml": module(corp, "")},
			cached("com.corp", "corp-parent", "7", "", widget("${widget.version}")), "", false},
		{"remote parent in the cache declares other dependencies only", map[string]string{"b/pom.xml": module(corp, "")},
			cached("com.corp", "corp-parent", "7", "", other), "", false},
		{"remote parent in the cache isn't modeled", map[string]string{"b/pom.xml": module(corp, "")},
			map[string]string{"com/corp/corp-parent/7/corp-parent-7.pom": `<project><groupId>com.corp</groupId><artifactId>corp-parent</artifactId><version>7</version><profiles><profile><id>p</id></profile></profiles></project>`},
			"", false},
		{"remote parent in the cache doesn't parse", map[string]string{"b/pom.xml": module(corp, "")},
			map[string]string{"com/corp/corp-parent/7/corp-parent-7.pom": `<project><groupId>com.corp`}, "", false},
		{"grandparent in the cache declares another version", map[string]string{"b/pom.xml": module(corp, "")},
			merge(cached("com.corp", "corp-parent", "7", grand, ""), cached("com.corp", "grand", "3", "", widget("1.3.0"))), "", false},
		{"grandparent missing from the cache", map[string]string{"b/pom.xml": module(corp, "")},
			cached("com.corp", "corp-parent", "7", grand, ""), "", false},
		{"nearest ancestor's declaration wins", map[string]string{"b/pom.xml": module(corp, "")},
			merge(cached("com.corp", "corp-parent", "7", grand, widget("1.4.0")), cached("com.corp", "grand", "3", "", widget("1.3.0"))), "1.4.0", false},
		{"remote parent in the cache names itself as its parent", map[string]string{"b/pom.xml": module(corp, "")},
			cached("com.corp", "corp-parent", "7", corp, ""), "", false},
		{"remote parent in the project-local cache, no dependencies", map[string]string{
			"b/pom.xml": module(corp, ""), ".m2/repository/com/corp/corp-parent/7/corp-parent-7.pom": corpEmpty["com/corp/corp-parent/7/corp-parent-7.pom"],
		}, nil, "1.4.0", true},
		{"remote parent copies in the two caches differ", map[string]string{
			"b/pom.xml": module(corp, ""), ".m2/repository/com/corp/corp-parent/7/corp-parent-7.pom": corpEmpty["com/corp/corp-parent/7/corp-parent-7.pom"],
		}, cached("com.corp", "corp-parent", "7", "", widget("1.4.0")), "", false},
		{"remote parent copies in the Maven and Gradle caches differ", map[string]string{"b/pom.xml": module(corp, "")},
			merge(corpEmpty, map[string]string{"~/.gradle/caches/modules-2/files-2.1/com.corp/corp-parent/7/0a1b/corp-parent-7.pom": `<project><groupId>com.corp</groupId><artifactId>corp-parent</artifactId><version>7</version><dependencies>` + widget("1.3.0") + `</dependencies></project>`}),
			"", false},
		{"parent version differs from the tree's, cache holds it", map[string]string{"b/pom.xml": module(parent("com.example", "root", "0.9.0", ""), "")},
			cached("com.example", "root", "0.9.0", "", ""), "1.4.0", true},
		{"relativePath outside the root carries the parent, cache holds it too", map[string]string{
			"b/pom.xml": module(parent("com.example", "root", "1.0.0", `<relativePath>../../outside/pom.xml</relativePath>`), ""),
		}, cached("com.example", "root", "1.0.0", "", ""), "", false},
		{"remote parent version is a range, cache holds a directory named for it", map[string]string{"b/pom.xml": module(parent("com.corp", "corp-parent", "[7,8)", ""), "")},
			cached("com.corp", "corp-parent", "[7,8)", "", ""), "", false},
		{"remote parent, no dependencies", map[string]string{"b/pom.xml": module(corp, "")}, nil, "", false},
		{"remote parent, other dependencies only", map[string]string{"b/pom.xml": module(corp, other)}, nil, "", false},
		{"remote parent, module declares the same version", map[string]string{"b/pom.xml": module(corp, widget("1.4.0"))}, nil, "1.4.0", true},
		{"remote parent, module declares another version", map[string]string{"b/pom.xml": module(corp, widget("1.3.0"))}, nil, "", true},
		{"parent in the tree", map[string]string{"b/pom.xml": module(root, "")}, nil, "1.4.0", true},
		{"parent in the tree named by relativePath", map[string]string{
			"b/pom.xml": module(parent("com.example", "root", "1.0.0", `<relativePath>..</relativePath>`), ""),
		}, nil, "1.4.0", true},
		{"empty relativePath", map[string]string{"b/pom.xml": module(parent("com.example", "root", "1.0.0", `<relativePath/>`), "")}, nil, "", false},
		{"parent version differs from the tree's", map[string]string{"b/pom.xml": module(parent("com.example", "root", "0.9.0", ""), "")}, nil, "", false},
		{"relativePath outside the root", map[string]string{
			"b/pom.xml": module(parent("com.example", "root", "1.0.0", `<relativePath>../../outside/pom.xml</relativePath>`), ""),
		}, nil, "", false},
		{"parent in the tree inherits from a remote parent", map[string]string{
			"b/pom.xml":   module(parent("com.example", "mid", "1.0.0", `<relativePath>../mid</relativePath>`), ""),
			"mid/pom.xml": `<project><modelVersion>4.0.0</modelVersion>` + corp + `<groupId>com.example</groupId><artifactId>mid</artifactId><version>1.0.0</version><packaging>pom</packaging></project>`,
		}, nil, "", false},
		// Maven 4 infers a parent with no coordinates from its relativePath.
		{"parent with no coordinates, relativePath outside the root", map[string]string{
			"b/pom.xml": module(`<parent><relativePath>../../outside/pom.xml</relativePath></parent>`, ""),
		}, nil, "", false},
		{"parent with no coordinates, empty relativePath", map[string]string{"b/pom.xml": module(`<parent><relativePath/></parent>`, "")}, nil, "", false},
		{"parent with no coordinates, in the tree", map[string]string{"b/pom.xml": module(`<parent/>`, "")}, nil, "1.4.0", true},
		{"parent with no version, in the tree", map[string]string{
			"b/pom.xml": module(`<parent><groupId>com.example</groupId><artifactId>root</artifactId></parent>`, ""),
		}, nil, "1.4.0", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := isolateHome(t)
			for k, v := range tc.repo {
				path := filepath.Join(home, ".m2", "repository", filepath.FromSlash(k))
				if rest, ok := strings.CutPrefix(k, "~/"); ok {
					path = filepath.Join(home, filepath.FromSlash(rest))
				}
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(v), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			files := map[string]string{"pom.xml": reactorOf("a", "b"), "a/pom.xml": widgetPOM("1.4.0", root)}
			for k, v := range tc.files {
				files[k] = v
			}
			// The build is checked out under build/, so a relativePath can reach a POM beside it.
			tree := map[string]string{"outside/pom.xml": reactorOf()}
			for k, v := range files {
				tree["build/"+k] = v
			}
			dir := writeTree(t, tree)
			res := resolve(t, filepath.Join(dir, "build"), "com.example.lib:widget")
			if !res.Found || res.Match.Version != tc.want || res.Match.Resolved != (tc.want != "") {
				t.Fatalf("match = %+v, want version %q", res.Match, tc.want)
			}
			if res.MatchesComplete != tc.complete {
				t.Fatalf("MatchesComplete = %v, want %v (Matches %+v)", res.MatchesComplete, tc.complete, res.Matches)
			}
		})
	}
}

// MatchesComplete holds only for a POM-only build in which every module declares the coordinate
// at a literal version or pulls in nothing; anything that can bring in another version leaves it
// false.
func TestResolveVersions_MatchesComplete(t *testing.T) {
	dep := func(v string) string {
		return `<dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>` + v + `</version></dependency>`
	}
	other := `<dependency><groupId>org.other</groupId><artifactId>thing</artifactId><version>2.1.3</version></dependency>`
	pom := func(deps string) string {
		return `<project><groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version><dependencies>` + deps + `</dependencies></project>`
	}
	module := func(deps string) string {
		return `<project><parent><groupId>com.example</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent>
<artifactId>m</artifactId><dependencies>` + deps + `</dependencies></project>`
	}
	const aggregator = `<project><groupId>com.example</groupId><artifactId>parent</artifactId><version>1.0.0</version>
<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>
<dependencyManagement><dependencies><dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>1.0.0</version></dependency></dependencies></dependencyManagement></project>`
	reactor := func(modules string) string {
		return `<project><groupId>com.example</groupId><artifactId>parent</artifactId><version>1.0.0</version><packaging>pom</packaging>` + modules + `</project>`
	}
	plugin := func(extensions string) string {
		return `<project><dependencies>` + dep("1.4.0") + `</dependencies><build><plugins><plugin><groupId>org.acme</groupId><artifactId>acme-maven-plugin</artifactId><version>1.0</version>` + extensions + `</plugin></plugins></build></project>`
	}
	tests := []struct {
		name     string
		files    map[string]string
		want     bool
		versions []string
	}{
		{"literal pin", map[string]string{"pom.xml": pom(dep("1.4.0"))}, true, []string{"1.4.0"}},
		{"exact-bracket pin", map[string]string{"pom.xml": pom(dep("[1.4.0]"))}, false, nil},
		{"modules pinning their own versions under a managing parent", map[string]string{
			"pom.xml": aggregator, "a/pom.xml": module(dep("1.4.0")), "b/pom.xml": module(dep("1.3.0")),
		}, true, []string{"1.4.0", "1.3.0"}},
		{"module taking its version from the parent's dependencyManagement", map[string]string{
			"pom.xml": aggregator, "a/pom.xml": module(dep("1.4.0")),
			"b/pom.xml": module(`<dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId></dependency>`),
		}, false, nil},
		{"module pulling other packages", map[string]string{
			"pom.xml": aggregator, "a/pom.xml": module(dep("1.4.0")), "b/pom.xml": module(other),
		}, false, nil},
		{"module whose parent is out of scope", map[string]string{
			"pom.xml": pom(dep("1.4.0")), "b/pom.xml": `<project><parent><groupId>com.example</groupId><artifactId>corp</artifactId><version>1</version><relativePath>../../corp</relativePath></parent><artifactId>b</artifactId></project>`,
		}, false, nil},
		{"property version", map[string]string{
			"pom.xml": `<project><properties><widget.version>1.4.0</widget.version></properties><dependencies>` + dep("${widget.version}") + `</dependencies></project>`,
		}, false, nil},
		{"range version", map[string]string{"pom.xml": pom(dep("[1.0,2.0)"))}, false, nil},
		{"profile with dependencies", map[string]string{
			"pom.xml": `<project><dependencies>` + dep("1.4.0") + `</dependencies><profiles><profile><id>legacy</id><dependencies>` + dep("1.2.0") + `</dependencies></profile></profiles></project>`,
		}, false, nil},
		{"core extensions", map[string]string{"pom.xml": pom(dep("1.4.0")), ".mvn/extensions.xml": `<extensions />`}, false, nil},
		{"build extension", map[string]string{
			"pom.xml": `<project><dependencies>` + dep("1.4.0") + `</dependencies><build><extensions><extension><groupId>org.acme</groupId><artifactId>acme-ext</artifactId><version>1.0</version></extension></extensions></build></project>`,
		}, false, nil},
		{"plugin loaded as a build extension", map[string]string{"pom.xml": plugin(`<extensions>true</extensions>`)}, false, nil},
		{"build extension in a profile", map[string]string{
			"pom.xml": `<project><dependencies>` + dep("1.4.0") + `</dependencies><profiles><profile><id>ext</id><build><extensions><extension><groupId>org.acme</groupId><artifactId>acme-ext</artifactId><version>1.0</version></extension></extensions></build></profile></profiles></project>`,
		}, false, nil},
		{"plugin with extensions false", map[string]string{"pom.xml": plugin(`<extensions>false</extensions>`)}, false, nil},
		{"module named by a POM file the walk does not return", map[string]string{
			"pom.xml":   reactor(`<modules><module>a</module><module>tools/tools.xml</module></modules>`),
			"a/pom.xml": module(dep("1.4.0")), "tools/tools.xml": module(dep("1.3.0")), "tools/pom.xml": module(dep("1.3.0")),
		}, true, []string{"1.4.0", "1.3.0", "1.3.0"}},
		{"module under a build-output directory", map[string]string{
			"pom.xml":   reactor(`<modules><module>a</module><module>build/tools</module></modules>`),
			"a/pom.xml": module(dep("1.4.0")), "build/tools/pom.xml": module(dep("1.3.0")),
		}, true, []string{"1.4.0", "1.3.0"}},
		{"module under a dot-directory", map[string]string{
			"pom.xml":   reactor(`<modules><module>a</module><module>.ci/gen</module></modules>`),
			"a/pom.xml": module(dep("1.4.0")), ".ci/gen/pom.xml": module(dep("1.3.0")),
		}, true, []string{"1.4.0", "1.3.0"}},
		{"module outside the build directory", map[string]string{
			"pom.xml": reactor(`<modules><module>a</module><module>../shared</module></modules>`), "a/pom.xml": module(dep("1.4.0")),
		}, false, nil},
		{"module in a profile the scan did not read", map[string]string{
			"pom.xml":   reactor(`<modules><module>a</module></modules><profiles><profile><id>tools</id><modules><module>build/tools</module></modules></profile></profiles>`),
			"a/pom.xml": module(dep("1.4.0")), "build/tools/pom.xml": module(dep("1.3.0")),
		}, false, nil},
		{"module only a profile lists", map[string]string{
			"pom.xml":   reactor(`<modules><module>a</module></modules><profiles><profile><id>more</id><modules><module>b/</module></modules></profile></profiles>`),
			"a/pom.xml": module(dep("1.4.0")), "b/pom.xml": module(dep("1.5.0")),
		}, false, []string{"1.4.0", "1.5.0"}},
		{"Gradle build beside the POM", map[string]string{
			"pom.xml": pom(dep("1.4.0")), "svc/build.gradle": "dependencies {\n  implementation 'com.example.lib:widget:1.4.0'\n}\n",
		}, false, nil},
		{"Gradle settings in scope", map[string]string{"pom.xml": pom(dep("1.4.0")), "settings.gradle": "rootProject.name = 'x'\n"}, false, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := resolve(t, writeTree(t, tc.files), "com.example.lib:widget")
			if r.MatchesComplete != tc.want {
				t.Fatalf("MatchesComplete = %v, want %v (Matches %+v)", r.MatchesComplete, tc.want, r.Matches)
			}
			var got []string
			for _, m := range r.Matches {
				got = append(got, m.Version)
			}
			if tc.versions != nil && !slices.Equal(got, tc.versions) {
				t.Fatalf("Matches = %v, want %v", got, tc.versions)
			}
		})
	}
}

// A subtree the walk cannot read may hold another module, so Matches cannot be complete.
func TestResolveVersions_MatchesCompleteUnreadableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0 directory")
	}
	dir := writeTree(t, map[string]string{
		"pom.xml":        `<project><dependencies><dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>1.4.0</version></dependency></dependencies></project>`,
		"hidden/pom.xml": `<project />`,
	})
	hidden := filepath.Join(dir, "hidden")
	if err := os.Chmod(hidden, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hidden, 0o755) })
	if r := resolve(t, dir, "com.example.lib:widget"); r.MatchesComplete {
		t.Fatalf("an unreadable subtree must leave MatchesComplete false; got %+v", r.Matches)
	}
}
