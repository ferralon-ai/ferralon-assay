package javaanalysis

import (
	"context"
	"os"
	"path/filepath"
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

// wantDeclaredOnly fails unless res found a Gradle declaration that is not Resolved: with no lock
// binding it, a declared literal is only a request (Gradle selects the highest version asked for
// anywhere in the graph), so it is kept as the Constraint and never as the Version.
func wantDeclaredOnly(t *testing.T, res plugin.DependencyVersionResult, constraint string) {
	t.Helper()
	if !res.Found || res.Match.Resolved || res.Match.Version != "" || res.Match.Constraint != constraint {
		t.Fatalf("match = %+v (found %v), want found, not resolved, constraint %q", res.Match, res.Found, constraint)
	}
}

func TestParseGradle_StringNotation(t *testing.T) {
	dir := writeTree(t, map[string]string{"build.gradle": gradleStringNotationFile})

	wantDeclaredOnly(t, resolve(t, dir, "com.example.lib:widget"), "1.4.0")
	wantDeclaredOnly(t, resolve(t, dir, "com.test:helper"), "3.0.0")
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
	wantDeclaredOnly(t, resolve(t, dir, "com.example.lib:widget"), "1.4.0")
	if res := resolve(t, dir, "no.ver:thing"); !res.Found || res.Match.Resolved {
		t.Fatalf("map-notation no-version must be Found but UNRESOLVED, got %+v", res.Match)
	}
}

func TestParseGradle_KotlinDSL(t *testing.T) {
	dir := writeTree(t, map[string]string{"build.gradle.kts": `dependencies {
    implementation("com.example.lib:widget:1.4.0")
}`})
	wantDeclaredOnly(t, resolve(t, dir, "com.example.lib:widget"), "1.4.0")
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
