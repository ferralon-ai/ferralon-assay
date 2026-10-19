package javaanalysis

import (
	"context"
	"os"
	"path/filepath"
	"slices"
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

func TestParsePOM_PropertyInterpolationResolves(t *testing.T) {
	dir := writeTree(t, map[string]string{"pom.xml": pomProperty})
	if res := resolve(t, dir, "com.example.lib:widget"); !res.Match.Resolved || res.Match.Version != "1.5.0" {
		t.Fatalf("widget via ${widget.version} = %+v, want 1.5.0", res.Match)
	}
	if res := resolve(t, dir, "com.example.lib:core"); !res.Match.Resolved || res.Match.Version != "3.2.1" {
		t.Fatalf("core via ${project.version} = %+v, want 3.2.1", res.Match)
	}
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

// A resolved match for a coordinate that ALSO appears versionless elsewhere must win (the
// resolver prefers a Resolved match over an UNRESOLVED one for the same coordinate).
func TestResolveVersions_ResolvedMatchWinsOverUnresolved(t *testing.T) {
	dir := writeTree(t, map[string]string{"build.gradle": `dependencies {
    implementation 'com.example.lib:widget'          // UNRESOLVED, appears first
    implementation 'com.example.lib:widget:1.4.0'    // RESOLVED
}`})
	res := resolve(t, dir, "com.example.lib:widget")
	if !res.Match.Resolved || res.Match.Version != "1.4.0" {
		t.Fatalf("resolved match must win, got %+v", res.Match)
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
		{"exact-bracket pin", map[string]string{"pom.xml": pom(dep("[1.4.0]"))}, true, []string{"1.4.0"}},
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
		{"plugin not loaded as an extension", map[string]string{"pom.xml": plugin(`<extensions>false</extensions>`)}, true, []string{"1.4.0"}},
		{"module named by a POM file the scan does not read", map[string]string{
			"pom.xml":   reactor(`<modules><module>a</module><module>tools/tools.xml</module></modules>`),
			"a/pom.xml": module(dep("1.4.0")), "tools/tools.xml": module(dep("1.3.0")), "tools/pom.xml": module(dep("1.3.0")),
		}, false, nil},
		{"module under a build-output directory", map[string]string{
			"pom.xml":   reactor(`<modules><module>a</module><module>build/tools</module></modules>`),
			"a/pom.xml": module(dep("1.4.0")), "build/tools/pom.xml": module(dep("1.3.0")),
		}, false, nil},
		{"module under a dot-directory", map[string]string{
			"pom.xml":   reactor(`<modules><module>a</module><module>.ci/gen</module></modules>`),
			"a/pom.xml": module(dep("1.4.0")), ".ci/gen/pom.xml": module(dep("1.3.0")),
		}, false, nil},
		{"module outside the build directory", map[string]string{
			"pom.xml": reactor(`<modules><module>a</module><module>../shared</module></modules>`), "a/pom.xml": module(dep("1.4.0")),
		}, false, nil},
		{"module in a profile the scan did not read", map[string]string{
			"pom.xml":   reactor(`<modules><module>a</module></modules><profiles><profile><id>tools</id><modules><module>build/tools</module></modules></profile></profiles>`),
			"a/pom.xml": module(dep("1.4.0")), "build/tools/pom.xml": module(dep("1.3.0")),
		}, false, nil},
		{"modules all read, profile included", map[string]string{
			"pom.xml":   reactor(`<modules><module>a</module></modules><profiles><profile><id>more</id><modules><module>b/</module></modules></profile></profiles>`),
			"a/pom.xml": module(dep("1.4.0")), "b/pom.xml": module(dep("1.5.0")),
		}, true, []string{"1.4.0", "1.5.0"}},
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
