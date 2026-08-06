package javaanalysis

import (
	"context"
	"os"
	"path/filepath"
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
// TEGRON-JAVA-DEP-0001 repro poms, the exact (version, resolved) the pipeline disqualification
// path consumes: patched=1.4.0 resolved, vulnerable=1.3.9 resolved, unresolved=UNRESOLVED.
func TestResolveVersions_CorpusRepros(t *testing.T) {
	const coord = "com.example.lib:widget"
	cases := []struct {
		repro        string
		wantVer      string
		wantResolved bool
	}{
		{"TEGRON-JAVA-DEP-0001-patched", "1.4.0", true},
		{"TEGRON-JAVA-DEP-0001-vulnerable", "1.3.9", true},
		{"TEGRON-JAVA-DEP-0001-unresolved", "", false},
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
