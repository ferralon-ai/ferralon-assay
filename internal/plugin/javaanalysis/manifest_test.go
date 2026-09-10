package javaanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func buildManifest(t *testing.T, dir, lang string) plugin.BuildManifestResult {
	t.Helper()
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir}, lang)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	return res
}

// The irreducible residue every JVM manifest must declare (Target/Configuration always;
// exact-Toolchain unless a pin file records it). The tests assert these are named, never
// silently dropped, and never Complete over them (inv.5).
func assertHonestResidue(t *testing.T, res plugin.BuildManifestResult, wantToolchainUnpinned bool) {
	t.Helper()
	if res.Partiality.Complete {
		t.Errorf("JVM manifest must never be Complete (portable Target + no static Configuration): %+v", res.Partiality)
	}
	if res.Target != "" {
		t.Errorf("Target must be empty (portable bytecode), got %q", res.Target)
	}
	if res.Configuration != "" {
		t.Errorf("Configuration must be empty (no static profile), got %q", res.Configuration)
	}
	if !hasReason(res.Partiality, reasonTargetNotApplicable) {
		t.Errorf("missing declared reason %q in %v", reasonTargetNotApplicable, res.Partiality.Reasons)
	}
	if !hasReason(res.Partiality, reasonNoBuildConfiguration) {
		t.Errorf("missing declared reason %q in %v", reasonNoBuildConfiguration, res.Partiality.Reasons)
	}
	if got := hasReason(res.Partiality, reasonToolchainUnpinned); got != wantToolchainUnpinned {
		t.Errorf("toolchain_unpinned reason = %v, want %v (reasons %v)", got, wantToolchainUnpinned, res.Partiality.Reasons)
	}
}

const pomManifest = `<project>
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <properties>
    <maven.compiler.release>17</maven.compiler.release>
    <maven.compiler.source>11</maven.compiler.source>
  </properties>
</project>`

const pomJavaVersionProp = `<project>
  <groupId>com.example</groupId><artifactId>svc</artifactId><version>1.0.0</version>
  <properties>
    <java.ver>1.8</java.ver>
    <java.version>${java.ver}</java.version>
  </properties>
</project>`

const pomNoVersion = `<project>
  <groupId>com.example</groupId><artifactId>bare</artifactId><version>1.0.0</version>
</project>`

func TestBuildManifest_MavenEmitBar(t *testing.T) {
	dir := writeTree(t, map[string]string{"pom.xml": pomManifest})
	res := buildManifest(t, dir, "java")

	if res.ProjectRoot != "com.example:app" {
		t.Errorf("ProjectRoot = %q, want com.example:app", res.ProjectRoot)
	}
	if res.Runtime.Name != "java" {
		t.Errorf("Runtime.Name = %q, want java", res.Runtime.Name)
	}
	if res.Runtime.Version != "17" { // release ⊐ source
		t.Errorf("Runtime.Version = %q, want 17", res.Runtime.Version)
	}
	if res.Resolver.Name != "maven" || res.Resolver.Command != "mvn -o -DskipTests package" {
		t.Errorf("Resolver = %+v, want maven / offline package", res.Resolver)
	}
	assertHonestResidue(t, res, true)
	if hasReason(res.Partiality, reasonNoRuntimeVersion) {
		t.Errorf("must not declare no_runtime_version when a version resolved: %v", res.Partiality.Reasons)
	}
}

func TestBuildManifest_MavenPropertyInterpolation(t *testing.T) {
	dir := writeTree(t, map[string]string{"pom.xml": pomJavaVersionProp})
	res := buildManifest(t, dir, "java")
	if res.Runtime.Version != "1.8" {
		t.Errorf("Runtime.Version = %q, want 1.8 (resolved ${java.ver})", res.Runtime.Version)
	}
}

func TestBuildManifest_MavenNoRuntimeVersion(t *testing.T) {
	dir := writeTree(t, map[string]string{"pom.xml": pomNoVersion})
	res := buildManifest(t, dir, "java")
	if res.Runtime.Version != "" {
		t.Errorf("Runtime.Version = %q, want empty (never guessed)", res.Runtime.Version)
	}
	if !hasReason(res.Partiality, reasonNoRuntimeVersion) {
		t.Errorf("missing no_runtime_version reason: %v", res.Partiality.Reasons)
	}
}

const gradleManifest = `plugins { id 'java' }
java {
    sourceCompatibility = JavaVersion.VERSION_17
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}
dependencies { implementation 'com.example:lib:1.0.0' }
`

const settingsGradle = `rootProject.name = 'my-service'
`

func TestBuildManifest_GradleEmitBar(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"build.gradle":    gradleManifest,
		"settings.gradle": settingsGradle,
	})
	res := buildManifest(t, dir, "java")

	if res.ProjectRoot != "my-service" {
		t.Errorf("ProjectRoot = %q, want my-service", res.ProjectRoot)
	}
	if res.Runtime.Version != "21" { // languageVersion floor wins over sourceCompatibility
		t.Errorf("Runtime.Version = %q, want 21", res.Runtime.Version)
	}
	if res.Resolver.Name != "gradle" || res.Resolver.Command != "gradle --offline assemble" {
		t.Errorf("Resolver = %+v, want gradle / offline assemble", res.Resolver)
	}
	assertHonestResidue(t, res, true)
}

func TestBuildManifest_GradleKotlinDSLJvmTarget(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"build.gradle.kts": "kotlin { }\ntasks.compileKotlin { kotlinOptions.jvmTarget = \"11\" }\n",
	})
	res := buildManifest(t, dir, "kotlin")
	if res.Runtime.Version != "11" {
		t.Errorf("Runtime.Version = %q, want 11 (jvmTarget)", res.Runtime.Version)
	}
}

func TestBuildManifest_ToolchainPinFromFile(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pom.xml":        pomManifest,
		".tool-versions": "java temurin-17.0.9\nnodejs 20.0.0\n",
	})
	res := buildManifest(t, dir, "java")
	if res.Runtime.Toolchain != "temurin-17.0.9" {
		t.Errorf("Runtime.Toolchain = %q, want temurin-17.0.9", res.Runtime.Toolchain)
	}
	assertHonestResidue(t, res, false) // an exact pin exists ⇒ no toolchain_unpinned reason
}

func TestBuildManifest_MultiModule(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pom.xml":       "<project><groupId>com.example</groupId><artifactId>parent</artifactId><version>1.0.0</version></project>",
		"mod-a/pom.xml": "<project><parent><groupId>com.example</groupId></parent><artifactId>a</artifactId></project>",
		"mod-b/pom.xml": "<project><parent><groupId>com.example</groupId></parent><artifactId>b</artifactId></project>",
	})
	res := buildManifest(t, dir, "java")
	if res.ProjectRoot != "com.example:parent" {
		t.Errorf("ProjectRoot = %q, want com.example:parent (root pom)", res.ProjectRoot)
	}
	if !hasReason(res.Partiality, reasonMultiModule) {
		t.Errorf("missing multi_module_project reason: %v", res.Partiality.Reasons)
	}
}

func TestBuildManifest_NoManifest(t *testing.T) {
	dir := writeTree(t, map[string]string{})
	res := buildManifest(t, dir, "java")
	if !hasReason(res.Partiality, plugin.PartialReasonNoManifest) {
		t.Errorf("missing no_manifest reason: %v", res.Partiality.Reasons)
	}
	if res.ProjectRoot != "." {
		t.Errorf("ProjectRoot = %q, want . fallback", res.ProjectRoot)
	}
}

func TestBuildManifest_MissingBuildDirIsHardError(t *testing.T) {
	_, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: "/nonexistent/path/xyz"}, "java")
	if err == nil {
		t.Fatal("missing build dir must be a hard error (inv.4)")
	}
}

// Delegation parity: kotlin == java for the same build tree (Runtime.Name aside).
func TestBuildManifest_KotlinDelegationParity(t *testing.T) {
	files := map[string]string{
		"build.gradle":    gradleManifest,
		"settings.gradle": settingsGradle,
	}
	javaDir := writeTree(t, cloneFiles(files))
	kotlinDir := writeTree(t, cloneFiles(files))

	jres := buildManifest(t, javaDir, "java")
	kres := buildManifest(t, kotlinDir, "kotlin")

	if jres.Runtime.Name != "java" || kres.Runtime.Name != "kotlin" {
		t.Fatalf("Runtime.Name should differ per lane: java=%q kotlin=%q", jres.Runtime.Name, kres.Runtime.Name)
	}
	// Everything except Runtime.Name must be identical.
	jres.Runtime.Name, kres.Runtime.Name = "", ""
	if !equalManifest(jres, kres) {
		t.Errorf("kotlin delegation must equal java (Runtime.Name aside):\n java   = %+v\n kotlin = %+v", jres, kres)
	}
}

func cloneFiles(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func equalManifest(a, b plugin.BuildManifestResult) bool {
	if a.Runtime != b.Runtime || a.Target != b.Target || a.Configuration != b.Configuration ||
		a.ProjectRoot != b.ProjectRoot || a.Resolver != b.Resolver ||
		a.Partiality.Complete != b.Partiality.Complete || len(a.Partiality.Reasons) != len(b.Partiality.Reasons) {
		return false
	}
	for i := range a.Partiality.Reasons {
		if a.Partiality.Reasons[i] != b.Partiality.Reasons[i] {
			return false
		}
	}
	return true
}
