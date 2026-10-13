package javaanalysis

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// A Maven reactor with two modules is outside what this release analyses: the advisory's
// symbols still resolve from the JAR, but the result is partial run-wide with
// multiple_projects_unsupported, which the gate reads as did-not-run.
func TestResolveDependencySymbols_TwoModulesAreUnsupported(t *testing.T) {
	build := buildNetkitFixture(t, false)
	writeNetkitOwnPom(t, build)
	writeFile(t, filepath.Join(build, "pom.xml"), `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0.0</version><packaging>pom</packaging>
  <modules><module>app</module><module>lib</module></modules>
</project>`)
	writeFile(t, filepath.Join(build, "app", "pom.xml"), netkitPom)
	writeFile(t, filepath.Join(build, "lib", "pom.xml"), `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId><artifactId>lib</artifactId><version>1.0.0</version>
</project>`)

	res := resolveNetkit(t, build, "com.evil.netkit.UrlFetcher.fetch")
	if res.Partiality.Complete || !slices.Contains(res.Partiality.Reasons, reasonMultipleProjectsUnsupported) {
		t.Fatalf("want run-wide %s, got %+v", reasonMultipleProjectsUnsupported, res.Partiality)
	}
	if got := report.ClassifyPartialityReason(reasonMultipleProjectsUnsupported); got != report.PartialityDidNotRun {
		t.Errorf("%s classifies as %v, want did_not_run", reasonMultipleProjectsUnsupported, got)
	}
}

func TestMultipleProjects(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		multi bool
	}{
		{"single pom", map[string]string{"pom.xml": "<project><artifactId>a</artifactId></project>"}, false},
		{"pom with modules", map[string]string{"pom.xml": "<project><artifactId>p</artifactId><modules><module>a</module></modules></project>"}, true},
		{"two poms", map[string]string{"pom.xml": "<project><artifactId>a</artifactId></project>", "tools/pom.xml": "<project><artifactId>b</artifactId></project>"}, true},
		{"pom in a cache dir", map[string]string{"pom.xml": "<project><artifactId>a</artifactId></project>", ".m2/repository/x/pom.xml": "<project><artifactId>x</artifactId></project>"}, false},
		{"single gradle project", map[string]string{"build.gradle": "", "src/main/java/A.java": "class A {}"}, false},
		{"gradle subprojects with code", map[string]string{"settings.gradle": "include 'a', 'b'", "a/build.gradle": "", "a/src/main/java/A.java": "", "b/build.gradle.kts": "", "b/src/main/java/B.java": ""}, true},
		{"gradle root without code plus one subproject", map[string]string{"build.gradle": "", "a/build.gradle": "", "a/src/main/java/A.java": ""}, false},
		// Maven modules in a profile join the reactor whenever the profile is active.
		{"pom with modules in a profile", map[string]string{"pom.xml": "<project><artifactId>p</artifactId><profiles><profile><id>all</id><modules><module>a</module></modules></profile></profiles></project>"}, true},
		// No directory hides a project: bin/, build/ and dot-dirs are walked.
		{"second pom under bin", map[string]string{"pom.xml": "<project><artifactId>a</artifactId></project>", "bin/pom.xml": "<project><artifactId>b</artifactId></project>"}, true},
		{"gradle subproject under bin", map[string]string{"build.gradle": "", "src/main/java/A.java": "", "bin/build.gradle": "", "bin/src/main/java/B.java": ""}, true},
		{"gradle subproject under a dot-dir", map[string]string{"build.gradle": "", "src/main/java/A.java": "", ".tools/build.gradle.kts": "", ".tools/src/main/java/B.java": ""}, true},
		{"gradle subproject in node_modules is not the build's", map[string]string{"build.gradle": "", "src/main/java/A.java": "", "node_modules/x/build.gradle": "", "node_modules/x/src/A.java": ""}, false},
		// settings.gradle is read: a subproject configured from the root has no build script.
		{"settings include, configured from the root", map[string]string{"settings.gradle": "include 'api'\n", "build.gradle": "subprojects { apply plugin: 'java' }\n", "src/main/java/A.java": "", "api/src/main/java/B.java": ""}, true},
		{"settings includes two projects", map[string]string{"settings.gradle.kts": "rootProject.name = \"x\"\ninclude(\n  \":api\",\n  \":core\",\n)\n", "build.gradle.kts": ""}, true},
		{"settings includes one project, root has no code", map[string]string{"settings.gradle.kts": "rootProject.name = \"x\"\ninclude(\"app\")\n", "app/build.gradle.kts": "", "app/src/main/java/A.java": ""}, false},
		{"settings include in a comment", map[string]string{"settings.gradle": "// include 'api'\n/* include 'core' */\nrootProject.name = 'x'\n", "build.gradle": "", "src/main/java/A.java": ""}, false},
		{"settings includes a build", map[string]string{"settings.gradle": "includeBuild('../lib')\n", "build.gradle": ""}, true},
		{"settings includes in a loop", map[string]string{"settings.gradle": "file('modules').eachDir { include it.name }\n", "build.gradle": "", "src/main/java/A.java": ""}, true},
		{"settings includes an interpolated name", map[string]string{"settings.gradle": "def n = 'api'\ninclude \"${n}\"\n", "build.gradle": ""}, true},
		{"settings applies another script", map[string]string{"settings.gradle": "apply from: 'more.gradle'\n", "build.gradle": "", "src/main/java/A.java": ""}, true},
		{"settings below the root", map[string]string{"build.gradle": "", "src/main/java/A.java": "", "tools/settings.gradle": "", "tools/build.gradle": ""}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for p, b := range tc.files {
				writeFile(t, filepath.Join(dir, p), b)
			}
			if got, why := multipleProjects(dir); got != tc.multi {
				t.Errorf("multipleProjects = %v (%s), want %v", got, why, tc.multi)
			}
		})
	}
}
