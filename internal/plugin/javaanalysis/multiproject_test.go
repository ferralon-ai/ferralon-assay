package javaanalysis

import (
	"os"
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
		// The settings reader is an allow-list: rootProject.name and include over in-tree string
		// literals, nothing else.
		{"settings moves a project out of the tree", map[string]string{"settings.gradle": "include 'app'\nproject(':app').projectDir = file('../elsewhere/app')\n", "build.gradle": ""}, true},
		{"settings.kts moves a project out of the tree", map[string]string{"settings.gradle.kts": "rootProject.name = \"x\"\ninclude(\"app\")\nproject(\":app\").projectDir = file(\"../elsewhere/app\")\n", "build.gradle.kts": ""}, true},
		{"settings plugins block", map[string]string{"settings.gradle": "plugins {\n  id 'com.example.autoinc' version '1.0'\n}\n", "build.gradle": "", "src/main/java/A.java": ""}, true},
		{"settings dependencyResolutionManagement block", map[string]string{"settings.gradle": "dependencyResolutionManagement {\n  repositories { mavenCentral() }\n}\nrootProject.name = 'x'\n", "build.gradle": "", "src/main/java/A.java": ""}, true},
		{"settings includeFlat", map[string]string{"settings.gradle": "includeFlat 'lib'\n", "build.gradle": ""}, true},
		{"settings includes a path out of the tree", map[string]string{"settings.gradle": "include '../outside'\n", "build.gradle": ""}, true},
		{"settings chains a call on the name", map[string]string{"settings.gradle": "rootProject.name = 'x'.with { include 'a', 'b' }\n", "build.gradle": "", "src/main/java/A.java": ""}, true},
		{"settings hides statements in an unterminated comment", map[string]string{"settings.gradle": "rootProject.name = 'x'\n/*\nproject(':app').projectDir = file('../e')\n", "build.gradle": "", "src/main/java/A.java": ""}, true},
		{"settings triple-quoted string", map[string]string{"settings.gradle": "rootProject.name = 'x'\ndef s = '''\ninclude 'a'\n'''\n", "build.gradle": "", "src/main/java/A.java": ""}, true},
		{"settings slashy string", map[string]string{"settings.gradle": "rootProject.name = 'x'\ndef p = /a\\/*/\n", "build.gradle": "", "src/main/java/A.java": ""}, true},
		{"settings name and include share a line unseparated", map[string]string{"settings.gradle": "rootProject.name = 'x' include 'app'\n", "app/build.gradle": "", "app/src/main/java/A.java": ""}, true},
		{"settings include and name share a line unseparated", map[string]string{"settings.gradle": "include 'app' rootProject.name = 'x'\n", "app/build.gradle": "", "app/src/main/java/A.java": ""}, true},
		{"settings name and one include stay single", map[string]string{"settings.gradle": "rootProject.name = 'x'\ninclude 'app'\n", "app/build.gradle": "", "app/src/main/java/A.java": ""}, false},
		{"settings include before the name stays single", map[string]string{"settings.gradle": "include 'app'\nrootProject.name='x'\n", "app/build.gradle": "", "app/src/main/java/A.java": ""}, false},
		{"settings statements on one line stay single", map[string]string{"settings.gradle.kts": "rootProject.name = \"x\"; include(\":app\")\n", "app/build.gradle.kts": "", "app/src/main/java/A.java": ""}, false},
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

// The walk never follows a symlink. An in-root symlinked directory is read when the walk enters
// its target at its real path; a link that leaves the build, does not resolve, or points into a
// directory the walk skips cannot be vouched for, and neither can a directory it cannot read, so
// each of those counts as a possible second project.
func TestMultipleProjects_SymlinksAndUnreadable(t *testing.T) {
	single := map[string]string{"pom.xml": "<project><artifactId>a</artifactId></project>", "shared/A.java": "class A {}"}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		multi bool
	}{
		{"in-root symlinked directory is read", func(t *testing.T, dir string) {
			mustSymlink(t, "shared", filepath.Join(dir, "alias"))
		}, false},
		{"link back to the root terminates and is read", func(t *testing.T, dir string) {
			mustSymlink(t, "..", filepath.Join(dir, "shared", "loop"))
		}, false},
		{"link cycle does not resolve", func(t *testing.T, dir string) {
			mustSymlink(t, "y", filepath.Join(dir, "x"))
			mustSymlink(t, "x", filepath.Join(dir, "y"))
		}, true},
		{"symlinked directory leaving the build", func(t *testing.T, dir string) {
			outside := t.TempDir()
			writeFile(t, filepath.Join(outside, "pom.xml"), "<project><artifactId>b</artifactId></project>")
			mustSymlink(t, outside, filepath.Join(dir, "ext"))
		}, true},
		{"file link leaving the build, like a venv interpreter", func(t *testing.T, dir string) {
			outside := filepath.Join(t.TempDir(), "python3")
			writeFile(t, outside, "")
			mustSymlink(t, outside, filepath.Join(dir, ".venv", "bin", "python"))
		}, true},
		{"dangling link", func(t *testing.T, dir string) {
			mustSymlink(t, "gone", filepath.Join(dir, "lib"))
		}, true},
		{"symlinked directory into a skipped tree", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "node_modules", "x", "pom.xml"), "<project><artifactId>x</artifactId></project>")
			mustSymlink(t, filepath.Join("node_modules", "x"), filepath.Join(dir, "x"))
		}, true},
		{"symlinked directory onto a skipped directory", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "node_modules", "x", "pom.xml"), "<project><artifactId>x</artifactId></project>")
			mustSymlink(t, "node_modules", filepath.Join(dir, "deps"))
		}, true},
		{"unreadable directory", func(t *testing.T, dir string) {
			locked := filepath.Join(dir, "locked")
			writeFile(t, filepath.Join(locked, "pom.xml"), "<project><artifactId>b</artifactId></project>")
			if err := os.Chmod(locked, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
		}, true},
		{"unreadable root POM", func(t *testing.T, dir string) {
			pom := filepath.Join(dir, "pom.xml")
			if err := os.Chmod(pom, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(pom, 0o644) })
		}, true},
		{"root POM that does not parse", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "pom.xml"), "<project><modules><module>b</module>")
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for p, b := range single {
				writeFile(t, filepath.Join(dir, p), b)
			}
			tc.setup(t, dir)
			if got, why := multipleProjects(dir); got != tc.multi {
				t.Errorf("multipleProjects = %v (%s), want %v", got, why, tc.multi)
			}
		})
	}
	t.Run("build directory whose real path cannot be resolved", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root searches a mode-0 directory")
		}
		parent := t.TempDir()
		dir := filepath.Join(parent, "b")
		writeFile(t, filepath.Join(dir, "pom.xml"), single["pom.xml"])
		if err := os.Chmod(parent, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
		if got, why := multipleProjects(dir); !got {
			t.Errorf("multipleProjects = false (%s), want true", why)
		}
	})
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
