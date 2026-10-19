package javaanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// gradleWidgetLock has entries for every resolvable configuration an implementation
// declaration feeds, and empty= for the annotation processor paths, as Gradle writes it.
const (
	gradleLockingOn     = "dependencyLocking {\n    lockAllConfigurations()\n}\n"
	gradleLockingStrict = "dependencyLocking {\n    lockAllConfigurations()\n    lockMode = LockMode.STRICT\n}\n"
	gradleWidgetDecl    = "dependencies {\n    implementation 'com.example.lib:widget:2.0'\n}\n"
	gradleWidgetLock    = "com.example.lib:widget:2.5=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath\nempty=annotationProcessor,testAnnotationProcessor\n"
)

func TestGradleLockedVersions(t *testing.T) {
	for _, tt := range []struct {
		name     string
		files    map[string]string
		versions []string
		complete bool
	}{
		{"enforced, every fed configuration pinned", map[string]string{
			"build.gradle": gradleLockingOn + gradleWidgetDecl, "gradle.lockfile": gradleWidgetLock,
		}, []string{"2.5"}, true},
		{"no lock", map[string]string{"build.gradle": gradleLockingOn + gradleWidgetDecl}, nil, false},
		{"STRICT, no lock at all", map[string]string{"build.gradle": gradleLockingStrict + gradleWidgetDecl}, nil, false},
		{"no locking statement", map[string]string{
			"build.gradle": gradleWidgetDecl, "gradle.lockfile": gradleWidgetLock,
		}, []string{"2.5"}, false},
		{"a statement outside the SAFE set", map[string]string{
			"build.gradle": gradleLockingOn + gradleWidgetDecl + "apply from: 'pins.gradle'\n", "gradle.lockfile": gradleWidgetLock,
		}, []string{"2.5"}, false},
		{"default mode, testRuntimeClasspath without entries", map[string]string{
			"build.gradle":    gradleLockingOn + gradleWidgetDecl,
			"gradle.lockfile": "com.example.lib:widget:2.5=compileClasspath,runtimeClasspath,testCompileClasspath\nempty=annotationProcessor,testAnnotationProcessor,testRuntimeClasspath\n",
		}, []string{"2.5"}, false},
		{"STRICT, testRuntimeClasspath with no lock state", map[string]string{
			"build.gradle":    gradleLockingStrict + gradleWidgetDecl,
			"gradle.lockfile": "com.example.lib:widget:2.5=compileClasspath,runtimeClasspath,testCompileClasspath\n",
		}, []string{"2.5"}, true},
		{"STRICT, empty= names testRuntimeClasspath", map[string]string{
			"build.gradle":    gradleLockingStrict + gradleWidgetDecl,
			"gradle.lockfile": "com.example.lib:widget:2.5=compileClasspath,runtimeClasspath,testCompileClasspath\nempty=testRuntimeClasspath\n",
		}, []string{"2.5"}, false},
		{"default mode, annotationProcessor fed and empty", map[string]string{
			"build.gradle":    gradleLockingOn + gradleWidgetDecl + "dependencies {\n    annotationProcessor 'com.example:proc:1.0'\n}\n",
			"gradle.lockfile": gradleWidgetLock,
		}, []string{"2.5"}, false},
		{"a lock line that is not a coordinate", map[string]string{
			"build.gradle": gradleLockingOn + gradleWidgetDecl, "gradle.lockfile": gradleWidgetLock + "com.example.lib:widget\n",
		}, []string{"2.5"}, false},
		{"two versions across configurations", map[string]string{
			"build.gradle":    gradleLockingOn + gradleWidgetDecl,
			"gradle.lockfile": "com.example.lib:widget:2.0=compileClasspath,testCompileClasspath\ncom.example.lib:widget:2.5=runtimeClasspath,testRuntimeClasspath\n",
		}, []string{"2.0", "2.5"}, true},
		{"declared, absent from every pinned lock", map[string]string{
			"build.gradle":    gradleLockingOn + gradleWidgetDecl,
			"gradle.lockfile": "com.example:other:1.0=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath\n",
		}, nil, true},
		{"a subproject declaring with no lock", map[string]string{
			"settings.gradle": "include 'app'\n",
			"build.gradle":    gradleLockingOn, "gradle.lockfile": "empty=\n",
			"app/build.gradle": gradleLockingOn + gradleWidgetDecl,
		}, nil, false},
		{"every project pinned, the version in a subproject", map[string]string{
			"settings.gradle":  "include 'app'\n",
			"build.gradle":     gradleLockingOn,
			"app/build.gradle": gradleLockingOn + gradleWidgetDecl, "app/gradle.lockfile": gradleWidgetLock,
		}, []string{"2.5"}, true},
		{"a root block declaring for a subproject that pins nothing", map[string]string{
			"settings.gradle":  "include 'app'\n",
			"build.gradle":     gradleLockingOn + "subprojects {\n    dependencies {\n        runtimeOnly 'com.example:extra:1.0'\n    }\n}\n",
			"gradle.lockfile":  "com.example:extra:1.0=runtimeClasspath,testRuntimeClasspath\n",
			"app/build.gradle": gradleLockingOn, "app/gradle.lockfile": "empty=\n",
		}, nil, false},
		{"a root that declares and locks nothing", map[string]string{
			"settings.gradle":  "include 'app'\n",
			"build.gradle":     "group = 'com.example'\n",
			"app/build.gradle": gradleLockingOn + gradleWidgetDecl, "app/gradle.lockfile": gradleWidgetLock,
		}, []string{"2.5"}, true},
		{"compileOnly and runtimeOnly need only the classpaths they feed", map[string]string{
			"build.gradle":    gradleLockingOn + "dependencies {\n    compileOnly 'com.example.lib:widget:2.0'\n    runtimeOnly 'com.example:other:1.0'\n}\n",
			"gradle.lockfile": "com.example.lib:widget:2.5=compileClasspath\ncom.example:other:1.0=runtimeClasspath,testRuntimeClasspath\nempty=annotationProcessor,testAnnotationProcessor,testCompileClasspath\n",
		}, []string{"2.5"}, true},
		{"an intermediate project of a nested include, unread", map[string]string{
			"settings.gradle":       "include 'libs:app'\n",
			"build.gradle":          gradleLockingOn,
			"libs/app/build.gradle": gradleLockingOn + gradleWidgetDecl, "libs/app/gradle.lockfile": gradleWidgetLock,
		}, []string{"2.5"}, false},
		{"a root block feeding a subproject's unpinned testRuntimeClasspath", map[string]string{
			"settings.gradle":     "include 'app'\n",
			"build.gradle":        gradleLockingOn + "subprojects {\n    dependencies {\n        runtimeOnly 'com.example:extra:1.0'\n    }\n}\n",
			"gradle.lockfile":     "com.example:extra:1.0=runtimeClasspath,testRuntimeClasspath\n",
			"app/build.gradle":    gradleLockingOn + "dependencies {\n    compileOnly 'com.example.lib:widget:2.5'\n}\n",
			"app/gradle.lockfile": "com.example.lib:widget:2.5=compileClasspath\ncom.example:extra:1.0=runtimeClasspath\nempty=annotationProcessor,testAnnotationProcessor,testCompileClasspath\n",
		}, []string{"2.5"}, false},
		{"entries beside a legacy lock directory", map[string]string{
			"build.gradle": gradleLockingOn + gradleWidgetDecl, "gradle.lockfile": gradleWidgetLock,
			"gradle/dependency-locks/runtimeClasspath.lockfile": "# a comment, so no line goes unparsed\n",
		}, []string{"2.5"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, tt.files)
			deps, complete, why := gradleLockedVersions(dir, "com.example.lib:widget")
			var got []string
			for _, d := range deps {
				if !d.Resolved || d.Coordinate != "com.example.lib:widget" {
					t.Errorf("dep %+v, want a resolved com.example.lib:widget", d)
				}
				got = append(got, d.Version)
			}
			if !reflect.DeepEqual(got, tt.versions) {
				t.Errorf("versions = %v, want %v", got, tt.versions)
			}
			if complete != tt.complete {
				t.Errorf("complete = %v (%s), want %v", complete, why, tt.complete)
			}
			if !complete && why == "" {
				t.Error("incomplete with no reason")
			}
		})
	}
}

// F2: Gradle selects the highest version requested anywhere in the graph, so a declared version
// is Resolved only where the build's enforced locks bind it.
func TestResolveVersions_GradleResolvedOnlyFromAnEnforcedLock(t *testing.T) {
	const pom = `<project><dependencies><dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>2.0</version></dependency></dependencies></project>`
	for _, tt := range []struct {
		name       string
		files      map[string]string
		resolved   bool
		version    string
		constraint string
	}{
		{"declared 2.0, no lock (a transitive may ask for 2.5)", map[string]string{
			"build.gradle": gradleWidgetDecl,
		}, false, "", "2.0"},
		{"locked and enforced", map[string]string{
			"build.gradle": gradleLockingOn + gradleWidgetDecl, "gradle.lockfile": gradleWidgetLock,
		}, true, "2.5", ""},
		{"locked and enforced, kts", map[string]string{
			"build.gradle.kts": gradleLockingOn + "dependencies {\n    implementation(\"com.example.lib:widget:2.0\")\n}\n", "gradle.lockfile": gradleWidgetLock,
		}, true, "2.5", ""},
		{"locked, the build not SAFE", map[string]string{
			"build.gradle": gradleLockingOn + gradleWidgetDecl + "apply from: 'pins.gradle'\n", "gradle.lockfile": gradleWidgetLock,
		}, false, "", "2.0"},
		{"locked, a fed configuration with no entries in default mode", map[string]string{
			"build.gradle":    gradleLockingOn + gradleWidgetDecl,
			"gradle.lockfile": "com.example.lib:widget:2.5=compileClasspath,runtimeClasspath,testCompileClasspath\n",
		}, false, "", "2.0"},
		{"locked at two versions", map[string]string{
			"build.gradle":    gradleLockingOn + gradleWidgetDecl,
			"gradle.lockfile": "com.example.lib:widget:2.0=compileClasspath,testCompileClasspath\ncom.example.lib:widget:2.5=runtimeClasspath,testRuntimeClasspath\n",
		}, false, "", "2.0"},
		{"STRICT, a subproject in out/ locking its own version", map[string]string{
			"settings.gradle":     "include 'app', 'out'\n",
			"build.gradle":        gradleLockingStrict,
			"app/build.gradle":    gradleLockingStrict + gradleWidgetDecl,
			"app/gradle.lockfile": gradleWidgetLock,
			"out/build.gradle":    gradleLockingStrict + "dependencies {\n    implementation 'com.example.lib:widget:3.0'\n}\n",
			"out/gradle.lockfile": "com.example.lib:widget:3.0=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath\nempty=annotationProcessor,testAnnotationProcessor\n",
		}, false, "", "2.0"},
		{"versionless, locked and enforced", map[string]string{
			"build.gradle": gradleLockingOn + "dependencies {\n    implementation 'com.example.lib:widget'\n}\n", "gradle.lockfile": gradleWidgetLock,
		}, true, "2.5", ""},
		{"control, Maven unchanged", map[string]string{"pom.xml": pom}, true, "2.0", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := resolve(t, writeTree(t, tt.files), "com.example.lib:widget")
			if !res.Found {
				t.Fatalf("Found = false, want true: %+v", res)
			}
			m := res.Match
			if m.Resolved != tt.resolved || m.Version != tt.version || m.Constraint != tt.constraint {
				t.Errorf("Match = %+v, want resolved=%v version=%q constraint=%q", m, tt.resolved, tt.version, tt.constraint)
			}
			for _, d := range res.All {
				if d.Coordinate == "com.example.lib:widget" && d.Resolved != tt.resolved {
					t.Errorf("All carries %+v, want resolved=%v", d, tt.resolved)
				}
			}
		})
	}
}

func gradleWidgetAt(v string) (decl, lock string) {
	return "dependencies {\n    implementation 'com.example.lib:widget:" + v + "'\n}\n",
		"com.example.lib:widget:" + v + "=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath\nempty=annotationProcessor,testAnnotationProcessor\n"
}

// A STRICT project whose lock the walk never reads (a directory it skips, the target of a
// symlinked project directory, one it can't list) gets no lock state, which gradleConfigPinned
// counts as pinned. Gradle reads that lock by path and binds lib's version there, so the
// binding is incomplete.
func TestGradleLockedVersions_ProjectLockUnread(t *testing.T) {
	appDecl, appLock := gradleWidgetAt("2.5")
	libDecl, libLock := gradleWidgetAt("3.0")
	tree := func(lib string) map[string]string {
		return map[string]string{
			"settings.gradle":        "include 'app', 'lib'\n",
			"build.gradle":           gradleLockingStrict,
			"app/build.gradle":       gradleLockingStrict + appDecl,
			"app/gradle.lockfile":    appLock,
			lib + "/build.gradle":    gradleLockingStrict + libDecl,
			lib + "/gradle.lockfile": libLock,
		}
	}
	for _, tt := range []struct {
		name     string
		files    map[string]string
		setup    func(t *testing.T, dir string)
		versions []string
		complete bool
	}{
		{name: "control, lib read", files: tree("lib"), versions: []string{"2.5", "3.0"}, complete: true},
		{name: "lib in out/ depending only on app", files: map[string]string{
			"settings.gradle":     "include 'app', 'out'\n",
			"build.gradle":        gradleLockingStrict,
			"app/build.gradle":    gradleLockingStrict + appDecl,
			"app/gradle.lockfile": appLock,
			"out/build.gradle":    gradleLockingStrict + "dependencies {\n    implementation project(':app')\n}\n",
			"out/gradle.lockfile": libLock,
		}, versions: []string{"2.5"}},
		{name: "STRICT, a project whose lock pins only empty configurations", files: map[string]string{
			"build.gradle":    gradleLockingStrict + appDecl,
			"gradle.lockfile": "empty=annotationProcessor,testAnnotationProcessor\n",
		}},
		{name: "STRICT lib with no lock", files: func() map[string]string {
			m := tree("lib")
			delete(m, "lib/gradle.lockfile")
			return m
		}(), versions: []string{"2.5"}},
		{name: "lib behind a symlinked project directory", files: tree("shared/lib"), setup: func(t *testing.T, dir string) {
			if err := os.Symlink(filepath.Join(dir, "shared", "lib"), filepath.Join(dir, "lib")); err != nil {
				t.Fatal(err)
			}
		}, versions: []string{"2.5"}},
		{name: "lib the walk can't list", files: tree("lib"), setup: func(t *testing.T, dir string) {
			if os.Geteuid() == 0 {
				t.Skip("root lists any directory")
			}
			lib := filepath.Join(dir, "lib")
			if err := os.Chmod(lib, 0o111); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(lib, 0o755) })
		}, versions: []string{"2.5"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, tt.files)
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			checkWidgetLock(t, dir, tt.versions, tt.complete)
		})
	}
	for _, name := range []string{"out", "bin", "build", "target", ".x"} {
		t.Run("lib in a directory named "+name, func(t *testing.T) {
			files := tree(name)
			files["settings.gradle"] = "include 'app', '" + name + "'\n"
			checkWidgetLock(t, writeTree(t, files), []string{"2.5"}, false)
		})
	}
}

func checkWidgetLock(t *testing.T, dir string, versions []string, complete bool) {
	t.Helper()
	deps, gotComplete, why := gradleLockedVersions(dir, "com.example.lib:widget")
	var got []string
	for _, d := range deps {
		got = append(got, d.Version)
	}
	if !reflect.DeepEqual(got, versions) {
		t.Errorf("versions = %v, want %v", got, versions)
	}
	if gotComplete != complete {
		t.Errorf("complete = %v (%s), want %v", gotComplete, why, complete)
	}
	if !gotComplete && why == "" {
		t.Error("incomplete with no reason")
	}
}

// gradleProjectsPinned fails on a project script it can't read by itself. Through
// gradleLockedVersions, gradleBuildSafe has read the same scripts first, so only a direct call
// shows the check.
func TestGradleProjectsPinned_UnreadScript(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0 file")
	}
	dir := writeTree(t, map[string]string{
		"settings.gradle":     "include 'app'\n",
		"build.gradle":        gradleLockingOn,
		"app/build.gradle":    gradleLockingOn + gradleWidgetDecl,
		"app/gradle.lockfile": gradleWidgetLock,
	})
	projects, ok := gradleProjects(dir)
	if !ok {
		t.Fatal("gradleProjects not ok")
	}
	rootSrcs, ok := readGradleSources(gradleScriptsIn(dir))
	if !ok {
		t.Fatal("root script unread")
	}
	_, _, _, _, state := readLockfiles(dir)
	if why, ok := gradleProjectsPinned(dir, projects, rootSrcs, state); !ok {
		t.Fatalf("control: not pinned (%s)", why)
	}
	if err := os.Chmod(filepath.Join(dir, "app", "build.gradle"), 0); err != nil {
		t.Fatal(err)
	}
	if why, ok := gradleProjectsPinned(dir, projects, rootSrcs, state); ok || why == "" {
		t.Errorf("an unreadable app script: ok=%v why=%q, want not pinned with a reason", ok, why)
	}
}

// The locks speak only for the projects the root settings script creates. A Gradle script
// anywhere else, a nested build with its own settings or a directory no settings include,
// leaves them unbound, so no copy resolves and the Match can't name the root's version while
// the other build ships its own.
func TestResolveVersions_GradleBindsOnlyTheProjectSet(t *testing.T) {
	type entry struct {
		resolved            bool
		version, constraint string
	}
	outsideDecl, _ := gradleWidgetAt("3.0")
	root := map[string]string{"build.gradle": gradleLockingOn + gradleWidgetDecl, "gradle.lockfile": gradleWidgetLock}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range root {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	for _, tt := range []struct {
		name  string
		files map[string]string
		want  []entry
	}{
		{"a nested build with its own settings", with(map[string]string{
			"services/legacy/settings.gradle": "rootProject.name = 'legacy'\n",
			"services/legacy/build.gradle":    outsideDecl,
		}), []entry{{false, "", "2.0"}, {false, "", "3.0"}}},
		{"a directory no settings include", with(map[string]string{
			"examples/build.gradle": outsideDecl,
		}), []entry{{false, "", "2.0"}, {false, "", "3.0"}}},
		{"control, an included subproject", with(map[string]string{
			"settings.gradle":     "include 'app'\n",
			"app/build.gradle":    gradleLockingOn + gradleWidgetDecl,
			"app/gradle.lockfile": gradleWidgetLock,
		}), []entry{{true, "2.5", ""}, {true, "2.5", ""}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := resolve(t, writeTree(t, tt.files), "com.example.lib:widget")
			if !res.Found {
				t.Fatalf("Found = false, want true: %+v", res)
			}
			var got []entry
			for _, d := range res.All {
				if d.Coordinate == "com.example.lib:widget" {
					got = append(got, entry{d.Resolved, d.Version, d.Constraint})
				}
			}
			sort.Slice(got, func(i, j int) bool { return got[i].constraint < got[j].constraint })
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("All widget entries = %+v, want %+v", got, tt.want)
			}
			if res.Match.Resolved != tt.want[0].resolved {
				t.Errorf("Match = %+v, want resolved %v", res.Match, tt.want[0].resolved)
			}
		})
	}
}

// Gradle opens each project's lock by path. A project directory the walk can't list, skips,
// or reaches only through a symlink leaves its lock state unknown, and a Gradle script the
// locks don't speak for leaves them unbound; a project directory that genuinely isn't there
// holds no lock, so it fails on its own grounds and not as an unread lock. Each row names
// the reason it expects, so a guard that only moves the outcome to a later check still shows.
func TestGradleLockBinding_EnumerationUncertainty(t *testing.T) {
	appDecl, appLock := gradleWidgetAt("2.5")
	libDecl, libLock := gradleWidgetAt("3.0")
	tree := func(include string, extra map[string]string) map[string]string {
		m := map[string]string{
			"settings.gradle":     "include " + include + "\n",
			"build.gradle":        gradleLockingStrict,
			"app/build.gradle":    gradleLockingStrict + appDecl,
			"app/gradle.lockfile": appLock,
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	lib := func(dir string) map[string]string {
		return map[string]string{dir + "/build.gradle": gradleLockingStrict + libDecl, dir + "/gradle.lockfile": libLock}
	}
	chmod := func(rel string, mode os.FileMode) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			if os.Geteuid() == 0 {
				t.Skip("root lists and traverses any directory")
			}
			p := filepath.Join(dir, rel)
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
			if _, err := os.ReadDir(p); err == nil {
				t.Fatalf("%s is still listable at %v", rel, mode)
			}
		}
	}
	for _, tt := range []struct {
		name     string
		files    map[string]string
		setup    func(t *testing.T, dir string)
		versions []string
		why      string // empty: complete
	}{
		{name: "control, every project listed", files: tree("'app', 'lib'", lib("lib")), versions: []string{"2.5", "3.0"}},
		{name: "permission denial, the project walked after app", files: tree("'app', 'lib'", lib("lib")),
			setup: chmod("lib", 0o111), versions: []string{"2.5"}, why: "lib/gradle.lockfile can't be read"},
		{name: "permission denial, the project walked before app", files: tree("'aaa', 'app'", lib("aaa")),
			setup: chmod("aaa", 0o111), versions: []string{"2.5"}, why: "aaa/gradle.lockfile can't be read"},
		{name: "an intermediate project that can't be traversed", files: tree("'app', 'a:b'", lib("a/b")),
			setup: chmod("a", 0), versions: []string{"2.5"}, why: "a/b/gradle.lockfile can't be read"},
		{name: "a project in a directory the walk skips", files: tree("'app', 'build'", lib("build")),
			versions: []string{"2.5"}, why: "build/gradle.lockfile can't be read"},
		{name: "a symlinked project directory", files: tree("'app', 'lib'", lib("shared/lib")), setup: func(t *testing.T, dir string) {
			if err := os.Symlink(filepath.Join(dir, "shared", "lib"), filepath.Join(dir, "lib")); err != nil {
				t.Fatal(err)
			}
		}, versions: []string{"2.5"}, why: "lib/gradle.lockfile can't be read"},
		// Genuine absence is no unread lock: the build fails the SAFE check for the missing
		// project's script instead, before the lock state is ever asked about.
		{name: "a missing project directory", files: tree("'app', 'gone'", nil), versions: []string{"2.5"},
			why: "gone is a project with no build script to read"},
		{name: "a project path through a regular file", files: tree("'app', 'f:lib'", map[string]string{"f": "not a directory\n"}),
			versions: []string{"2.5"}, why: "f is a project with no build script to read"},
		{name: "a stale lock where a removed project was", files: tree("'app'", map[string]string{"removed/gradle.lockfile": libLock}),
			versions: []string{"2.5"}},
		{name: "conflicting locks, root and subproject", files: func() map[string]string {
			m := tree("'app'", nil)
			m["build.gradle"] = gradleLockingStrict + libDecl
			m["gradle.lockfile"] = libLock
			return m
		}(), versions: []string{"2.5", "3.0"}},
		{name: "legacy lock state that can't be ruled out", files: tree("'app', 'lib'", lib("lib")), setup: func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "lib", "gradle"), 0o755); err != nil {
				t.Fatal(err)
			}
			chmod("lib/gradle", 0)(t, dir)
		}, versions: []string{"2.5", "3.0"}, why: "lib's runtimeClasspath is not pinned"},
		{name: "STRICT project with no lock, depending only on app", files: tree("'app', 'lib'", map[string]string{
			"lib/build.gradle": gradleLockingStrict + "dependencies {\n    implementation project(':app')\n}\n",
		}), versions: []string{"2.5"}, why: "lib is STRICT and no lock was read for it"},
		{name: "a nested independent build", files: tree("'app'", map[string]string{
			"services/legacy/settings.gradle": "rootProject.name = 'legacy'\n",
			"services/legacy/build.gradle":    libDecl,
		}), versions: []string{"2.5"}, why: "services/legacy/build.gradle is a build script outside"},
		{name: "a nested independent build walked before the projects", files: tree("'app'", map[string]string{
			"aaa/settings.gradle": "rootProject.name = 'legacy'\n",
			"aaa/build.gradle":    libDecl,
		}), versions: []string{"2.5"}, why: "aaa/build.gradle is a build script outside"},
		{name: "an unincluded directory the walk can't list", files: tree("'app'", map[string]string{"docs/README": "x\n"}),
			setup: chmod("docs", 0), versions: []string{"2.5"}, why: "docs can't be listed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, tt.files)
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			deps, complete, why := gradleLockedVersions(dir, "com.example.lib:widget")
			var got []string
			for _, d := range deps {
				got = append(got, d.Version)
			}
			if !reflect.DeepEqual(got, tt.versions) {
				t.Errorf("versions = %v, want %v", got, tt.versions)
			}
			if complete != (tt.why == "") || !strings.Contains(why, tt.why) {
				t.Errorf("complete = %v, why = %q; want complete %v, why containing %q", complete, why, tt.why == "", tt.why)
			}
			if !complete {
				if res := resolve(t, dir, "com.example.lib:widget"); res.Match.Resolved {
					t.Errorf("Match = %+v resolved while the locks don't bind", res.Match)
				}
			}
		})
	}
}

// The public resolver withholds when a readable subproject lock sits in a directory that can't
// be listed, the root's lock holding another version.
func TestResolveVersions_UnlistableSubprojectLockWithholds(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	decl := "dependencies {\n    implementation 'com.example.lib:widget'\n}\n"
	dir := writeTree(t, map[string]string{
		"settings.gradle":     "include 'app'\n",
		"build.gradle":        gradleLockingStrict + decl,
		"gradle.lockfile":     gradleWidgetLock,
		"app/build.gradle":    gradleLockingStrict + decl,
		"app/gradle.lockfile": strings.ReplaceAll(gradleWidgetLock, "2.5", "1.0"),
	})
	app := filepath.Join(dir, "app")
	if err := os.Chmod(app, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(app, 0o755) })
	if _, err := os.ReadDir(app); err == nil {
		t.Fatal("app is still listable")
	}
	if _, err := os.ReadFile(filepath.Join(app, "gradle.lockfile")); err != nil {
		t.Fatalf("app's lock must stay readable by path: %v", err)
	}
	if res := resolve(t, dir, "com.example.lib:widget"); res.Match.Resolved {
		t.Errorf("Match = %+v resolved; app locks 1.0", res.Match)
	}
	if deps, complete, why := gradleLockedVersions(dir, "com.example.lib:widget"); complete || !strings.Contains(why, "app/gradle.lockfile") {
		t.Errorf("complete = %v, why = %q, deps %+v; want incomplete naming app/gradle.lockfile", complete, why, deps)
	}
}
