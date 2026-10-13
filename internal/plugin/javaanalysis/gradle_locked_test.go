package javaanalysis

import (
	"reflect"
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
