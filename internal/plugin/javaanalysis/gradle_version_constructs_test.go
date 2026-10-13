package javaanalysis

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestGradleVersionConstructs(t *testing.T) {
	for _, tt := range []struct {
		name string
		srcs []string
		want []string
	}{
		{"none", []string{"dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n"}, []string{}},
		{"catalog accessor", []string{"dependencies { implementation libs.netkit }"}, []string{"libs."}},
		{"catalog accessor in an interpolation", []string{`implementation "com.evil:netkit:${libs.versions.n.get()}"`}, []string{"libs."}},
		{"catalog accessor in a short interpolation", []string{`implementation "com.evil:netkit:$libs.versions.n"`}, []string{"libs."}},
		{"catalog file reference", []string{"versionCatalogs { create('deps') { from(files('gradle/deps.toml')) } }"}, []string{".toml", "versionCatalogs"}},
		{"rich versions", []string{"version { strictly '2.0' }", "version { require '2.0' }", "version { prefer '2.0' }"}, []string{"prefer", "require", "strictly"}},
		{"resolution rules", []string{"configurations.all { resolutionStrategy.eachDependency { it.useVersion '2.0' } }"}, []string{"eachDependency", "resolutionStrategy", "useVersion"}},
		{"substitution", []string{"dependencySubstitution { substitute module('a:b') using module('a:b:2.0') }"}, []string{"dependencySubstitution"}},
		{"force", []string{"force 'a:b:2.0'"}, []string{"force"}},
		{"kotlin isForce", []string{`implementation("a:b:1.0") { isForce = true }`}, []string{"isForce"}},
		{"enforced platform", []string{"implementation enforcedPlatform('a:bom:2.0')"}, []string{"enforcedPlatform"}},
		{"only in comments", []string{"// force 'a:b:2.0'\n/* libs.netkit strictly */\n"}, []string{}},
		{"only inside other identifiers", []string{"ext.forced = true\next.preferredJava = 17\ndef requireJava = 1\ndef mylibs = []\n"}, []string{}},
		{"only at the end of other identifiers", []string{"def myforce = 1\ndef notstrictly = 2\next.mylibs.netkit = 3\n"}, []string{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := gradleVersionConstructs(tt.srcs...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("gradleVersionConstructs = %q, want %q", got, tt.want)
			}
		})
	}
}

// A construct that can move a version off what the lock and the literal declarations say leaves
// every GA its project locks unconfirmed, even when the lock and the declarations agree: here the
// lock holds 1.0.0 while the build resolves 2.0.0.
func TestGradle_VersionConstructsUnconfirmLock(t *testing.T) {
	const enforced = "dependencyLocking {\n    lockAllConfigurations()\n}\n"
	const lock = "com.evil:netkit:1.0.0=compileClasspath,runtimeClasspath\norg.pulls:it:1.0=compileClasspath,runtimeClasspath\n"
	const catalogRef = "[versions]\nn = \"2.0.0\"\n\n[libraries]\nnetkit = { module = \"com.evil:netkit\", version.ref = \"n\" }\n"
	const catalogLit = "[libraries]\nnetkit = { module = \"com.evil:netkit\", version = \"2.0.0\" }\n"
	netkit := mavenPURL("com.evil", "netkit", "1.0.0")
	for _, tt := range []struct {
		name     string
		files    map[string]string
		resolved bool
	}{
		{"no construct", map[string]string{
			"build.gradle": enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
		}, true},
		{"catalog alias with version.ref", map[string]string{
			"build.gradle":              enforced + "dependencies {\n    implementation libs.netkit\n}\n",
			"gradle/libs.versions.toml": catalogRef,
		}, false},
		{"catalog alias with version.ref, kts", map[string]string{
			"build.gradle.kts":          enforced + "dependencies {\n    implementation(libs.netkit)\n}\n",
			"gradle/libs.versions.toml": catalogRef,
		}, false},
		{"catalog alias with a literal", map[string]string{
			"build.gradle":              enforced + "dependencies {\n    implementation libs.netkit\n}\n",
			"gradle/libs.versions.toml": catalogLit,
		}, false},
		{"catalog version in an interpolation", map[string]string{
			"build.gradle":              enforced + "dependencies {\n    implementation \"com.evil:netkit:${libs.versions.n.get()}\"\n}\n",
			"gradle/libs.versions.toml": catalogRef,
		}, false},
		{"version { strictly }", map[string]string{
			"build.gradle": enforced + "dependencies {\n    implementation('com.evil:netkit:1.0.0') { version { strictly '2.0.0' } }\n}\n",
		}, false},
		{"version { require }", map[string]string{
			"build.gradle": enforced + "dependencies {\n    implementation('com.evil:netkit:1.0.0') { version { require '2.0.0' } }\n}\n",
		}, false},
		{"version { prefer }", map[string]string{
			"build.gradle": enforced + "dependencies {\n    implementation('com.evil:netkit') { version { prefer '2.0.0' } }\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
		}, false},
		{"eachDependency useVersion", map[string]string{
			"build.gradle": enforced + "configurations.all {\n    resolutionStrategy.eachDependency { if (it.requested.name == 'netkit') it.useVersion '2.0.0' }\n}\n" +
				"dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
		}, false},
		{"eachDependency useVersion on a transitive-only GA", map[string]string{
			"build.gradle": enforced + "configurations.all {\n    resolutionStrategy.eachDependency { if (it.requested.name == 'netkit') it.useVersion '2.0.0' }\n}\n" +
				"dependencies {\n    implementation 'org.pulls:it:1.0'\n}\n",
		}, false},
		{"eachDependency useVersion, kts", map[string]string{
			"build.gradle.kts": enforced + "configurations.all {\n    resolutionStrategy {\n        eachDependency { if (requested.name == \"netkit\") useVersion(\"2.0.0\") }\n    }\n}\n" +
				"dependencies {\n    implementation(\"com.evil:netkit:1.0.0\")\n}\n",
		}, false},
		{"force through a catalog alias", map[string]string{
			"build.gradle": enforced + "configurations.all {\n    resolutionStrategy.force libs.netkit\n}\n" +
				"dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"gradle/libs.versions.toml": catalogRef,
		}, false},
		{"force on the declaration, kts", map[string]string{
			"build.gradle.kts": enforced + "dependencies {\n    implementation(\"com.evil:netkit:1.0.0\") { isForce = true }\n    implementation(\"org.pulls:it:1.0\")\n}\n",
		}, false},
		{"dependency substitution", map[string]string{
			"build.gradle": enforced + "configurations.all {\n    resolutionStrategy.dependencySubstitution {\n        substitute module('com.evil:netkit') using module('com.evil:netkit:2.0.0')\n    }\n}\n" +
				"dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
		}, false},
		{"enforced platform", map[string]string{
			"build.gradle": enforced + "dependencies {\n    implementation enforcedPlatform('com.evil:bom:2.0')\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
		}, false},
		{"a construct in the root script reaches the subproject", map[string]string{
			"settings.gradle":     "include 'app'\n",
			"build.gradle":        "subprojects {\n    configurations.all { resolutionStrategy.eachDependency { it.useVersion '2.0.0' } }\n}\n",
			"app/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"app/gradle.lockfile": lock,
		}, false},
		{"a construct in the root script reaches a GA only the subproject locks", map[string]string{
			"settings.gradle":     "include 'app'\n",
			"build.gradle":        "subprojects {\n    configurations.all { resolutionStrategy.eachDependency { if (it.requested.name == 'netkit') it.useVersion '2.0.0' } }\n}\n",
			"gradle.lockfile":     "org.pulls:it:1.0=compileClasspath,runtimeClasspath\n",
			"app/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"app/gradle.lockfile": "com.evil:netkit:1.0.0=compileClasspath,runtimeClasspath\n",
		}, false},
		{"a construct in a project without a lock", map[string]string{
			"settings.gradle":  "include 'app'\n",
			"build.gradle":     enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"app/build.gradle": "configurations.all { resolutionStrategy.force 'com.evil:netkit:2.0.0' }\n",
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			locked := false
			for rel, body := range tt.files {
				writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
				locked = locked || filepath.Base(rel) == "gradle.lockfile"
			}
			if !locked {
				writeFile(t, filepath.Join(dir, "gradle.lockfile"), lock)
			}
			inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
			if got := findNode(t, inv, netkit) != nil; got != tt.resolved {
				t.Fatalf("netkit resolved at 1.0.0 = %v, want %v; nodes %+v", got, tt.resolved, inv.Nodes)
			}
			if tt.resolved {
				return
			}
			n := findNode(t, inv, mavenPURL("com.evil", "netkit", ""))
			if n == nil || !hasStr(n.Partiality.Reasons, reasonGradleLockUnconfirmed) {
				t.Errorf("want netkit present, unresolved, %s; got %+v", reasonGradleLockUnconfirmed, n)
			}
		})
	}
}
