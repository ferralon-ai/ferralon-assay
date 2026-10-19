package javaanalysis

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestResolveVersions_UnwalkedGradleProjectWithholds pins tracker#254's skip-dir half and tracker#273: a Gradle
// build buildFiles doesn't walk must leave the inventory incomplete and the Match unresolved, or a
// root POM's copy resolves alone while Gradle ships another version.
func TestResolveVersions_UnwalkedGradleProjectWithholds(t *testing.T) {
	const (
		pom    = `<project><dependencies><dependency><groupId>com.evil</groupId><artifactId>netkit</artifactId><version>1.0.0</version></dependency></dependencies></project>`
		gradle = "dependencies {\n    implementation 'com.evil:netkit:2.0.0'\n}\n"
	)
	tests := []struct {
		name     string
		files    map[string]string
		link     string            // a symlink at this path, relative to the tree, to a fresh dir outside it holding gradle
		sub      string            // the build dir within the tree, when the tree holds more than the build
		out      map[string]string // files in a fresh dir outside the tree; @OUT@ in a file names it, @ROOT@ the build dir
		withhold bool
		reason   string // the reason withheld rows carry; reasonGradleProjectUnwalked when empty
	}{
		{name: "project included from out", files: map[string]string{"settings.gradle": "include 'out'\n", "out/build.gradle": gradle}, withhold: true},
		{name: "project included from bin", files: map[string]string{"settings.gradle": "include 'bin'\n", "bin/build.gradle": gradle}, withhold: true},
		{name: "project included from build", files: map[string]string{"settings.gradle": "include 'build'\n", "build/build.gradle.kts": gradle}, withhold: true},
		{name: "project included from target", files: map[string]string{"settings.gradle": "include 'target'\n", "target/build.gradle": gradle}, withhold: true},
		{name: "project included from a dot dir", files: map[string]string{"settings.gradle": "include '.x'\n", ".x/build.gradle": gradle}, withhold: true},
		{name: "project nested in a skipped dir", files: map[string]string{"settings.gradle": "include 'build:app'\n", "build/app/build.gradle": gradle}, withhold: true},
		{name: "standalone build in a skipped dir", files: map[string]string{"out/settings.gradle": "", "out/build.gradle": gradle}, withhold: true},
		{name: "project included through a symlink out of the root", files: map[string]string{"settings.gradle": "include 'lib'\n"}, link: "lib", withhold: true, reason: reasonSymlinkOutOfBuildDir},
		{name: "symlink out of the root, not included", files: map[string]string{}, link: "vendor", withhold: true, reason: reasonSymlinkOutOfBuildDir},
		{name: "pluginManagement settings including a project in a skipped dir", files: map[string]string{"settings.gradle": "pluginManagement {\n    repositories {\n        gradlePluginPortal()\n    }\n}\ninclude 'build:app'\n", "build/app/build.gradle": gradle}, withhold: true},
		{name: "projectDir moved into a skipped dir", files: map[string]string{"settings.gradle": "pluginManagement {\n    repositories {\n        gradlePluginPortal()\n    }\n}\ninclude 'app'\nproject(':app').projectDir = file('out/app')\n", "out/app/build.gradle": gradle}, withhold: true},
		{name: "included build in a skipped dir", files: map[string]string{"settings.gradle.kts": "pluginManagement {\n    repositories {\n        gradlePluginPortal()\n    }\n}\nincludeBuild(\"out/plugin\")\n", "out/plugin/build.gradle.kts": gradle}, withhold: true},
		{name: "non-literal include with a script deep in a skipped dir", files: map[string]string{"settings.gradle": "def names = ['app']\ninclude(*names)\n", "build/x/app/build.gradle": gradle}, withhold: true},
		{name: "projectDir moved out of the root", sub: "repo", files: map[string]string{"repo/settings.gradle": "include 'app'\nproject(':app').projectDir = file('../shared/app')\n", "shared/app/build.gradle": gradle}, withhold: true},
		{name: "flat project beside the root", sub: "repo", files: map[string]string{"repo/settings.gradle": "includeFlat 'shared'\n", "shared/build.gradle": gradle}, withhold: true},
		{name: "include with a variable after a literal", files: map[string]string{"settings.gradle": "def p = 'build:app'\ninclude 'app', p\n", "app/build.gradle": "", "build/app/build.gradle": gradle}, withhold: true},
		{name: "include with an interpolated string after a literal", files: map[string]string{"settings.gradle": "def d = 'build'\ninclude \"app\", \"${d}:app\"\n", "app/build.gradle": "", "build/app/build.gradle": gradle}, withhold: true},
		{name: "include of a concatenation", files: map[string]string{"settings.gradle": "include 'build:' + 'app'\n", "build/app/build.gradle": gradle}, withhold: true},
		{name: "include with a spread after a literal", files: map[string]string{"settings.gradle.kts": "val extra = arrayOf(\"build:app\")\ninclude(\"app\", *extra)\n", "app/build.gradle.kts": "", "build/app/build.gradle.kts": gradle}, withhold: true},
		{name: "include continued on the next line inside parentheses", files: map[string]string{"settings.gradle.kts": "include(\n    \"build:\"\n        + \"app\"\n)\n", "build/app/build.gradle.kts": gradle}, withhold: true},
		{name: "includeBuild of a concatenation", files: map[string]string{"settings.gradle.kts": "val name = \"plugin\"\nincludeBuild(\"out/\" + name)\n", "out/plugin/build.gradle.kts": gradle}, withhold: true},
		{name: "includeBuild of a string with an escaped quote", files: map[string]string{"settings.gradle": "def n = 'out/plugin'\nincludeBuild 'x\\';' + n\n", "out/plugin/build.gradle": gradle}, withhold: true},
		{name: "projectDir of a string with an escaped quote", files: map[string]string{"settings.gradle": "def n = 'out/app'\ninclude 'app'\nproject(':app').projectDir = file('x\\');' + n)\n", "out/app/build.gradle": gradle}, withhold: true},
		{name: "include of an interpolated string alone", files: map[string]string{"settings.gradle": "include \"${System.getenv('MOD') ?: 'build:app'}\"\n", "build/app/build.gradle": gradle}, withhold: true},
		{name: "include inside pluginManagement", files: map[string]string{"settings.gradle": "pluginManagement {\n    include 'build:app'\n}\n", "build/app/build.gradle": gradle}, withhold: true},
		{name: "settings plugin outside the allow-list", files: map[string]string{"settings.gradle": "plugins {\n    id 'com.example.projects'\n}\ninclude 'app'\n", "app/build.gradle": "", "build/app/build.gradle": gradle}, withhold: true},
		{name: "unlisted block in settings", files: map[string]string{"settings.gradle.kts": "gradle.beforeProject {\n}\ninclude(\"app\")\n", "app/build.gradle.kts": "", "out/app/build.gradle.kts": gradle}, withhold: true},
		{name: "unbalanced settings block", files: map[string]string{"settings.gradle.kts": "include(\"app\")\npluginManagement {\n    repositories {\n        mavenCentral()\n    }\n", "app/build.gradle.kts": "", "out/app/build.gradle.kts": gradle}, withhold: true},
		{name: "projectDir moved by an absolute path", files: map[string]string{"settings.gradle": "include 'app'\nproject(':app').projectDir = file('@ROOT@/out/app')\n", "out/app/build.gradle": gradle}, out: map[string]string{}, withhold: true},
		{name: "projectDir moved by an absolute path (kts)", files: map[string]string{"settings.gradle.kts": "include(\"app\")\nproject(\":app\").projectDir = file(\"@ROOT@/out/app\")\n", "out/app/build.gradle.kts": gradle}, out: map[string]string{}, withhold: true},
		{name: "included build by an absolute path out of the root", files: map[string]string{"settings.gradle": "includeBuild('@OUT@')\n"}, out: map[string]string{"build.gradle": gradle}, withhold: true},
		{name: "included build by an absolute path to a dir with no script", files: map[string]string{"settings.gradle": "includeBuild('@OUT@')\n"}, out: map[string]string{"README": ""}, withhold: true},
		{name: "React Native settings with an included plugin build", sub: "android", files: map[string]string{"android/settings.gradle": "pluginManagement { includeBuild(\"../node_modules/@react-native/gradle-plugin\") }\nplugins { id(\"com.facebook.react.settings\") }\nextensions.configure(com.facebook.react.ReactSettingsExtension) { ex -> ex.autolinkLibrariesFromCommand() }\nrootProject.name = 'app'\ninclude ':app'\nincludeBuild('../node_modules/@react-native/gradle-plugin')\n", "android/app/build.gradle": "", "node_modules/@react-native/gradle-plugin/settings.gradle.kts": "", "node_modules/@react-native/gradle-plugin/build.gradle.kts": "", "node_modules/rn-lib/android/build.gradle": gradle}, withhold: true},
		{name: "includeFlat after an unlisted block", sub: "repo", files: map[string]string{"repo/settings.gradle": "buildCache {\n    local {\n        enabled = true\n    }\n}\nincludeFlat 'shared'\n", "shared/build.gradle": gradle}, withhold: true},
		{name: "projectDir out of the root after an unlisted line", sub: "repo", files: map[string]string{"repo/settings.gradle": "gradle.startParameter.offline = true\ninclude 'app'\nproject(':app').projectDir = file('../shared/app')\n", "shared/app/build.gradle": gradle}, withhold: true},
		{name: "includeBuild out of the root after a develocity block", sub: "repo", files: map[string]string{"repo/settings.gradle.kts": "develocity {\n    buildScan {\n        termsOfUseAgree = \"yes\"\n    }\n}\nincludeBuild(\"../shared\")\n", "shared/build.gradle.kts": gradle}, withhold: true},
		{name: "includeBuild in a second settings script after a non-literal one", sub: "repo", files: map[string]string{"repo/settings.gradle": "def x = 1\n", "repo/settings.gradle.kts": "includeBuild(\"../shared\")\n", "shared/build.gradle.kts": gradle}, withhold: true},
		{name: "include with a unicode escape", files: map[string]string{"settings.gradle": "include 'build\\u003aapp'\n", "build/app/build.gradle": gradle}, withhold: true},
		{name: "control: includeBuild with a configuration block", files: map[string]string{"settings.gradle.kts": "includeBuild(\"build-logic\") {\n    name = \"logic\"\n}\ninclude(\n    \"app\",\n    \"lib\"\n)\n", "build-logic/build.gradle.kts": "", "app/build.gradle.kts": "", "lib/build.gradle.kts": "", "node_modules/rn-lib/android/build.gradle": gradle}},
		{name: "control: Android Studio template settings, Android build under node_modules", files: map[string]string{"settings.gradle.kts": "pluginManagement {\n    repositories {\n        google {\n            content {\n                includeGroupByRegex(\"com\\\\.android.*\")\n                includeGroupByRegex(\"com\\\\.google.*\")\n                includeGroupByRegex(\"androidx.*\")\n            }\n        }\n        mavenCentral()\n        gradlePluginPortal()\n    }\n}\ndependencyResolutionManagement {\n    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)\n    repositories {\n        google()\n        mavenCentral()\n    }\n}\n\nrootProject.name = \"My Application\"\ninclude(\":app\")\n", "app/build.gradle.kts": "", "node_modules/rn-lib/android/build.gradle": gradle}},
		{name: "control: foojay settings plugin, Android build under node_modules", files: map[string]string{"settings.gradle.kts": "plugins {\n    id(\"org.gradle.toolchains.foojay-resolver-convention\") version \"0.8.0\"\n}\nrootProject.name = \"svc\"\ninclude(\"app\")\n", "app/build.gradle.kts": "", "node_modules/rn-lib/android/build.gradle": gradle}},
		{name: "control: non-literal include, skipped dirs hold no script", files: map[string]string{"settings.gradle": "def names = ['app']\ninclude(*names)\n", "app/build.gradle": "", "target/classes/App.class": "x"}},
		{name: "control: target holds only build output", files: map[string]string{"target/classes/App.class": "x"}},
		{name: "control: dot dir with no script", files: map[string]string{".idea/misc.xml": "<project/>"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.files[filepath.Join(tt.sub, "pom.xml")] = pom
			dir := writeTree(t, tt.files)
			if tt.link != "" {
				outside := t.TempDir()
				if err := os.WriteFile(filepath.Join(outside, "build.gradle"), []byte(gradle), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(dir, tt.link)); err != nil {
					t.Fatal(err)
				}
			}
			if tt.out != nil {
				out := writeTree(t, tt.out)
				for name, content := range tt.files {
					content = strings.ReplaceAll(content, "@OUT@", filepath.ToSlash(out))
					content = strings.ReplaceAll(content, "@ROOT@", filepath.ToSlash(filepath.Join(dir, tt.sub)))
					if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			res := resolve(t, filepath.Join(dir, tt.sub), "com.evil:netkit")
			if !tt.withhold {
				if !res.Partiality.Complete || !res.Match.Resolved || res.Match.Version != "1.0.0" {
					t.Errorf("control withheld: Match %+v, Partiality %+v", res.Match, res.Partiality)
				}
				return
			}
			if !res.Found || res.Match.Resolved || res.Match.Version != "" {
				t.Errorf("Match = %+v (Found %v); want Found and unresolved", res.Match, res.Found)
			}
			want := tt.reason
			if want == "" {
				want = reasonGradleProjectUnwalked
			}
			if res.Partiality.Complete || !slices.Contains(res.Partiality.Reasons, want) {
				t.Errorf("Partiality = %+v; want incomplete with %s", res.Partiality, want)
			}
		})
	}
}
