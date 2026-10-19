package javaanalysis

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestResolveVersions_UnwalkedGradleProjectWithholds pins tracker#254's skip-dir half: a Gradle
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
		link     string // a symlink at this path, relative to the tree, to a fresh dir outside it holding gradle
		withhold bool
	}{
		{name: "project included from out", files: map[string]string{"settings.gradle": "include 'out'\n", "out/build.gradle": gradle}, withhold: true},
		{name: "project included from bin", files: map[string]string{"settings.gradle": "include 'bin'\n", "bin/build.gradle": gradle}, withhold: true},
		{name: "project included from build", files: map[string]string{"settings.gradle": "include 'build'\n", "build/build.gradle.kts": gradle}, withhold: true},
		{name: "project included from target", files: map[string]string{"settings.gradle": "include 'target'\n", "target/build.gradle": gradle}, withhold: true},
		{name: "project included from a dot dir", files: map[string]string{"settings.gradle": "include '.x'\n", ".x/build.gradle": gradle}, withhold: true},
		{name: "project nested in a skipped dir", files: map[string]string{"settings.gradle": "include 'build:app'\n", "build/app/build.gradle": gradle}, withhold: true},
		{name: "standalone build in a skipped dir", files: map[string]string{"out/settings.gradle": "", "out/build.gradle": gradle}, withhold: true},
		{name: "project included through a symlink out of the root", files: map[string]string{"settings.gradle": "include 'lib'\n"}, link: "lib", withhold: true},
		{name: "symlink out of the root, not included", files: map[string]string{}, link: "vendor", withhold: true},
		{name: "control: target holds only build output", files: map[string]string{"target/classes/App.class": "x"}},
		{name: "control: dot dir with no script", files: map[string]string{".idea/misc.xml": "<project/>"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.files["pom.xml"] = pom
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
			res := resolve(t, dir, "com.evil:netkit")
			if !tt.withhold {
				if !res.Partiality.Complete || !res.Match.Resolved || res.Match.Version != "1.0.0" {
					t.Errorf("control withheld: Match %+v, Partiality %+v", res.Match, res.Partiality)
				}
				return
			}
			if !res.Found || res.Match.Resolved || res.Match.Version != "" {
				t.Errorf("Match = %+v (Found %v); want Found and unresolved", res.Match, res.Found)
			}
			if res.Partiality.Complete || !slices.Contains(res.Partiality.Reasons, reasonGradleProjectUnwalked) {
				t.Errorf("Partiality = %+v; want incomplete with %s", res.Partiality, reasonGradleProjectUnwalked)
			}
		})
	}
}
