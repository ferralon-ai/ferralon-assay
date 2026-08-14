package javaanalysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMavenJarRelPath(t *testing.T) {
	cases := []struct {
		coordinate, version, want string
		ok                        bool
	}{
		{"com.google.code.gson:gson", "2.10.1", "com/google/code/gson/gson/2.10.1/gson-2.10.1.jar", true},
		{"com.example.lib:widget", "1.4.0", "com/example/lib/widget/1.4.0/widget-1.4.0.jar", true},
		{"single", "1.0", "", false},       // not group:artifact
		{"g:a:extra", "1.0", "", false},    // too many parts
		{"com.example:lib", "", "", false}, // empty version
		{" : ", "1.0", "", false},          // blank parts
	}
	for _, tc := range cases {
		got, ok := mavenJarRelPath(tc.coordinate, tc.version)
		if ok != tc.ok || filepath.ToSlash(got) != tc.want {
			t.Errorf("mavenJarRelPath(%q,%q) = (%q,%v), want (%q,%v)", tc.coordinate, tc.version, got, ok, tc.want, tc.ok)
		}
	}
}

func TestLocateDependencyJar(t *testing.T) {
	// Build a synthetic per-build Maven cache: <root>/com/example/lib/widget/1.4.0/widget-1.4.0.jar.
	// The locator only checks for the file's presence, so dummy content suffices here;
	// bytecode parsing is exercised in the classfile package's tests.
	root := t.TempDir()
	jarDir := filepath.Join(root, "com", "example", "lib", "widget", "1.4.0")
	if err := os.MkdirAll(jarDir, 0o755); err != nil {
		t.Fatal(err)
	}
	jarPath := filepath.Join(jarDir, "widget-1.4.0.jar")
	if err := os.WriteFile(jarPath, []byte("PK\x03\x04"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("found in root", func(t *testing.T) {
		got, ok := LocateDependencyJar([]string{root}, "com.example.lib:widget", "1.4.0")
		if !ok || got != jarPath {
			t.Fatalf("LocateDependencyJar = (%q,%v), want (%q,true)", got, ok, jarPath)
		}
	})
	t.Run("wrong version is a miss, not a fetch", func(t *testing.T) {
		if got, ok := LocateDependencyJar([]string{root}, "com.example.lib:widget", "9.9.9"); ok {
			t.Fatalf("want miss for absent version, got %q", got)
		}
	})
	t.Run("skips empty and non-existent roots", func(t *testing.T) {
		got, ok := LocateDependencyJar([]string{"", filepath.Join(root, "nope"), root}, "com.example.lib:widget", "1.4.0")
		if !ok || got != jarPath {
			t.Fatalf("LocateDependencyJar across roots = (%q,%v), want (%q,true)", got, ok, jarPath)
		}
	})
	t.Run("malformed coordinate is a miss", func(t *testing.T) {
		if _, ok := LocateDependencyJar([]string{root}, "widget", "1.4.0"); ok {
			t.Fatal("want miss for malformed coordinate")
		}
	})
}

func TestMavenRepoRoots_IncludesProjectLocalCache(t *testing.T) {
	build := t.TempDir()
	roots := mavenRepoRoots(build)
	want := filepath.Join(build, ".m2", "repository")
	if len(roots) == 0 || roots[0] != want {
		t.Fatalf("first repo root = %v, want project-local %q first", roots, want)
	}
}
