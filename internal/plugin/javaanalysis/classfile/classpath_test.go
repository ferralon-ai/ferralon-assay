package classfile

import (
	"archive/zip"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeZip(t *testing.T, path string, names ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, n := range names {
		if _, err := zw.Create(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeEmpty(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// TestClasspathPackages: what a classpath entry defines, read without parsing a class, and
// the entries that cannot be listed in full.
func TestClasspathPackages(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, build, outside string) string // returns the entry
		want  []string                                         // nil: not listed
	}{
		{"JAR: class entries name their packages; resources and the manifest do not", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZip(t, p, "META-INF/MANIFEST.MF", "com/acme/A.class", "com/acme/b/B.class", "org/x/res.txt", "Top.class")
			return p
		}, []string{"com/acme", "com/acme/b"}},
		{"multi-release JAR: a class only under META-INF/versions/11/ defines its package", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "mr.jar")
			writeZip(t, p, "META-INF/versions/11/com/sun/tools/javac/main/Option.class", "META-INF/versions/9/module-info.class")
			return p
		}, []string{"com/sun/tools/javac/main"}},
		{"corrupt JAR", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "bad.jar")
			if err := os.WriteFile(p, []byte("PK\x03\x04 not a zip"), 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		}, nil},
		{"missing entry", func(t *testing.T, build, _ string) string {
			return filepath.Join(build, "libs", "gone.jar")
		}, nil},
		{"class directory", func(t *testing.T, build, _ string) string {
			root := filepath.Join(build, "classes")
			writeEmpty(t, filepath.Join(root, "com", "acme", "A.class"))
			writeEmpty(t, filepath.Join(root, "META-INF", "versions", "17", "org", "x", "X.class"))
			writeEmpty(t, filepath.Join(root, "com", "acme", "app.properties"))
			return root
		}, []string{"com/acme", "org/x"}},
		{"directory symlink leaving the build tree", func(t *testing.T, build, outside string) string {
			writeEmpty(t, filepath.Join(outside, "com", "acme", "A.class"))
			link := filepath.Join(build, "classes")
			symlink(t, outside, link)
			return link
		}, nil},
		{"control: directory symlink inside the build tree lists normally", func(t *testing.T, build, _ string) string {
			writeEmpty(t, filepath.Join(build, "real", "com", "acme", "A.class"))
			link := filepath.Join(build, "classes")
			symlink(t, filepath.Join(build, "real"), link)
			return link
		}, []string{"com/acme"}},
		{"control: a JAR symlinked from a cache outside the build tree lists normally", func(t *testing.T, build, outside string) string {
			p := filepath.Join(outside, "cache", "a.jar")
			writeZip(t, p, "com/acme/A.class")
			link := filepath.Join(build, "a.jar")
			symlink(t, p, link)
			return link
		}, []string{"com/acme"}},
		{"class directory holding a symlink", func(t *testing.T, build, outside string) string {
			root := filepath.Join(build, "classes")
			writeEmpty(t, filepath.Join(root, "com", "acme", "A.class"))
			writeEmpty(t, filepath.Join(outside, "B.class"))
			symlink(t, filepath.Join(outside, "B.class"), filepath.Join(root, "com", "acme", "B.class"))
			return root
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build, outside := t.TempDir(), t.TempDir()
			pkgs, ok := ClasspathPackages(tc.setup(t, build, outside), build)
			if tc.want == nil {
				if ok {
					t.Fatalf("listed %v, want unlisted", slices.Sorted(maps.Keys(pkgs)))
				}
				return
			}
			if !ok {
				t.Fatal("unlisted, want listed")
			}
			if got := slices.Sorted(maps.Keys(pkgs)); !slices.Equal(got, tc.want) {
				t.Fatalf("packages %v, want %v", got, tc.want)
			}
		})
	}
}
