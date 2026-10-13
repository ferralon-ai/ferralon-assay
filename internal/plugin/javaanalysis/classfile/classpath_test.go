package classfile

import (
	"archive/zip"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

func writeZipFiles(t *testing.T, path string, files map[string]string) {
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
	for _, n := range slices.Sorted(maps.Keys(files)) {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(files[n])); err != nil {
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
// the entries that cannot be listed in full, and the entries whose listing is not closed: they
// can put more on the classpath than their own classes (open).
func TestClasspathPackages(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, build, outside string) string // returns the entry
		want  []string                                         // nil: not listed
		open  bool
	}{
		{"JAR: class entries name their packages; resources and the manifest do not", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZip(t, p, "META-INF/MANIFEST.MF", "com/acme/A.class", "com/acme/b/B.class", "org/x/res.txt", "Top.class")
			return p
		}, []string{"com/acme", "com/acme/b"}, false},
		{"multi-release JAR: a class only under META-INF/versions/11/ defines its package", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "mr.jar")
			writeZip(t, p, "META-INF/versions/11/com/sun/tools/javac/main/Option.class", "META-INF/versions/9/module-info.class")
			return p
		}, []string{"com/sun/tools/javac/main"}, false},
		{"corrupt JAR", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "bad.jar")
			if err := os.WriteFile(p, []byte("PK\x03\x04 not a zip"), 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		}, nil, false},
		{"missing entry", func(t *testing.T, build, _ string) string {
			return filepath.Join(build, "libs", "gone.jar")
		}, nil, false},
		{"class directory", func(t *testing.T, build, _ string) string {
			root := filepath.Join(build, "classes")
			writeEmpty(t, filepath.Join(root, "com", "acme", "A.class"))
			writeEmpty(t, filepath.Join(root, "META-INF", "versions", "17", "org", "x", "X.class"))
			writeEmpty(t, filepath.Join(root, "com", "acme", "app.properties"))
			return root
		}, []string{"com/acme", "org/x"}, false},
		{"directory symlink leaving the build tree", func(t *testing.T, build, outside string) string {
			writeEmpty(t, filepath.Join(outside, "com", "acme", "A.class"))
			link := filepath.Join(build, "classes")
			symlink(t, outside, link)
			return link
		}, nil, false},
		{"control: directory symlink inside the build tree lists normally", func(t *testing.T, build, _ string) string {
			writeEmpty(t, filepath.Join(build, "real", "com", "acme", "A.class"))
			link := filepath.Join(build, "classes")
			symlink(t, filepath.Join(build, "real"), link)
			return link
		}, []string{"com/acme"}, false},
		{"control: a JAR symlinked from a cache outside the build tree lists normally", func(t *testing.T, build, outside string) string {
			p := filepath.Join(outside, "cache", "a.jar")
			writeZip(t, p, "com/acme/A.class")
			link := filepath.Join(build, "a.jar")
			symlink(t, p, link)
			return link
		}, []string{"com/acme"}, false},
		{"Spring Boot JAR: a BOOT-INF/lib nested JAR", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "app.jar")
			writeZip(t, p, "BOOT-INF/classes/com/acme/App.class", "BOOT-INF/lib/javac-shaded.jar", "org/springframework/boot/loader/Launcher.class")
			return p
		}, []string{"BOOT-INF/classes/com/acme", "org/springframework/boot/loader"}, true},
		{"WAR: a WEB-INF/lib nested JAR", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "app.war")
			writeZip(t, p, "WEB-INF/classes/com/acme/App.class", "WEB-INF/lib/javac-shaded.jar")
			return p
		}, []string{"WEB-INF/classes/com/acme"}, true},
		{"a nested JAR more than one directory deep, upper-case suffix", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZip(t, p, "com/acme/A.class", "lib/ext/vendor/JAVAC.JAR")
			return p
		}, []string{"com/acme"}, true},
		{"a nested WAR", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZip(t, p, "com/acme/A.class", "webapps/root.war")
			return p
		}, []string{"com/acme"}, true},
		{"a nested zip", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZip(t, p, "com/acme/A.class", "plugins/javac.zip")
			return p
		}, []string{"com/acme"}, true},
		{"manifest Class-Path", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZipFiles(t, p, map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nClass-Path: javac-shaded.jar\r\n\r\n", "com/acme/A.class": ""})
			return p
		}, []string{"com/acme"}, true},
		{"manifest class-path in lower case, value on a continuation line", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZipFiles(t, p, map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nclass-path: \n javac-shaded.jar\nCreated-By: x\n\n", "com/acme/A.class": ""})
			return p
		}, []string{"com/acme"}, true},
		{"class directory holding a JAR", func(t *testing.T, build, _ string) string {
			root := filepath.Join(build, "classes")
			writeEmpty(t, filepath.Join(root, "com", "acme", "A.class"))
			writeEmpty(t, filepath.Join(root, "lib", "javac-shaded.jar"))
			return root
		}, []string{"com/acme"}, true},
		{"control: an empty Class-Path is closed", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZipFiles(t, p, map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nClass-Path: \nMain-Class: com.acme.A\n\n", "com/acme/A.class": ""})
			return p
		}, []string{"com/acme"}, false},
		{"control: an empty Class-Path as the main section's last attribute is closed", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZipFiles(t, p, map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nClass-Path:  \r\n\r\n", "com/acme/A.class": ""})
			return p
		}, []string{"com/acme"}, false},
		{"a manifest line too long to read: not listed", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZipFiles(t, p, map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nX-Long: " + strings.Repeat("a", 2<<20) + "\n\n", "com/acme/A.class": ""})
			return p
		}, nil, true},
		{"a class under a package segment starting with a digit", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZip(t, p, "com/1acme/A.class", "com/acme/B.class")
			return p
		}, []string{"com/1acme", "com/acme"}, true},
		{"control: a Class-Path in a per-entry section is closed", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZipFiles(t, p, map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n\nName: com/acme/\nClass-Path: x.jar\n\n", "com/acme/A.class": ""})
			return p
		}, []string{"com/acme"}, false},
		{"control: a JAR with no nested archive and no Class-Path is closed", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZipFiles(t, p, map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nMain-Class: com.acme.A\n\n", "com/acme/A.class": "", "com/acme/jar.txt": ""})
			return p
		}, []string{"com/acme"}, false},
		{"Spring Boot JAR with no nested JAR: classes under BOOT-INF/classes/", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "app.jar")
			writeZip(t, p, "BOOT-INF/classes/com/sun/tools/javac/main/Main.class", "com/acme/A.class")
			return p
		}, []string{"BOOT-INF/classes/com/sun/tools/javac/main", "com/acme"}, true},
		{"control: a package-info class and a nested-class name are closed", func(t *testing.T, build, _ string) string {
			p := filepath.Join(build, "libs", "a.jar")
			writeZip(t, p, "com/acme/package-info.class", "com/acme/A$1.class", "com/acme_2/$x/été/B.class", "module-info.class")
			return p
		}, []string{"com/acme", "com/acme_2/$x/été"}, false},
		{"class directory holding a symlink", func(t *testing.T, build, outside string) string {
			root := filepath.Join(build, "classes")
			writeEmpty(t, filepath.Join(root, "com", "acme", "A.class"))
			writeEmpty(t, filepath.Join(outside, "B.class"))
			symlink(t, filepath.Join(outside, "B.class"), filepath.Join(root, "com", "acme", "B.class"))
			return root
		}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build, outside := t.TempDir(), t.TempDir()
			pkgs, ok, closed := ClasspathPackages(tc.setup(t, build, outside), build)
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
			if closed == tc.open {
				t.Fatalf("closed = %v, want %v", closed, !tc.open)
			}
		})
	}
}
