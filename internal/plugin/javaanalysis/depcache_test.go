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
		// Nothing taken from a build file may steer the path out of the cache.
		{"com.evil:netkit", "../../planted/fake", "", false},
		{"com.evil:netkit", "1.0/../../x", "", false},
		{"com.evil:netkit", `..\\x`, "", false},
		{"com.evil:netkit", "..", "", false},
		{"com.evil:netkit", ".", "", false},
		{"com.evil:netkit", "1.0\x00", "", false},
		{"com..evil:netkit", "1.0", "", false},
		{"com.evil:../netkit", "1.0", "", false},
		{"com/evil:netkit", "1.0", "", false},
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
		if !ok || got != realPath(t, jarPath) {
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
		if !ok || got != realPath(t, jarPath) {
			t.Fatalf("LocateDependencyJar across roots = (%q,%v), want (%q,true)", got, ok, jarPath)
		}
	})
	t.Run("malformed coordinate is a miss", func(t *testing.T) {
		if _, ok := LocateDependencyJar([]string{root}, "widget", "1.4.0"); ok {
			t.Fatal("want miss for malformed coordinate")
		}
	})
	t.Run("a directory at the jar path is a miss", func(t *testing.T) {
		dirRoot := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dirRoot, "com", "example", "lib", "widget", "1.4.0", "widget-1.4.0.jar"), 0o755); err != nil {
			t.Fatal(err)
		}
		if got, ok := LocateDependencyJar([]string{dirRoot}, "com.example.lib:widget", "1.4.0"); ok {
			t.Fatalf("want miss for a directory, got %q", got)
		}
	})
	// The first copy found is the one the caller would bind; when it leaves its cache, a later
	// root's copy doesn't stand in for it.
	t.Run("first copy links out of its cache", func(t *testing.T) {
		linkRoot := t.TempDir()
		linkDir := filepath.Join(linkRoot, "com", "example", "lib", "widget", "1.4.0")
		if err := os.MkdirAll(linkDir, 0o755); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "elsewhere.jar")
		if err := os.WriteFile(outside, []byte("PK\x03\x04"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(linkDir, "widget-1.4.0.jar")); err != nil {
			t.Fatal(err)
		}
		if got, ok := LocateDependencyJar([]string{linkRoot, root}, "com.example.lib:widget", "1.4.0"); ok {
			t.Fatalf("want miss when the first copy escapes, got %q", got)
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

// Every reader of the local caches (dependency JARs for the graph, cached POMs and their digest
// sidecars, in the Maven and the Gradle layout) treats a file reached through a link out of
// its cache, or a version that walks out of it, as absent. Absent means the caller reports the
// gap; what sits outside the cache is never read as the build's artifact.
func TestCacheReaders_StayInsideTheCache(t *testing.T) {
	const pom = `<project><groupId>com.evil</groupId><artifactId>netkit</artifactId><version>1.0.0</version></project>`
	link := func(t *testing.T, target, name string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "netkit.pom"), pom)
	writeFile(t, filepath.Join(outside, "netkit.jar"), "PK\x03\x04")
	writeFile(t, filepath.Join(outside, "netkit.sha1"), "0123abcd")

	t.Run("maven", func(t *testing.T) {
		repo := t.TempDir()
		dir := filepath.Join(repo, "com", "evil", "netkit", "1.0.0")
		link(t, filepath.Join(outside, "netkit.pom"), filepath.Join(dir, "netkit-1.0.0.pom"))
		link(t, filepath.Join(outside, "netkit.jar"), filepath.Join(dir, "netkit-1.0.0.jar"))
		link(t, filepath.Join(outside, "netkit.sha1"), filepath.Join(dir, "netkit-1.0.0.jar.sha1"))
		// Where a lexical join of the traversal version below lands: a real POM, though not
		// netkit's.
		writeFile(t, filepath.Join(repo, "planted.pom"), pom)

		cache := newMavenCacheAt(repo)
		if _, ok := cache.get("com.evil", "netkit", "1.0.0"); ok {
			t.Error("mavenCache.get read a POM linked from outside the cache")
		}
		if _, ok := cache.get("com.evil", "netkit", "../../../planted"); ok {
			t.Error("mavenCache.get followed a traversal version")
		}
		if d := cache.digestFor("com.evil", "netkit", "1.0.0"); d != "" {
			t.Errorf("digestFor read a sidecar linked from outside the cache: %q", d)
		}
		if p, ok := LocateDependencyJar([]string{repo}, "com.evil:netkit", "1.0.0"); ok {
			t.Errorf("LocateDependencyJar bound a JAR linked from outside the cache: %q", p)
		}
	})
	t.Run("maven, link inside the cache", func(t *testing.T) {
		repo := t.TempDir()
		writeFile(t, filepath.Join(repo, "blobs", "netkit.pom"), pom)
		link(t, filepath.Join(repo, "blobs", "netkit.pom"), filepath.Join(repo, "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.pom"))
		if _, ok := newMavenCacheAt(repo).get("com.evil", "netkit", "1.0.0"); !ok {
			t.Error("mavenCache.get refused a link that stays inside the cache")
		}
	})
	t.Run("gradle", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "com.evil", "netkit", "1.0.0", "0a1b")
		link(t, filepath.Join(outside, "netkit.pom"), filepath.Join(dir, "netkit-1.0.0.pom"))
		link(t, filepath.Join(outside, "netkit.sha1"), filepath.Join(dir, "netkit-1.0.0.jar.sha1"))
		cache := newGradleCache(root)
		if _, ok := cache.pom("com.evil", "netkit", "1.0.0"); ok {
			t.Error("gradleCache.pom read a POM linked from outside the cache")
		}
		if d := cache.digest("com.evil", "netkit", "1.0.0"); d != "" {
			t.Errorf("gradleCache.digest read a sidecar linked from outside the cache: %q", d)
		}
		// root/com.evil/netkit/../../x/<hash>/netkit-../../x.pom lands on root/x/h/x.pom.
		writeFile(t, filepath.Join(root, "x", "h", "x.pom"), pom)
		if _, ok := cache.pom("com.evil", "netkit", "../../x"); ok {
			t.Error("gradleCache.pom followed a traversal version")
		}
	})
}
