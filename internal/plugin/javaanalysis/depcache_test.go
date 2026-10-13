package javaanalysis

import (
	"os"
	"path/filepath"
	"syscall"
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

// isolateHome points HOME at a fresh directory, so the user caches a lookup searches are the
// test's own.
func isolateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// Only a JAR that is not there is missing. One that is there but cannot be looked at, or is not a
// regular file, could be the bytes the build ran, so it is unreadable, and no other copy stands
// in for it.
func TestLocateArtifactJar_UnreadableIsNotAbsent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file modes do not stop root reading a directory")
	}
	const gav = "com.example.lib:widget"
	m2 := func(base string) string {
		return filepath.Join(base, ".m2", "repository", "com", "example", "lib", "widget", "1.4.0")
	}
	gradle := func(base string) string {
		return filepath.Join(base, ".gradle", "caches", "modules-2", "files-2.1", "com.example.lib", "widget", "1.4.0")
	}
	lock := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	}
	for _, tc := range []struct {
		name       string
		coordinate string
		setup      func(t *testing.T, build, home string)
		want       jarLookup
	}{
		{name: "a copy in the checkout alone", coordinate: gav, setup: func(t *testing.T, build, home string) {}, want: jarFound},
		{name: "user Maven version directory cannot be read", coordinate: gav, setup: func(t *testing.T, build, home string) {
			lock(t, m2(home))
		}, want: jarUnreadable},
		{name: "user Gradle version directory cannot be read", coordinate: gav, setup: func(t *testing.T, build, home string) {
			lock(t, gradle(home))
		}, want: jarUnreadable},
		{name: "a directory at the jar path", coordinate: gav, setup: func(t *testing.T, build, home string) {
			if err := os.MkdirAll(filepath.Join(m2(home), "widget-1.4.0.jar"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, want: jarFound},
		{name: "a FIFO at the jar path", coordinate: gav, setup: func(t *testing.T, build, home string) {
			if err := os.MkdirAll(m2(home), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(filepath.Join(m2(home), "widget-1.4.0.jar"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, want: jarUnreadable},
		{name: "malformed coordinate", coordinate: "widget", setup: func(t *testing.T, build, home string) {}, want: jarUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := isolateHome(t)
			build := t.TempDir()
			writeJar(t, filepath.Join(m2(build), "widget-1.4.0.jar"), "com/example/lib/widget/W.class", emitClass(&cpb{}, "com/example/lib/widget/W", nil))
			tc.setup(t, build, home)
			if _, found := locateArtifactJar(build, tc.coordinate, "1.4.0"); found != tc.want {
				t.Fatalf("locateArtifactJar = %v, want %v", found, tc.want)
			}
		})
	}
}

// A FIFO is neither a cache hit nor a miss, and reading one fails at once instead of waiting for
// a writer.
func TestCacheReads_RefuseAFIFO(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "w.jar")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, st := inCache(root, "w.jar"); st != cacheEscape {
		t.Errorf("inCache on a FIFO = %v, want cacheEscape", st)
	}
	if _, err := readRegular(fifo); err == nil {
		t.Error("readRegular read a FIFO")
	}
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
		if p, st := inCache(repo, filepath.Join("com", "evil", "netkit", "1.0.0", "netkit-1.0.0.jar")); st != cacheEscape {
			t.Errorf("inCache bound a JAR linked from outside the cache: %q, %v", p, st)
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
	// The first root's POM is an escape: a later root's copy does not stand in for it.
	t.Run("maven, escape in an earlier root", func(t *testing.T) {
		first, second := t.TempDir(), t.TempDir()
		link(t, filepath.Join(outside, "netkit.pom"), filepath.Join(first, "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.pom"))
		writeFile(t, filepath.Join(second, "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.pom"), pom)
		if _, ok := newMavenCacheAt(first, second).get("com.evil", "netkit", "1.0.0"); ok {
			t.Error("mavenCache.get fell through an escaping POM to the next root")
		}
	})
	// A repository the checkout only links to is somewhere else's cache.
	t.Run("maven, checkout repository links out", func(t *testing.T) {
		isolateHome(t)
		build, repo := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(repo, "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.pom"), pom)
		link(t, repo, filepath.Join(build, ".m2", "repository"))
		if _, ok := newMavenCache(build).get("com.evil", "netkit", "1.0.0"); ok {
			t.Error("mavenCache.get read a POM through a checkout repository that links outside the checkout")
		}
		other := t.TempDir()
		inside := filepath.Join(other, "cache")
		writeFile(t, filepath.Join(inside, "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.pom"), pom)
		link(t, inside, filepath.Join(other, ".m2", "repository"))
		if _, ok := newMavenCache(other).get("com.evil", "netkit", "1.0.0"); !ok {
			t.Error("mavenCache.get refused a checkout repository that links inside the checkout")
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
