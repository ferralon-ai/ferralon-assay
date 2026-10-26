package javaanalysis

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Nothing taken from a build file may steer a cache path out of the cache.
func TestValidGAV(t *testing.T) {
	for _, tc := range []struct {
		group, artifact, version string
		ok                       bool
	}{
		{"com.google.code.gson", "gson", "2.10.1", true},
		{"com.example", "lib", "", false},
		{"com.evil", "netkit", "../../planted/fake", false},
		{"com.evil", "netkit", "1.0/../../x", false},
		{"com.evil", "netkit", `..\x`, false},
		{"com.evil", "netkit", "..", false},
		{"com.evil", "netkit", ".", false},
		{"com.evil", "netkit", "1.0\x00", false},
		{"com..evil", "netkit", "1.0", false},
		{"com.evil", "../netkit", "1.0", false},
		{"com/evil", "netkit", "1.0", false},
	} {
		if got := validGAV(tc.group, tc.artifact, tc.version); got != tc.ok {
			t.Errorf("validGAV(%q, %q, %q) = %v, want %v", tc.group, tc.artifact, tc.version, got, tc.ok)
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
	// A cached name that links, inside the cache, to a FIFO is judged by what it resolves to.
	link := filepath.Join(root, "com", "x", "w", "1.0", "w-1.0.jar")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	if _, st := inCache(root, filepath.Join("com", "x", "w", "1.0", "w-1.0.jar")); st != cacheEscape {
		t.Errorf("inCache on a link to a FIFO = %v, want cacheEscape", st)
	}
	if _, err := readRegular(link); err == nil {
		t.Error("readRegular read a FIFO through a link")
	}
}

// The cached-POM reader treats a file reached through a link out of its cache, or a version
// that walks out of it, as absent. Absent means the caller reports the
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

	t.Run("maven", func(t *testing.T) {
		repo := t.TempDir()
		dir := filepath.Join(repo, "com", "evil", "netkit", "1.0.0")
		link(t, filepath.Join(outside, "netkit.pom"), filepath.Join(dir, "netkit-1.0.0.pom"))
		link(t, filepath.Join(outside, "netkit.jar"), filepath.Join(dir, "netkit-1.0.0.jar"))
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
}
