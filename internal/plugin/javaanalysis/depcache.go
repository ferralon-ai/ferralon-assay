package javaanalysis

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// depcache.go — step (a) of dependency reachability: locate a resolved dependency's
// JAR in the build's LOCAL artifact cache. Zero-egress by construction: it reads
// caches the build already populated and never fetches. A coordinate whose JAR is
// not present is a declared miss (ok=false) the caller turns into a completeness
// hazard — never a silent "the dependency has no code".
//
// This is the resolution front the dependency graph consumes. Its inputs (a
// resolved coordinate + version) come from ResolveDependencyVersions; PLAN-140's
// Maven effective-resolution refines which version is selected, but the cache
// lookup itself is version-agnostic and lands now.

// mavenJarRelPath renders the Maven local-repository relative path of an artifact:
//
//	<groupId as path>/<artifactId>/<version>/<artifactId>-<version>.jar
//
// e.g. ("com.google.code.gson:gson", "2.10.1") ->
// "com/google/code/gson/gson/2.10.1/gson-2.10.1.jar". ok is false for a coordinate
// that is not "groupId:artifactId", or any part validGAV rejects — a malformed input
// never yields a path that could match an unrelated file.
func mavenJarRelPath(coordinate, version string) (string, bool) {
	return mavenArtifactRelPath(coordinate, version, "jar")
}

// mavenArtifactRelPath is mavenJarRelPath for the artifact file with extension ext ("jar", "pom").
func mavenArtifactRelPath(coordinate, version, ext string) (string, bool) {
	group, artifact, ok := splitCoordinate(coordinate)
	if !ok || !validGAV(group, artifact, version) {
		return "", false
	}
	groupPath := strings.ReplaceAll(group, ".", "/")
	return filepath.Join(groupPath, artifact, version, artifact+"-"+version+"."+ext), true
}

// splitCoordinate splits "groupId:artifactId" into its parts. ok is false unless
// both are non-empty and there is exactly one separator.
func splitCoordinate(coordinate string) (group, artifact string, ok bool) {
	parts := strings.Split(coordinate, ":")
	if len(parts) != 2 {
		return "", "", false
	}
	group, artifact = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if group == "" || artifact == "" {
		return "", "", false
	}
	return group, artifact, true
}

// validCacheSegment reports whether s can stand for one level of a cache path: it is
// non-empty and holds no path separator, no "..", and no NUL. Coordinates and versions come
// from the repository's own build files, so a crafted one ("../../planted/fake") must never
// steer a lookup out of the cache.
func validCacheSegment(s string) bool {
	return s != "" && s != "." && !strings.ContainsAny(s, "/\\\x00") && !strings.Contains(s, "..")
}

// validGAV reports whether a group, artifact and version are all valid cache segments.
func validGAV(group, artifact, version string) bool {
	return validCacheSegment(group) && validCacheSegment(artifact) && validCacheSegment(version)
}

// cacheLookup is the outcome of looking one relative path up under a cache root.
type cacheLookup int

const (
	cacheMiss   cacheLookup = iota // nothing is there, or only a directory
	cacheHit                       // a regular file whose real path stays inside the cache
	cacheEscape                    // the name resolves outside the cache, cannot be resolved or read, or is not a regular file
)

// missing reports whether err says nothing is at a path: no such name, or a non-directory
// where the path needs a directory. Any other failure (a permission, an I/O error) leaves the
// path's contents unknown, which is not the same as absent.
func missing(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// inCache looks rel up under root. A hit returns the file's real path: every symlink resolved,
// and under root's own real path, so a symlinked root is fine but a link out of the cache is
// not. What an escaping link points at is not the build's cached artifact. Only a name that is
// not there is a miss; one that cannot be looked at could be the artifact the build used.
func inCache(root, rel string) (string, cacheLookup) {
	if root == "" {
		return "", cacheMiss
	}
	candidate := filepath.Join(root, rel)
	if _, err := os.Lstat(candidate); err != nil {
		if missing(err) {
			return "", cacheMiss
		}
		return "", cacheEscape
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", cacheEscape
	}
	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", cacheEscape
	}
	if !within(realRoot, real) {
		return "", cacheEscape
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", cacheEscape
	}
	if info.IsDir() {
		return "", cacheMiss
	}
	if !info.Mode().IsRegular() {
		return "", cacheEscape // a FIFO or device: reading it could block, and it is no cached artifact
	}
	return real, cacheHit
}

// within reports whether path lies under base; both are already resolved.
func within(base, path string) bool {
	r, err := filepath.Rel(base, path)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}

// rootLeavesCheckout reports whether a cache root inside the build directory resolves outside
// it. A cache the checkout carries is trusted as the build's own; one it only links to is
// somewhere else's bytes. A root outside the build directory (the user's caches) is never
// judged here, and a root that is not there leaves nothing to judge.
func rootLeavesCheckout(buildDir, root string) bool {
	if !within(filepath.Clean(buildDir), filepath.Clean(root)) {
		return false
	}
	realBuild, err := filepath.EvalSymlinks(buildDir)
	if err != nil {
		return true
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return !missing(err)
	}
	return !within(realBuild, real)
}

// mavenRepoRoots returns the local Maven repository roots to search for a build, in
// priority order: a project-local ".m2/repository" under the build (a per-build
// cache, the zero-egress CI shape), then the user "~/.m2/repository". Non-existent
// roots are harmless: nothing is found in them.
func mavenRepoRoots(buildDir string) []string {
	var roots []string
	roots = append(roots, filepath.Join(buildDir, ".m2", "repository"))
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, ".m2", "repository"))
	}
	return roots
}

// jarLookup is the outcome of locating a dependency JAR across the local caches.
type jarLookup int

const (
	jarMissing      jarLookup = iota // no cache holds the JAR
	jarFound                         // every copy found holds the same bytes
	jarCopiesDiffer                  // two copies hold different bytes
	jarUnreadable                    // a copy cannot be read, resolves outside its cache, or the coordinate cannot name a cache path
)

// artifactJar is a located dependency JAR: its real path and the bytes read from it.
type artifactJar struct {
	path string
	data []byte
}

// locateArtifactJar finds a dependency JAR in the build's local caches. Both the Maven
// repositories and the Gradle module cache are searched whatever the build tool, since a
// Gradle build can read the Maven local repository (mavenLocal()) and nothing here says
// which copy it used. Only jarFound returns a JAR, with the bytes the copies were compared on,
// so the caller parses exactly what was checked: when copies differ, or one cannot be read or
// leaves its cache, any of them could be the bytes the build ran, so none is offered.
func locateArtifactJar(buildDir, coordinate, version string) (artifactJar, jarLookup) {
	return locateArtifact(buildDir, coordinate, version, "jar")
}

// locateArtifactPOM finds an artifact's POM in the build's local caches, under the same rules as
// locateArtifactJar.
func locateArtifactPOM(buildDir, coordinate, version string) (artifactJar, jarLookup) {
	return locateArtifact(buildDir, coordinate, version, "pom")
}

// locateArtifact is locateArtifactJar for the artifact file with extension ext.
func locateArtifact(buildDir, coordinate, version, ext string) (artifactJar, jarLookup) {
	rel, ok := mavenArtifactRelPath(coordinate, version, ext)
	if !ok {
		return artifactJar{}, jarUnreadable
	}
	group, artifact, _ := splitCoordinate(coordinate)
	var copies []string
	escaped := false
	for _, root := range mavenRepoRoots(buildDir) {
		if rootLeavesCheckout(buildDir, root) {
			escaped = true
			continue
		}
		switch p, st := inCache(root, rel); st {
		case cacheHit:
			copies = append(copies, p)
		case cacheEscape:
			escaped = true
		}
	}
	gradle, gradleEscaped := gradleArtifactCopies(buildDir, gradleCacheRoots(buildDir), group, artifact, version, ext)
	copies = append(copies, gradle...)
	if escaped || gradleEscaped {
		return artifactJar{}, jarUnreadable
	}
	if len(copies) == 0 {
		return artifactJar{}, jarMissing
	}
	var first []byte
	digests := make([][32]byte, len(copies))
	for i, c := range copies {
		data, err := readRegular(c)
		if err != nil {
			return artifactJar{}, jarUnreadable
		}
		if i == 0 {
			first = data
		}
		digests[i] = sha256.Sum256(data)
	}
	for _, d := range digests[1:] {
		if d != digests[0] {
			return artifactJar{}, jarCopiesDiffer
		}
	}
	return artifactJar{path: copies[0], data: first}, jarFound
}

// gradleArtifactCopies lists every copy of the artifact file with extension ext in the Gradle
// module cache layout:
//
//	<cache>/<group>/<artifact>/<version>/<sha1>/<artifact>-<version>.<ext>
//
// Gradle keeps the group dotted and interposes a content-hash directory, so every child of
// the version directory is checked, in sorted order. escaped is true when any copy resolves
// outside its cache root or cannot be read, when a version directory cannot be listed, or when
// a cache root inside the build directory resolves outside it.
func gradleArtifactCopies(buildDir string, roots []string, group, artifact, version, ext string) (copies []string, escaped bool) {
	jar := artifact + "-" + version + "." + ext
	for _, root := range roots {
		if rootLeavesCheckout(buildDir, root) {
			escaped = true
			continue
		}
		hashDirs, err := os.ReadDir(filepath.Join(root, group, artifact, version))
		if err != nil {
			if !missing(err) {
				escaped = true
			}
			continue
		}
		for _, hd := range hashDirs {
			switch p, st := inCache(root, filepath.Join(group, artifact, version, hd.Name(), jar)); st {
			case cacheHit:
				copies = append(copies, p)
			case cacheEscape:
				escaped = true
			}
		}
	}
	return copies, escaped
}

// readRegular reads a file it has checked, on the open descriptor, to be a regular file. The
// open does not block on a FIFO, and what is read is what was checked.
func readRegular(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	return io.ReadAll(f)
}

// gradleCacheRoots returns the Gradle module-cache roots to search, in priority order: a
// project-local .gradle cache, a project-local GRADLE_USER_HOME ("caches" under the build),
// then the user ~/.gradle.
func gradleCacheRoots(buildDir string) []string {
	roots := []string{
		filepath.Join(buildDir, ".gradle", "caches", "modules-2", "files-2.1"),
		filepath.Join(buildDir, "caches", "modules-2", "files-2.1"),
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, ".gradle", "caches", "modules-2", "files-2.1"))
	}
	return roots
}
