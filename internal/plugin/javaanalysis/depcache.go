package javaanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	group, artifact, ok := splitCoordinate(coordinate)
	if !ok || !validGAV(group, artifact, version) {
		return "", false
	}
	groupPath := strings.ReplaceAll(group, ".", "/")
	jar := artifact + "-" + version + ".jar"
	return filepath.Join(groupPath, artifact, version, jar), true
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
	cacheEscape                    // the name exists but resolves outside the cache, or cannot be resolved
)

// inCache looks rel up under root. A hit returns the file's real path: every symlink resolved,
// and under root's own real path, so a symlinked root is fine but a link out of the cache is
// not. What an escaping link points at is not the build's cached artifact.
func inCache(root, rel string) (string, cacheLookup) {
	if root == "" {
		return "", cacheMiss
	}
	candidate := filepath.Join(root, rel)
	if _, err := os.Lstat(candidate); err != nil {
		return "", cacheMiss
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", cacheEscape
	}
	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", cacheEscape
	}
	if r, err := filepath.Rel(realRoot, real); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", cacheEscape
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", cacheEscape
	}
	if info.IsDir() {
		return "", cacheMiss
	}
	return real, cacheHit
}

// LocateDependencyJar searches the given local Maven repository roots for the
// artifact's JAR and returns the first one found, by its real path. ok is false when the
// JAR is absent from every root (the caller declares a completeness hazard, it does not
// fetch), when the coordinate/version is malformed, or when the first copy found resolves
// outside its root.
func LocateDependencyJar(repoRoots []string, coordinate, version string) (string, bool) {
	rel, ok := mavenJarRelPath(coordinate, version)
	if !ok {
		return "", false
	}
	for _, root := range repoRoots {
		switch p, st := inCache(root, rel); st {
		case cacheHit:
			return p, true
		case cacheEscape:
			return "", false
		}
	}
	return "", false
}

// mavenRepoRoots returns the local Maven repository roots to search for a build, in
// priority order: a project-local ".m2/repository" under the build (a per-build
// cache, the zero-egress CI shape), then the user "~/.m2/repository". Non-existent
// roots are harmless — LocateDependencyJar simply finds nothing in them.
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

// locateArtifactJar finds a dependency JAR in the build's local caches. Both the Maven
// repositories and the Gradle module cache are searched whatever the build tool, since a
// Gradle build can read the Maven local repository (mavenLocal()) and nothing here says
// which copy it used. Only jarFound returns a path: when copies differ, or one cannot be read
// or leaves its cache, any of them could be the bytes the build ran, so none is offered.
func locateArtifactJar(buildDir, coordinate, version string) (string, jarLookup) {
	rel, ok := mavenJarRelPath(coordinate, version)
	if !ok {
		return "", jarUnreadable
	}
	group, artifact, _ := splitCoordinate(coordinate)
	var copies []string
	escaped := false
	for _, root := range mavenRepoRoots(buildDir) {
		switch p, st := inCache(root, rel); st {
		case cacheHit:
			copies = append(copies, p)
		case cacheEscape:
			escaped = true
		}
	}
	gradle, gradleEscaped := gradleJarCopies(gradleCacheRoots(buildDir), group, artifact, version)
	copies = append(copies, gradle...)
	if escaped || gradleEscaped {
		return "", jarUnreadable
	}
	if len(copies) == 0 {
		return "", jarMissing
	}
	digests := make([]string, len(copies))
	for i, c := range copies {
		d, err := fileDigest(c)
		if err != nil {
			return "", jarUnreadable
		}
		digests[i] = d
	}
	for _, d := range digests[1:] {
		if d != digests[0] {
			return "", jarCopiesDiffer
		}
	}
	return copies[0], jarFound
}

// gradleJarCopies lists every copy of the JAR in the Gradle module cache layout:
//
//	<cache>/<group>/<artifact>/<version>/<sha1>/<artifact>-<version>.jar
//
// Gradle keeps the group dotted and interposes a content-hash directory, so every child of
// the version directory is checked, in sorted order. escaped is true when any copy resolves
// outside its cache root.
func gradleJarCopies(roots []string, group, artifact, version string) (copies []string, escaped bool) {
	jar := artifact + "-" + version + ".jar"
	for _, root := range roots {
		hashDirs, err := os.ReadDir(filepath.Join(root, group, artifact, version))
		if err != nil {
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

// fileDigest returns the SHA-256 of a file's contents.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
