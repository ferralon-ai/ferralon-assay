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
// that is not "groupId:artifactId" or an empty version — a malformed input never
// yields a path that could accidentally match an unrelated file.
func mavenJarRelPath(coordinate, version string) (string, bool) {
	group, artifact, ok := splitCoordinate(coordinate)
	if !ok || version == "" {
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

// LocateDependencyJar searches the given local Maven repository roots for the
// artifact's JAR and returns the first existing path. ok is false when the JAR is
// absent from every root (the caller declares a completeness hazard, it does not
// fetch) or when the coordinate/version is malformed.
func LocateDependencyJar(repoRoots []string, coordinate, version string) (string, bool) {
	rel, ok := mavenJarRelPath(coordinate, version)
	if !ok {
		return "", false
	}
	for _, root := range repoRoots {
		if root == "" {
			continue
		}
		candidate := filepath.Join(root, rel)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
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

// locateArtifactJar finds a dependency JAR in the build's local caches. Both the Maven
// repositories and the Gradle module cache are searched whatever the build tool, since a
// Gradle build can read the Maven local repository (mavenLocal()) and nothing here says
// which copy it used. ok is false when no cache holds the JAR. ambiguous is true when two
// copies differ, or one cannot be read to compare: either could be the bytes the build ran,
// so neither is offered.
func locateArtifactJar(buildDir, coordinate, version string) (path string, ok, ambiguous bool) {
	rel, ok := mavenJarRelPath(coordinate, version)
	if !ok {
		return "", false, false
	}
	group, artifact, _ := splitCoordinate(coordinate)
	var copies []string
	for _, root := range mavenRepoRoots(buildDir) {
		if candidate := filepath.Join(root, rel); isFile(candidate) {
			copies = append(copies, candidate)
		}
	}
	copies = append(copies, gradleJarCopies(gradleCacheRoots(buildDir), group, artifact, version)...)
	switch len(copies) {
	case 0:
		return "", false, false
	case 1:
		return copies[0], true, false
	}
	want, err := fileDigest(copies[0])
	if err != nil {
		return "", false, true
	}
	for _, c := range copies[1:] {
		if got, err := fileDigest(c); err != nil || got != want {
			return "", false, true
		}
	}
	return copies[0], true, false
}

// gradleJarCopies lists every copy of the JAR in the Gradle module cache layout:
//
//	<cache>/<group>/<artifact>/<version>/<sha1>/<artifact>-<version>.jar
//
// Gradle keeps the group dotted and interposes a content-hash directory, so every child of
// the version directory is checked, in sorted order.
func gradleJarCopies(roots []string, group, artifact, version string) []string {
	jar := artifact + "-" + version + ".jar"
	var out []string
	for _, root := range roots {
		versionDir := filepath.Join(root, group, artifact, version)
		hashDirs, err := os.ReadDir(versionDir)
		if err != nil {
			continue
		}
		for _, hd := range hashDirs {
			if candidate := filepath.Join(versionDir, hd.Name(), jar); hd.IsDir() && isFile(candidate) {
				out = append(out, candidate)
			}
		}
	}
	return out
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
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
