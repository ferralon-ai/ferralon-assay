package kotlinanalysis

import (
	"os"
	"path/filepath"
	"strings"
)

// depcache.go — locate a resolved dependency's JAR in the build's LOCAL artifact caches.
// Zero-egress by construction: it reads caches the build already populated and never
// fetches. A coordinate whose JAR is absent is a declared miss (ok=false) the caller turns
// into a completeness hazard — never a silent "the dependency has no code".
//
// GRADLE DECISION (R2 substrate gap): javaanalysis.depcache locates JARs only under Maven
// `.m2/repository`, which no Gradle/Kotlin-DSL build populates. Because Kotlin projects are
// predominantly Gradle, this package ADDS a sound Gradle module-cache locator here rather
// than declaring Gradle dependency resolution a partiality. Both layouts are read
// purely-locally; the Gradle path globs the content-hash subdirectory Gradle interposes.
// This is a LOCATOR only: it resolves a JAR GIVEN a coordinate+version. Deriving the
// version from build.gradle.kts is a separate, deferred concern (declared partiality) —
// see the capability manifest.

// splitCoordinate splits "groupId:artifactId" into its parts. ok is false unless both are
// non-empty and there is exactly one separator.
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

// LocateDependencyJar searches the build's local caches — Gradle first (the Kotlin common
// case), then Maven `.m2` — for the artifact's JAR, returning the first existing path. ok
// is false when the JAR is absent from every cache (the caller declares a hazard, it does
// not fetch) or when the coordinate/version is malformed.
func LocateDependencyJar(buildDir, coordinate, version string) (string, bool) {
	group, artifact, ok := splitCoordinate(coordinate)
	if !ok || version == "" {
		return "", false
	}
	if path, ok := locateGradleJar(gradleCacheRoots(buildDir), group, artifact, version); ok {
		return path, true
	}
	return locateMavenJar(mavenRepoRoots(buildDir), group, artifact, version)
}

// locateMavenJar resolves the Maven local-repository layout:
//
//	<group as path>/<artifact>/<version>/<artifact>-<version>.jar
func locateMavenJar(roots []string, group, artifact, version string) (string, bool) {
	rel := filepath.Join(strings.ReplaceAll(group, ".", "/"), artifact, version, artifact+"-"+version+".jar")
	for _, root := range roots {
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

// locateGradleJar resolves the Gradle module cache layout:
//
//	<cache>/<group>/<artifact>/<version>/<sha1>/<artifact>-<version>.jar
//
// Gradle keeps the group DOTTED (not slash-pathed) and interposes a content-hash
// directory whose name is unpredictable, so the version directory is scanned for the hash
// subdir carrying the expected JAR. The scan is bounded (one version dir, its immediate
// hash children) and reads only local metadata.
func locateGradleJar(roots []string, group, artifact, version string) (string, bool) {
	jar := artifact + "-" + version + ".jar"
	for _, root := range roots {
		if root == "" {
			continue
		}
		versionDir := filepath.Join(root, group, artifact, version)
		hashDirs, err := os.ReadDir(versionDir)
		if err != nil {
			continue
		}
		for _, hd := range hashDirs {
			if !hd.IsDir() {
				continue
			}
			candidate := filepath.Join(versionDir, hd.Name(), jar)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, true
			}
		}
	}
	return "", false
}

// mavenRepoRoots returns the local Maven repository roots to search, in priority order: a
// project-local `.m2/repository` under the build (the per-build, zero-egress CI cache),
// then the user `~/.m2/repository`. Non-existent roots are harmless.
func mavenRepoRoots(buildDir string) []string {
	roots := []string{filepath.Join(buildDir, ".m2", "repository")}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, ".m2", "repository"))
	}
	return roots
}

// gradleCacheRoots returns the Gradle module-cache roots to search, in priority order: a
// project-local `.gradle` cache under the build, a project-local `caches` (a
// GRADLE_USER_HOME pointed into the build for a hermetic CI cache), then the user
// `~/.gradle`. Each is suffixed with the module-cache subpath Gradle uses.
func gradleCacheRoots(buildDir string) []string {
	const moduleSub = "caches/modules-2/files-2.1"
	roots := []string{
		filepath.Join(buildDir, ".gradle", "caches", "modules-2", "files-2.1"),
		filepath.Join(buildDir, "caches", "modules-2", "files-2.1"),
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, ".gradle", filepath.FromSlash(moduleSub)))
	}
	return roots
}
