package kotlinanalysis

import (
	"crypto/sha256"
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

// LocateDependencyJar searches the build's local caches — Gradle (the Kotlin common case) and
// Maven `.m2` — for the artifact's JAR at exactly this version. ok is false when the JAR is
// absent from every cache (the caller declares a hazard, it does not fetch), when the
// coordinate/version is malformed, or when the caches hold copies of it whose bytes differ, in
// one cache or across both: the bytes the build used are then unknown, and analysing either
// copy could trace code that never ran.
func LocateDependencyJar(buildDir, coordinate, version string) (string, bool) {
	group, artifact, ok := splitCoordinate(coordinate)
	if !ok || version == "" {
		return "", false
	}
	hits := locateGradleJars(gradleCacheRoots(buildDir), group, artifact, version)
	hits = append(hits, locateMavenJars(mavenRepoRoots(buildDir), group, artifact, version)...)
	if len(hits) == 0 {
		return "", false
	}
	return hits[0], sameBytes(hits)
}

// locateMavenJars resolves the Maven local-repository layout in every root:
//
//	<group as path>/<artifact>/<version>/<artifact>-<version>.jar
func locateMavenJars(roots []string, group, artifact, version string) []string {
	rel := filepath.Join(strings.ReplaceAll(group, ".", "/"), artifact, version, artifact+"-"+version+".jar")
	var out []string
	for _, root := range roots {
		if root == "" {
			continue
		}
		if candidate := filepath.Join(root, rel); fileExists(candidate) {
			out = append(out, candidate)
		}
	}
	return out
}

// locateGradleJars resolves the Gradle module cache layout in every root:
//
//	<cache>/<group>/<artifact>/<version>/<sha1>/<artifact>-<version>.jar
//
// Gradle keeps the group DOTTED (not slash-pathed) and interposes a content-hash
// directory whose name is unpredictable, so the version directory is scanned for the hash
// subdirs carrying the expected JAR. The scan is bounded (one version dir, its immediate
// hash children) and reads only local metadata.
func locateGradleJars(roots []string, group, artifact, version string) []string {
	jar := artifact + "-" + version + ".jar"
	var out []string
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
			if candidate := filepath.Join(versionDir, hd.Name(), jar); fileExists(candidate) {
				out = append(out, candidate)
			}
		}
	}
	return out
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

// sameBytes reports whether every file in paths has identical content. A coordinate cached
// twice with different bytes (two content-hash directories, or two repository roots) leaves
// which copy the build used unknown.
func sameBytes(paths []string) bool {
	if len(paths) == 0 {
		return false
	}
	var first [sha256.Size]byte
	for i, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return false
		}
		sum := sha256.Sum256(data)
		if i == 0 {
			first = sum
		} else if sum != first {
			return false
		}
	}
	return true
}
