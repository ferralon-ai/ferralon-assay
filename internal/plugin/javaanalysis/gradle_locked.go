package javaanalysis

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// gradleFedConfigs maps each configuration a SAFE declaration may name (gradleSafeConfigs) to
// the resolvable configurations it feeds under the core plugins, the pre-Gradle-7 ones included.
// The SAFE set admits no configurations block, no extendsFrom and no plugin outside
// gradleCorePlugins, so a dependency, transitive ones included, reaches a resolvable
// configuration only through a declaration on one of these.
var gradleFedConfigs = map[string][]string{
	"implementation":          {"compileClasspath", "runtimeClasspath", "testCompileClasspath", "testRuntimeClasspath"},
	"api":                     {"compileClasspath", "runtimeClasspath", "testCompileClasspath", "testRuntimeClasspath"},
	"compileOnly":             {"compileClasspath"},
	"compileOnlyApi":          {"compileClasspath", "testCompileClasspath"},
	"runtimeOnly":             {"runtimeClasspath", "testRuntimeClasspath"},
	"annotationProcessor":     {"annotationProcessor"},
	"testImplementation":      {"testCompileClasspath", "testRuntimeClasspath"},
	"testCompileOnly":         {"testCompileClasspath"},
	"testRuntimeOnly":         {"testRuntimeClasspath"},
	"testAnnotationProcessor": {"testAnnotationProcessor"},
	"compile":                 {"compile", "runtime", "testCompile", "testRuntime", "default", "compileClasspath", "runtimeClasspath", "testCompileClasspath", "testRuntimeClasspath"},
	"runtime":                 {"runtime", "testRuntime", "default", "runtimeClasspath", "testRuntimeClasspath"},
	"testCompile":             {"testCompile", "testRuntime", "testCompileClasspath", "testRuntimeClasspath"},
	"testRuntime":             {"testRuntime", "testRuntimeClasspath"},
}

// gradleConfigWord matches a gradleFedConfigs key as a whole word.
var gradleConfigWord = func() *regexp.Regexp {
	names := make([]string, 0, len(gradleFedConfigs))
	for n := range gradleFedConfigs {
		names = append(names, n)
	}
	sort.Strings(names)
	return regexp.MustCompile(`\b(` + strings.Join(names, "|") + `)\b`)
}()

// gradleResolvableConfigs returns every resolvable configuration a declaration in the
// comment-stripped sources can feed. It over-approximates: a declarable configuration's name
// anywhere as a word counts, in a string or another project's block alike.
func gradleResolvableConfigs(srcs []string) []string {
	set := map[string]bool{}
	for _, src := range srcs {
		for _, name := range gradleConfigWord.FindAllString(src, -1) {
			for _, c := range gradleFedConfigs[name] {
				set[c] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// gradleLockedVersions returns every version of coordinate ("group:name") that a lock under
// root holds, across every Gradle project and configuration. complete is true only when those
// are the versions Gradle can resolve it to: the build is SAFE (gradleBuildSafe), every lock
// line parses, every project the settings script creates is read, in each of them every
// configuration a declaration can feed (gradleResolvableConfigs) is pinned by lock state read
// for it that Gradle enforces (gradleLockingEnforced, gradleConfigPinned), and the inventory's
// predicate (gradleLockConfirmation) finds no project whose resolution is unknown. A pinned configuration
// resolves only to what its lock state holds, or fails, so a version the locks lack is never
// resolved. A version in deps binds only when complete; why names the first reason it is not.
func gradleLockedVersions(root, coordinate string) (deps []plugin.ResolvedDependency, complete bool, why string) {
	locked, complete, why := gradleLockBinding(root)
	want := normalizeCoordinate(coordinate)
	for _, v := range locked[want] {
		deps = append(deps, plugin.ResolvedDependency{Coordinate: want, Version: v, Resolved: true, Source: "gradle"})
	}
	return deps, complete, why
}

// gradleLockBinding reads every lock under root once for gradleLockedVersions: each locked
// coordinate (normalized) to its sorted versions, and whether and why not those bind. The lock
// state comes from readLockfiles, which reports a project directory its walk didn't list as
// unread. The locks speak only for the projects the root settings script creates, so a Gradle
// build script anywhere else, or a directory whose scripts can't be enumerated, leaves them
// unbound (gradleScriptOutsideSet). gradleProjectsPinned also refuses a STRICT project with no
// lock state read, which gradleConfigPinned alone would count as pinned.
func gradleLockBinding(root string) (map[string][]string, bool, string) {
	locked, _, haveLock, unparsed, state := readLockfiles(root)
	versions := map[string][]string{}
	for _, e := range locked {
		ga := normalizeCoordinate(e.ga())
		versions[ga] = mergeReasons(versions[ga], e.version)
	}
	for _, vs := range versions {
		sort.Strings(vs)
	}
	if !haveLock {
		return versions, false, "no lock state"
	}
	if len(unparsed) > 0 {
		return versions, false, unparsed[0] + " can't be read as lock state"
	}
	if _, unknown := gradleLockConfirmation(root, locked, state); unknown != "" {
		return versions, false, unknown // gradleBuildSafe first among its reasons
	}
	projects, ok := gradleProjects(root)
	if !ok {
		return versions, false, "the settings script can't be read in full"
	}
	if why := gradleScriptOutsideSet(root, projects); why != "" {
		return versions, false, why
	}
	rootSrcs, ok := readGradleSources(gradleScriptsIn(root))
	if !ok {
		return versions, false, "the root build script can't be read"
	}
	if why, ok := gradleProjectsPinned(root, projects, rootSrcs, state); !ok {
		return versions, false, why
	}
	return versions, true, ""
}

// gradleScriptOutsideSet names the first reason the build's locks don't speak for every Gradle
// declaration ResolveDependencyVersions reads: a build script in a directory outside the project
// set (a nested build with its own settings, an unincluded directory, the target of a symlinked
// project directory), or a directory under root the walk can't list, which could hold one.
// Directories buildFiles skips are skipped here too, since no declaration is read from them.
func gradleScriptOutsideSet(root string, projects map[string]bool) string {
	var why string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			why = relToBase(root, path) + " can't be listed"
			return filepath.SkipAll
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if (d.Name() == "build.gradle" || d.Name() == "build.gradle.kts") && !projects[filepath.Dir(path)] {
			why = relToBase(root, path) + " is a build script outside the settings' project set"
			return filepath.SkipAll
		}
		return nil
	})
	return why
}

// gradleProjectsPinned reports whether, in every project, each configuration a declaration can
// feed is pinned by a lock Gradle enforces, from lock state that was read. A project script it
// can't read fails it on its own: gradleBuildSafe reads the same scripts first, but this check
// doesn't lean on that.
func gradleProjectsPinned(root string, projects map[string]bool, rootSrcs []string, state map[string]*gradleProjectLock) (string, bool) {
	dirs := make([]string, 0, len(projects))
	for dir := range projects {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		own, inherited := rootSrcs, []string(nil)
		if dir != filepath.Clean(root) {
			var ok bool
			if own, ok = readGradleSources(gradleScriptsIn(dir)); !ok {
				return relToBase(root, dir) + "'s build script can't be read", false
			}
			inherited = rootSrcs
		}
		confs := gradleResolvableConfigs(append(append([]string{}, own...), inherited...))
		if len(confs) == 0 {
			continue
		}
		enforced, strict := gradleLockingEnforced(own, inherited)
		if !enforced {
			return relToBase(root, dir) + " does not lock every configuration", false
		}
		if strict && state[dir] == nil {
			// gradleConfigPinned counts STRICT with no lock state as pinned, since Gradle fails
			// a project with none. readLockfiles already reports a project directory it couldn't
			// list, so this is a listed project holding no lock: its build fails, and no version
			// read for it is one the build produced.
			return relToBase(root, dir) + " is STRICT and no lock was read for it", false
		}
		for _, c := range confs {
			if !gradleConfigPinned(dir, state[dir], strict, c) {
				return relToBase(root, dir) + "'s " + c + " is not pinned by its lock", false
			}
		}
	}
	return "", true
}
