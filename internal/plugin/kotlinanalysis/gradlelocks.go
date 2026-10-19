package kotlinanalysis

import (
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
)

// gradlelocks.go — which version of a dependency the application runs with, read from the
// Gradle lockfile. A lockfile locks every resolvable configuration, so one group:artifact can be
// locked at one version for kapt or a test classpath and another for runtimeClasspath; the
// shared inventory keeps a single version per group:artifact for its node set and does not say
// which. Only runtimeClasspath selects the bytes the application is launched with (and Spring
// Boot's productionRuntimeClasspath, which bootJar packages): kapt*, annotationProcessor, ksp*,
// test* and compile-only configurations never reach it.

// gradleRuntimeConfigs are the configurations whose locked versions the application runs. A
// coordinate the two lock at different versions has no single runtime version.
var gradleRuntimeConfigs = map[string]bool{"runtimeClasspath": true, "productionRuntimeClasspath": true}

// runtimeLocks is a build's lockfile selection.
type runtimeLocks struct {
	// locked holds every "group:artifact" locked in any configuration.
	locked map[string]bool
	// runtime maps "group:artifact" to each version, as written, it is locked at in a
	// gradleRuntimeConfigs configuration.
	runtime map[string]map[string]bool
}

// readRuntimeLocks reads the build's lockfiles; ok is false when there are none.
func readRuntimeLocks(buildDir string) (runtimeLocks, bool) {
	entries, ok := javaanalysis.GradleLockEntries(buildDir)
	if !ok {
		return runtimeLocks{}, false
	}
	rl := runtimeLocks{locked: map[string]bool{}, runtime: map[string]map[string]bool{}}
	for _, e := range entries {
		ga := e.Group + ":" + e.Artifact
		rl.locked[ga] = true
		for _, c := range e.Configs {
			if !gradleRuntimeConfigs[c] {
				continue
			}
			if rl.runtime[ga] == nil {
				rl.runtime[ga] = map[string]bool{}
			}
			rl.runtime[ga][e.Version] = true
		}
	}
	return rl, true
}

// selection is the runtime version of a locked coordinate. onRuntime is false when the
// coordinate is locked only in configurations the application does not run with. Otherwise
// version is the single concrete version the runtime configurations lock, or "" when they
// lock more than one or one that is not concrete; detail then names what they lock.
func (rl runtimeLocks) selection(coordinate string) (version, detail string, onRuntime bool) {
	versions, onRuntime := rl.runtime[coordinate]
	if !onRuntime {
		return "", "", false
	}
	vs := sortedKeys(versions)
	if len(vs) == 1 && concreteVersion(vs[0]) {
		return vs[0], "", true
	}
	shown := make([]string, len(vs))
	for i, v := range vs {
		shown[i] = v
		if v == "" {
			shown[i] = "(no version)"
		}
	}
	return "", coordinate + ": runtime classpaths lock " + strings.Join(shown, ", "), true
}

// concreteVersion reports whether a locked version names exactly one artifact: not empty, not a
// dynamic selector (1.+, latest.release), a range ([1.0,2.0)) or an interpolation.
func concreteVersion(v string) bool {
	return v != "" && !strings.ContainsAny(v, "+[]()$,") && !strings.HasPrefix(v, "latest.")
}
