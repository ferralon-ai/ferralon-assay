package javaanalysis

import (
	"path/filepath"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// reasonMultipleProjectsUnsupported marks a build with more than one Maven module or Gradle
// project with code that the per-unit search (units.go) cannot place. The dependency-JAR
// analysis binds one module's view of the dependency graph; with modules no unit accounts for,
// no view stands for the build, so the result is partial run-wide and no sink is ever reported
// Searched for it.
const reasonMultipleProjectsUnsupported = "multiple_projects_unsupported"

// multipleProjects reports whether the build graph holds more than one module with code of its
// own (multipleModules) and the reactor cannot be searched one application unit at a time
// (reactorUnits). Without a graph it reports none: every op already declares
// build_graph_absent, which withholds Searched by itself. why names the modules and what could
// not be placed, for the partiality path.
func multipleProjects(buildDir string, opts ...Option) (multi bool, why string) {
	_, multi, why = reactorUnits(buildDir, opts...)
	return multi, why
}

// withMultipleProjects adds the run-wide multiple_projects_unsupported reason to p, with an
// unbounded scoped copy that carries the evidence.
func withMultipleProjects(p plugin.Partiality, why string) plugin.Partiality {
	out := plugin.Partiality{Complete: false, Scoped: append([]plugin.ScopedReason{}, p.Scoped...)}
	out.Reasons = append(append([]string{}, p.Reasons...), reasonMultipleProjectsUnsupported)
	out.Scoped = append(out.Scoped, plugin.ScopedReason{Reason: reasonMultipleProjectsUnsupported, Path: why})
	return out
}

func relSlash(base, path string) string {
	if r, err := filepath.Rel(base, path); err == nil {
		return filepath.ToSlash(r)
	}
	return path
}
