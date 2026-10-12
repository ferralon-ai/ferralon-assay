package javaanalysis

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// reasonMultipleProjectsUnsupported marks a build with more than one Maven module or Gradle
// project with code. The dependency-JAR analysis binds one module's view of the dependency
// graph; with several modules that view does not stand for the build, so the result is
// partial run-wide and no sink is ever reported Searched for it.
const reasonMultipleProjectsUnsupported = "multiple_projects_unsupported"

// multipleProjects reports whether buildDir holds more than one project: a POM that lists
// <modules>, more than one pom.xml, or more than one Gradle build script that sits beside a
// src directory. why names the evidence, for the partiality path.
func multipleProjects(buildDir string) (multi bool, why string) {
	poms := findPOMs(buildDir)
	for _, p := range poms {
		if pom, ok := parseMavenPOM(p); ok && len(pom.Modules) > 0 {
			return true, relSlash(buildDir, p) + " lists modules"
		}
	}
	if len(poms) > 1 {
		return true, relSlash(buildDir, poms[0]) + ", " + relSlash(buildDir, poms[1])
	}

	var gradle []string
	_ = filepath.WalkDir(buildDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree holds no project we can see
		}
		if d.IsDir() {
			if path != buildDir && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch d.Name() {
		case "build.gradle", "build.gradle.kts":
			if info, err := os.Stat(filepath.Join(filepath.Dir(path), "src")); err == nil && info.IsDir() {
				gradle = append(gradle, path)
			}
		}
		return nil
	})
	if len(gradle) > 1 {
		sort.Strings(gradle)
		return true, relSlash(buildDir, gradle[0]) + ", " + relSlash(buildDir, gradle[1])
	}
	return false, ""
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
