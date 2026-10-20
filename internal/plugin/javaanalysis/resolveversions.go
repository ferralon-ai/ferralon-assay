package javaanalysis

import (
	"context"
	"fmt"
	"os"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveDependencyVersions answers the advisory's coordinate from the build graph: every version
// the build resolved for it, Match resolved only when they agree (graphVersions). It never
// guesses (inv.5): without a graph the coordinate is Found and unresolved, and the pipeline fails
// open on it. A missing or unreadable build dir is a hard error (inv.4).
//
// Precedence across scopes is deliberate: the graph carries the version each module resolved in
// each scope, and every one of them is a Match candidate. Gradle mediates per configuration and
// Maven once across scopes, so a module's runtime version is the one that runs whichever tool
// resolved it; requiring agreement across all of them is the same rule for both.
func ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest, opts ...Option) (plugin.DependencyVersionResult, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyVersionResult{}, fmt.Errorf("javaanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyVersionResult{}, fmt.Errorf("javaanalysis: build dir %q is not a directory", req.BuildDir)
	}
	g := BuildGraph(opts...)
	if g == nil {
		return absentVersions(req.Coordinate), nil
	}
	return graphVersions(g, req.Coordinate, OtherToolBuild(g, req.BuildDir)), nil
}
