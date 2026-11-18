package goanalysis

import (
	"context"
	"slices"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// resultPerModule is resultFromGraph for an advisory govulncheck matched to several of the build's
// modules. resultFromGraph refutes the first module in path order. Each other module is then judged
// the same way on its own findings, and a refutation that survives every withhold joins
// Refutations. A module whose refutation is withheld is absent from it, and what the result declares
// stays what the first module's judgement declared.
func resultPerModule(ctx context.Context, scanned vulnScan, g reconcileGraph, buildDir string, env []string, load func() (*LoadResult, error), entry plugin.LibraryEntrypoints) (plugin.ReachabilityResult, error) {
	res, err := resultFromGraph(ctx, scanned, g, buildDir, env, load, entry)
	if err != nil {
		return res, err
	}
	modules := findingModules(scanned.findings)
	// A symbol finding in any module is a path or an unknown: no module of the advisory is refuted.
	if len(modules) < 2 || len(findingsToStacks(scanned.findings)) > 0 {
		return res, nil
	}
	for _, module := range modules[1:] {
		one := scanned
		one.findings = slices.DeleteFunc(slices.Clone(scanned.findings), func(f vulnFinding) bool {
			return len(f.Trace) == 0 || f.Trace[0].Module != module
		})
		other, err := resultFromGraph(ctx, one, g, buildDir, env, load, entry)
		if err != nil {
			return plugin.ReachabilityResult{}, err
		}
		if other.Refutation != nil {
			res.Refutations = append(res.Refutations, *other.Refutation)
		}
	}
	return res, nil
}

// findingModules returns the modules the findings name, in path order: the first is the one
// moduleRefutation refutes.
func findingModules(findings []vulnFinding) []string {
	var modules []string
	for _, f := range findings {
		if len(f.Trace) > 0 && f.Trace[0].Module != "" && !slices.Contains(modules, f.Trace[0].Module) {
			modules = append(modules, f.Trace[0].Module)
		}
	}
	slices.Sort(modules)
	return modules
}
