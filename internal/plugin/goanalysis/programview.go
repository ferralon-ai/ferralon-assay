package goanalysis

import (
	"context"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// notShippedElements are the path elements below the module path that put a main package outside the
// build's shipped programs: examples and tests are run by hand or by the test suite, never shipped.
// Unlike autoExcludedElements, cmd is not one: a program under cmd is the usual shipped binary.
var notShippedElements = []string{"example", "examples", "test", "tests", "testdata"}

// programStream runs govulncheck over the shipped mains for the program view; a test swaps it.
var programStream = govulncheckStream

// shippedMains returns the main packages of pkgs that the build ships: a main package with compiled
// files, in a main module of the build, with no path element in notShippedElements below its module.
func shippedMains(pkgs []*packages.Package) []*packages.Package {
	var mains []*packages.Package
	for _, p := range pkgs {
		if !isMain(p) || p.Module == nil || !p.Module.Main {
			continue
		}
		rel := strings.TrimPrefix(p.PkgPath, p.Module.Path)
		if slices.ContainsFunc(strings.Split(rel, "/"), func(el string) bool { return slices.Contains(notShippedElements, el) }) {
			continue
		}
		mains = append(mains, p)
	}
	slices.SortFunc(mains, func(a, b *packages.Package) int { return strings.Compare(a.PkgPath, b.PkgPath) })
	return mains
}

// programView is the program view of one advisory: the same search as the library view, started only
// from the build's shipped programs, so a caller that imports the build's packages does not count.
// It answers only when the library view holds no refutation (res), because that view's refutation
// already stands for every caller; and only for a library view that has something for the program
// view to rule out: a refutation the library-entry checks withheld, or a path (evidence is the
// library view's result before those checks). The library view's result is never read to change it.
//
// The view is a refutation only when govulncheck, run over the shipped mains alone, finds the module
// and no call to its vulnerable functions, and every check that does not depend on who imports the
// build still passes, for each module the advisory was matched to (programRulesOut): the load is complete and its cgo state known, no file the build left out may
// call into the module, no call reflection makes may reach it, and the run declares no limit that says
// a step did not run (programRunPartial). The library-entry checks (withholdForLibraryEscape,
// withholdForUnsearchedMethods) are what the view leaves out, and the scope it reports says so. Any
// step that cannot be completed leaves the view empty: it never concludes from what it did not run.
func programView(ctx context.Context, res, evidence plugin.ReachabilityResult, scanned vulnScan, g reconcileGraph, buildDir string, env []string, load func() (*LoadResult, error)) *plugin.ProgramView {
	if res.Refutation != nil || scanned.partial != nil || scanned.vulnID == "" || len(scanned.findings) == 0 ||
		evidence.Refutation == nil && len(evidence.Paths) == 0 {
		return nil
	}
	library := moduleRefutation(scanned.findings, env)
	if library == nil {
		return nil
	}
	loaded, err := load()
	if err != nil || loaded.cgoUnresolved || incompleteLoad(loaded.Packages, nil) {
		return nil
	}
	mains := shippedMains(loaded.Packages)
	if len(mains) == 0 || !singleModule(mains) {
		return nil
	}
	patterns := make([]string, len(mains))
	for i, m := range mains {
		patterns[i] = m.PkgPath
	}
	if tracedFromMain(scanned.findings, patterns) {
		return nil
	}
	out, err := runCached(ctx, "govulncheck-programs", append(append([]string{buildDir}, env...), patterns...), func() ([]byte, error) {
		return programStream(ctx, buildDir, env, patterns)
	})
	if err != nil {
		return nil
	}
	prog, err := parseFindings(out, scanned.vulnID)
	if err != nil {
		return nil
	}
	ruled := evidenceResult(prog.findings, g.CallGraph, env)
	if ruled.Refutation == nil || len(ruled.Paths) > 0 || ruled.Refutation.Package != library.Package ||
		programRunPartial(ruled.Partiality, ruled.Refutation.Package) {
		return nil
	}
	ruled = withholdForLeftOutFiles(ctx, ruled, scanned, loaded.Packages, loaded.buildRelease(), buildDir, env)
	ruled = withholdForReflectReach(ruled, scanned, g.ReflectReach)
	if ruled.Refutation == nil {
		return nil
	}
	// The run found no call into any module, but the refutation names the first alone; every other
	// module the advisory was matched to is ruled out by the same checks, or the view is empty.
	for _, m := range findingModules(slices.Concat(scanned.findings, prog.findings)) {
		if other := "pkg:golang/" + m; other != library.Package && !programRulesOut(ctx, ruled, other, scanned, loaded, g, buildDir, env) {
			return nil
		}
	}
	module := mains[0].Module.Path
	binaries := make([]string, len(mains))
	for i, m := range mains {
		binaries[i] = "."
		if rel := strings.TrimPrefix(strings.TrimPrefix(m.PkgPath, module), "/"); rel != "" {
			binaries[i] = rel
		}
	}
	refutation := *ruled.Refutation
	refutation.Detail = "started from the main and init of " + strings.Join(binaries, ", ") + " only: " + refutation.Detail
	refutation.Assumptions = nil
	return &plugin.ProgramView{Module: module, Binaries: binaries, Refutation: refutation}
}

// programRulesOut reports whether the program view's checks hold for module, another module the
// advisory was matched to than the one ruled refutes: the run declares no limit that says a step did
// not run for it, and neither a file the build left out nor a call reflection makes may reach it. A
// check that keeps the refutation only with a scope of its own does not rule it out, since the
// view's detail states the refuted module's scope alone.
func programRulesOut(ctx context.Context, ruled plugin.ReachabilityResult, module string, scanned vulnScan, loaded *LoadResult, g reconcileGraph, buildDir string, env []string) bool {
	if programRunPartial(ruled.Partiality, module) {
		return false
	}
	r := *ruled.Refutation
	r.Package = module
	one := ruled
	one.Refutation = &r
	one = withholdForLeftOutFiles(ctx, one, scanned, loaded.Packages, loaded.buildRelease(), buildDir, env)
	one = withholdForReflectReach(one, scanned, g.ReflectReach)
	return one.Refutation != nil && one.Refutation.Detail == r.Detail
}

// inherentReasons are the run-wide limits the program run may declare and still answer: the call
// graph's reflection and interface dispatch, limits of the method on every scan
// (report.ClassifyPartialityReason). What reflection's calls reach is ruled on by
// withholdForReflectReach.
var inherentReasons = []string{plugin.PartialReasonReflection, plugin.PartialReasonDynamicDispatch}

// programRunPartial reports whether the program run's partiality says a step it rests on did not run
// for the refuted module (a PURL): a run-wide reason other than inherentReasons, or a scoped limit that
// is unbounded, or whose package or targets name the module, one it lies under, or one under it. The
// standard library is matched by no module path, so for it every scoped limit counts.
func programRunPartial(p plugin.Partiality, refuted string) bool {
	if slices.ContainsFunc(p.Reasons, func(r string) bool { return !slices.Contains(inherentReasons, r) }) {
		return true
	}
	module := strings.ToLower(packageFromPURL(refuted))
	return slices.ContainsFunc(p.Scoped, func(s plugin.ScopedReason) bool {
		if len(s.Targets) == 0 || module == "" || module == "stdlib" {
			return true
		}
		return slices.ContainsFunc(append([]string{s.Package}, s.Targets...), func(t string) bool {
			path := strings.ToLower(packageFromPURL(t))
			return path != "" && (underModule(path, module) || underModule(module, path))
		})
	})
}

// singleModule reports whether every package is in one module, so the binaries have one module to
// be named under.
func singleModule(pkgs []*packages.Package) bool {
	return !slices.ContainsFunc(pkgs, func(p *packages.Package) bool { return p.Module.Path != pkgs[0].Module.Path })
}

// tracedFromMain reports whether a symbol finding's entry point is in one of the packages: a program
// reaches the advisory's code, so the program view cannot rule it out and need not be run. A finding
// traced from elsewhere says nothing about the programs, since govulncheck reports one path per
// symbol, and a library's path may be the one it chose.
func tracedFromMain(findings []vulnFinding, pkgs []string) bool {
	return slices.ContainsFunc(findings, func(f vulnFinding) bool {
		return len(f.Trace) > 0 && f.Trace[0].Function != "" && slices.Contains(pkgs, f.Trace[len(f.Trace)-1].Package)
	})
}
