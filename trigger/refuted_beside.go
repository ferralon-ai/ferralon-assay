package trigger

import (
	"fmt"
	"slices"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// admittedRefutation returns the lane's refutation of the admitted package: Refutation when it
// names that package, else the one of Refutations that does. With neither it returns Refutation,
// which the caller then finds names another package.
func admittedRefutation(reach plugin.ReachabilityResult, admitted pkgKey, root bool) *plugin.Refutation {
	if r := reach.Refutation; r != nil && inAdmitted(r.Package, admitted, root) {
		return r
	}
	for i := range reach.Refutations {
		if inAdmitted(reach.Refutations[i].Package, admitted, root) {
			return &reach.Refutations[i]
		}
	}
	return reach.Refutation
}

// refutedBeside returns the lane's refutations of Go modules other than the admitted package that
// stand on this assessment. Each rests on the analyzer's own search of that module
// (analyzer_symbol_not_reached), so three things hold one back:
//
//   - a refutation of the standard library, unless reachability ran under the subject's exact Go
//     toolchain (toolchainUndetermined's rule for a stdlib advisory);
//   - a scoped did-not-run limit that counts for the module (scopedLimitCounts), which the
//     admitted package's own gate never weighs;
//   - any other basis, which this version does not know how to weigh beside the admitted package.
func refutedBeside(store artifact.Store, assessmentID string, reach plugin.ReachabilityResult, admitted pkgKey) []plugin.Refutation {
	all := slices.Clone(reach.Refutations)
	if reach.Refutation != nil {
		all = append(all, *reach.Refutation)
	}
	scoped := footprintScoped(store, assessmentID)
	var out []plugin.Refutation
	for _, r := range all {
		key, ok := purlKey(r.Package)
		if !ok || key == admitted || key.typ != "golang" || r.Basis != plugin.RefutationAnalyzerSymbolNotReached {
			continue
		}
		if key.name == goStdlib && !subjectToolchainExactAndScanned(store, assessmentID) {
			continue
		}
		if slices.ContainsFunc(scoped, func(f artifact.ScopedPartialityFlag) bool {
			return report.ClassifyPartialityReason(f.Reason) == report.PartialityDidNotRun && scopedLimitCounts(f, key, true, false)
		}) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// subjectToolchainExactAndScanned reports whether the subject's Go toolchain is known exactly and
// reachability ran under it: the condition toolchainUndetermined lifts on.
func subjectToolchainExactAndScanned(store artifact.Store, assessmentID string) bool {
	fact, ok := pipeline.Toolchain(store, assessmentID)
	return ok && fact.Bound == pipeline.ToolchainBoundExact && pipeline.SubjectToolchainScanned(store, assessmentID)
}

// refutes reports whether one of the refutations names the package key is, by module path or by a
// package path that module holds (samePackage).
func refutes(beside []plugin.Refutation, key pkgKey, mods goModules) bool {
	return slices.ContainsFunc(beside, func(r plugin.Refutation) bool {
		refuted, ok := purlKey(r.Package)
		return ok && samePackage(key, refuted, mods)
	})
}

// withRefutedBeside states, on a not_exploitable ground for the admitted package, the refutations
// of the other packages the advisory names that the ground also rests on: each one's detail joins
// the detail, and its assumptions join the assumptions. A refutation of a package the advisory
// does not name is left out.
func withRefutedBeside(detail string, assumptions []string, purls []string, admitted pkgKey, mods goModules, beside []plugin.Refutation) (string, []string) {
	for _, r := range beside {
		refuted, ok := purlKey(r.Package)
		if !ok || !slices.ContainsFunc(purls, func(p string) bool {
			key, ok := purlKey(p)
			return ok && !samePackage(key, admitted, mods) && samePackage(key, refuted, mods)
		}) {
			continue
		}
		detail = fmt.Sprintf("%s; also %s: %s (%s)", detail, refuted.name, r.Detail, r.Basis)
		for _, a := range r.Assumptions {
			if !slices.Contains(assumptions, a) {
				assumptions = append(slices.Clone(assumptions), a)
			}
		}
	}
	return detail, assumptions
}
