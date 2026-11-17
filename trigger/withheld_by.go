package trigger

import (
	"slices"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// withheldBy returns the limits behind an undetermined row whose reason is refutation_withheld or
// analysis_did_not_run: the did-not-run limits analysisDidNotRun kept for this advisory, in the
// order the run declared them. A run-wide limit carries its reason alone; a scoped one carries the
// package, path and targets it was declared with. Any other reason has none.
func withheldBy(store artifact.Store, assessmentID string, pkg *report.Package, reason string) []report.Limit {
	if reason != report.ReasonRefutationWithheld && reason != report.ReasonAnalysisDidNotRun {
		return nil
	}
	kept, _ := keptDidNotRunReasons(store, assessmentID, pkg)
	if len(kept) == 0 {
		return nil
	}
	runWide := footprintPartialityFlags(store, assessmentID)
	if len(runWide) == 0 {
		if inv, ok := inventory(store, assessmentID); ok {
			runWide = inv.PartialityFlags
		}
	}
	var limits []report.Limit
	seen := map[string]bool{}
	for _, r := range runWide {
		if slices.Contains(kept, r) && !seen[r] {
			seen[r] = true
			limits = append(limits, report.Limit{Reason: r})
		}
	}
	admitted, _, resolved := admittedPackage(store, assessmentID, pkg)
	for _, s := range footprintScoped(store, assessmentID) {
		if !slices.Contains(kept, s.Reason) || !scopedLimitCounts(s, admitted, resolved, pkg != nil && pkg.Root) {
			continue
		}
		limits = append(limits, report.Limit{Reason: s.Reason, Package: s.Package, Path: s.Path, Targets: slices.Clone(s.Targets)})
	}
	return limits
}
