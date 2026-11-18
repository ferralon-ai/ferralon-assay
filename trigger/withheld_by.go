package trigger

import (
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// withheldBy returns the limits behind an undetermined row whose reason is refutation_withheld or
// analysis_did_not_run: the did-not-run limits analysisDidNotRun kept for this advisory, in the
// order the run declared them, each once. A run-wide limit carries its reason alone; a scoped one
// carries the package, path and targets it was declared with. Any other reason has none.
func withheldBy(store artifact.Store, assessmentID string, pkg *report.Package, reason string) []report.Limit {
	if reason != report.ReasonRefutationWithheld && reason != report.ReasonAnalysisDidNotRun {
		return nil
	}
	kept, _ := keptDidNotRunReasons(store, assessmentID, pkg)
	if len(kept) == 0 {
		return nil
	}
	// The declared limits in the order didNotRunReasons weighs them: run-wide, then the scoped ones
	// that count against this package.
	var declared []report.Limit
	runWide := footprintPartialityFlags(store, assessmentID)
	if len(runWide) == 0 {
		if inv, ok := inventory(store, assessmentID); ok {
			runWide = inv.PartialityFlags
		}
	}
	for _, r := range runWide {
		declared = append(declared, report.Limit{Reason: r})
	}
	admitted, _, resolved := admittedPackage(store, assessmentID, pkg)
	for _, s := range footprintScoped(store, assessmentID) {
		if scopedLimitCounts(s, admitted, resolved, pkg != nil && pkg.Root) {
			declared = append(declared, report.Limit{Reason: s.Reason, Package: s.Package, Path: s.Path, Targets: slices.Clone(s.Targets)})
		}
	}
	// kept is declared with entries dropped, and a dropped one is always the earliest of its
	// reason (withoutVersionLimits) or every one of it, so matching from the end pairs each kept
	// reason with the declaration that survived.
	var limits []report.Limit
	seen := map[string]bool{}
	for i, j := len(declared)-1, len(kept)-1; i >= 0 && j >= 0; i-- {
		l := declared[i]
		if l.Reason != kept[j] {
			continue
		}
		j--
		if key := limitKey(l); !seen[key] {
			seen[key] = true
			limits = append(limits, l)
		}
	}
	slices.Reverse(limits)
	return limits
}

// limitKey identifies a limit for de-duplication: a Go scoped limit reaches the footprint from both
// the call graph and the reachability result.
func limitKey(l report.Limit) string {
	return strings.Join(append([]string{l.Reason, l.Package, l.Path}, l.Targets...), "\x00")
}
