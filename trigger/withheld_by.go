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
// carries the package, path and targets it was declared with when it names this row's package, or
// when few of its reason count. Past maxLimitsElsewhere, the scoped limits of one reason that count
// without naming the package are listed as that reason once: they are the run's limits, which the
// report's partiality lists in full, and repeating them on every row grows the report by rows times
// limits. Any other reason has none.
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
	var elsewhere []bool
	runWide := footprintPartialityFlags(store, assessmentID)
	if len(runWide) == 0 {
		if inv, ok := inventory(store, assessmentID); ok {
			runWide = inv.PartialityFlags
		}
	}
	for _, r := range runWide {
		declared = append(declared, report.Limit{Reason: r})
		elsewhere = append(elsewhere, false)
	}
	root := pkg != nil && pkg.Root
	admitted, _, resolved := admittedPackage(store, assessmentID, pkg)
	for _, s := range footprintScoped(store, assessmentID) {
		if scopedLimitCounts(s, admitted, resolved, root) {
			declared = append(declared, report.Limit{Reason: s.Reason, Package: s.Package, Path: s.Path, Targets: slices.Clone(s.Targets)})
			elsewhere = append(elsewhere, !resolved || !scopedLimitNames(s, admitted, root))
		}
	}
	// kept is declared with entries dropped, and a dropped one is always the earliest of its
	// reason (withoutVersionLimits) or every one of it, so matching from the end pairs each kept
	// reason with the declaration that survived.
	held := make([]bool, len(declared))
	for i, j := len(declared)-1, len(kept)-1; i >= 0 && j >= 0; i-- {
		if declared[i].Reason == kept[j] {
			held[i] = true
			j--
		}
	}
	seen := map[string]bool{}
	perReason := map[string]int{}
	for i, l := range declared {
		if !held[i] {
			continue
		}
		if key := limitKey(l); seen[key] {
			held[i] = false
			continue
		} else {
			seen[key] = true
		}
		if elsewhere[i] {
			perReason[l.Reason]++
		}
	}
	var limits []report.Limit
	listed := map[string]bool{}
	for i, l := range declared {
		if !held[i] {
			continue
		}
		if elsewhere[i] && perReason[l.Reason] > maxLimitsElsewhere {
			l = report.Limit{Reason: l.Reason}
		}
		if key := limitKey(l); !listed[key] {
			listed[key] = true
			limits = append(limits, l)
		}
	}
	return limits
}

// maxLimitsElsewhere is how many scoped limits of one reason a row lists in full when they count
// against it without naming its package.
const maxLimitsElsewhere = 3

// scopedLimitNames reports whether a scoped limit names the admitted package, as the package it
// was declared in or as one of its targets.
func scopedLimitNames(s artifact.ScopedPartialityFlag, admitted pkgKey, root bool) bool {
	for _, p := range append([]string{s.Package}, s.Targets...) {
		if p == "" {
			if root {
				return true
			}
			continue
		}
		key, ok := purlKey(p)
		switch {
		case !ok:
		case key == admitted:
			return true
		case key.typ == "golang" && admitted.typ == "golang":
			if goPathWithin(key.name, admitted.name) || goPathWithin(admitted.name, key.name) {
				return true
			}
		}
	}
	return false
}

// limitKey identifies a limit for de-duplication: a Go scoped limit reaches the footprint from both
// the call graph and the reachability result.
func limitKey(l report.Limit) string {
	return strings.Join(append([]string{l.Reason, l.Package, l.Path}, l.Targets...), "\x00")
}
