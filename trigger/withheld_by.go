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
// carries the package, path and targets it was declared with. A row lists in full up to
// maxLimitsNaming scoped limits of one reason that name its package, and the ones that count without
// naming it while there are no more than maxLimitsElsewhere; the rest of that reason are one entry
// carrying their number, because repeating a run's scoped limits on every row grows the report by
// rows times limits. Any other reason has none.
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
	var naming []bool
	runWide := footprintPartialityFlags(store, assessmentID)
	if len(runWide) == 0 {
		if inv, ok := inventory(store, assessmentID); ok {
			runWide = inv.PartialityFlags
		}
	}
	for _, r := range runWide {
		declared = append(declared, report.Limit{Reason: r})
		naming = append(naming, false)
	}
	root := pkg != nil && pkg.Root
	admitted, _, resolved := admittedPackage(store, assessmentID, pkg)
	about, known := admitted, resolved
	if !known {
		about, known = packageKey(pkg)
	}
	for _, s := range footprintScoped(store, assessmentID) {
		if scopedLimitCounts(s, admitted, resolved, root) {
			declared = append(declared, report.Limit{Reason: s.Reason, Package: s.Package, Path: s.Path, Targets: slices.Clone(s.Targets)})
			naming = append(naming, known && scopedLimitNames(s, about, root))
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
	elsewhere := map[string]int{}
	var named []int
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
		if l.Package+l.Path != "" || len(l.Targets) > 0 {
			if naming[i] {
				named = append(named, i)
			} else {
				elsewhere[l.Reason]++
			}
		}
	}
	// Of the limits naming the package, the first in each package it was declared in is listed
	// before a second in any, so the cap does not hide which packages hold unseen code.
	full := make([]bool, len(declared))
	listed := map[string]int{}
	for _, firstOnly := range []bool{true, false} {
		inPackage := map[string]bool{}
		for _, i := range named {
			l := declared[i]
			first := !inPackage[l.Reason+"\x00"+l.Package]
			inPackage[l.Reason+"\x00"+l.Package] = true
			if !full[i] && first == firstOnly && listed[l.Reason] < maxLimitsNaming {
				full[i] = true
				listed[l.Reason]++
			}
		}
	}
	// A reason's count entry takes the place of the first scoped limit it stands for.
	var limits []report.Limit
	counted := map[string]int{}
	for i, l := range declared {
		if !held[i] {
			continue
		}
		scoped := l.Package+l.Path != "" || len(l.Targets) > 0
		switch {
		case !scoped:
		case full[i]:
		case !naming[i] && elsewhere[l.Reason] <= maxLimitsElsewhere:
		default:
			if at, ok := counted[l.Reason]; ok {
				limits[at].Others++
			} else {
				counted[l.Reason] = len(limits)
				limits = append(limits, report.Limit{Reason: l.Reason, Others: 1})
			}
			continue
		}
		limits = append(limits, l)
	}
	return limits
}

// maxLimitsNaming is how many scoped limits of one reason a row lists in full when they name its
// package; maxLimitsElsewhere is how many when they count against it without naming it.
const (
	maxLimitsNaming    = 8
	maxLimitsElsewhere = 3
)

// packageKey is the package a row is about when no version of it was admitted.
func packageKey(pkg *report.Package) (pkgKey, bool) {
	if pkg == nil {
		return pkgKey{}, false
	}
	if key, ok := purlKey(pkg.PURL); ok {
		return key, true
	}
	if typ, ok := purlTypeFor[pkg.Ecosystem]; ok && pkg.Name != "" {
		return pkgKey{typ: typ, name: normalizePackageName(typ, pkg.Name)}, true
	}
	return pkgKey{}, false
}

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
