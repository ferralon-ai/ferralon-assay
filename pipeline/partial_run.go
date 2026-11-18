package pipeline

import (
	"slices"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ownAdvisoryOnPartialRun reports whether the advisory is on the scanned project itself, the
// project states no version of itself, and the lane answered from a run over part of the build
// (part declares plugin.PartialReasonPartialRunUnversioned). No version places the project against
// the advisory's affected range, and the lane's own search left part of the project out, so the
// first-party call-graph fallback forms no candidate for it. All three must hold: a run over the
// whole build never declares the reason, so every row such a run reports is untouched.
func ownAdvisoryOnPartialRun(store artifact.Store, caseID string, part plugin.Partiality) bool {
	if !slices.Contains(part.Reasons, plugin.PartialReasonPartialRunUnversioned) || !RootSubject(store, caseID) {
		return false
	}
	_, versioned := ResolvedVersion(store, caseID)
	return !versioned
}

// OwnAdvisoryHeldForPartialRun is ownAdvisoryOnPartialRun read off the stored reachability result:
// whether reachability_ingress formed no first-party candidate for the scanned project's own
// advisory because the lane answered from a partial run.
func OwnAdvisoryHeldForPartialRun(store artifact.Store, caseID string) bool {
	rec, ok, err := Reachability(store, caseID)
	if err != nil || !ok {
		return false
	}
	res, err := rec.Result()
	return err == nil && ownAdvisoryOnPartialRun(store, caseID, res.Partiality)
}

// withoutPartialRunUnversioned is part without the partial_run_unversioned reason, leaving the rest
// of the declaration as it was.
func withoutPartialRunUnversioned(part plugin.Partiality) plugin.Partiality {
	if !slices.Contains(part.Reasons, plugin.PartialReasonPartialRunUnversioned) {
		return part
	}
	part.Reasons = slices.DeleteFunc(slices.Clone(part.Reasons), func(r string) bool {
		return r == plugin.PartialReasonPartialRunUnversioned
	})
	return part
}
