package pipeline

import (
	"encoding/json"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// AdvisoryRangeAbsent reports whether the normalized advisory carries no affected range the version
// axis can bound for the package it was assessed against: the selected affected_packages[] element
// when the advisory targets a secondary package, else the advisory's primary.
//
// A range is bounded when it records a fix, or when it records neither a lower bound above zero nor
// a last_affected version: an unfixed range from zero is "every version from here on" and is a
// declared range. A last_affected-only or introduced-above-zero-only range excludes versions the
// version axis cannot exclude, so it counts as absent, as does no range at all.
//
// Such an advisory is admitted at every installed version, because the version axis has nothing
// to compare against. A missing or unreadable advisory artifact reports false.
func AdvisoryRangeAbsent(store artifact.Store, caseID string) bool {
	if sel, ok := extractSelectedPackage(store, caseID); ok {
		return !anyBounded(sel.AffectedRanges)
	}
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return false
	}
	var adv struct {
		AffectedRanges []affectedRange `json:"affected_ranges"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return false
	}
	return !anyBounded(adv.AffectedRanges)
}

func anyBounded(ranges []affectedRange) bool {
	for _, r := range ranges {
		if r.UpperExclusive != "" || (r.LowerInclusive == "" && r.LastAffected == "") {
			return true
		}
	}
	return false
}
