package pipeline

import (
	"encoding/json"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// AdvisoryRangeAbsent reports whether the normalized advisory carries no affected range at all for
// the package it was assessed against: the selected affected_packages[] element when the advisory
// targets a secondary package, else the advisory's primary. Absent means no range was recorded, not
// that a range was recorded without a fix: an unfixed range carries an empty upper bound and is a
// declared range ("every version from here on").
//
// Such an advisory is admitted at every installed version, because the version axis has nothing
// to compare against. A missing or unreadable advisory artifact reports false.
func AdvisoryRangeAbsent(store artifact.Store, caseID string) bool {
	if sel, ok := extractSelectedPackage(store, caseID); ok {
		return len(sel.AffectedRanges) == 0
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
	return len(adv.AffectedRanges) == 0
}
