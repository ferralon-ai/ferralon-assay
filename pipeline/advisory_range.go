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
	ranges, ok := assessedRanges(store, caseID)
	return ok && !anyBounded(ranges)
}

// RecordedBound is what one affected range of a range-absent advisory does record: an introduced
// version above zero, a last_affected version, or both. Neither is a bound the version axis reads.
type RecordedBound struct {
	Introduced   string
	LastAffected string
}

// AdvisoryRecordedBounds returns the partial bounds of the affected ranges AdvisoryRangeAbsent
// read, in advisory order. Every such range records at least one of the two. It returns nil when the advisory
// has a range the version axis can bound, so it never describes an advisory that is not range-absent.
func AdvisoryRecordedBounds(store artifact.Store, caseID string) []RecordedBound {
	ranges, ok := assessedRanges(store, caseID)
	if !ok || anyBounded(ranges) {
		return nil
	}
	var out []RecordedBound
	for _, r := range ranges {
		out = append(out, RecordedBound{Introduced: r.LowerInclusive, LastAffected: r.LastAffected})
	}
	return out
}

// assessedRanges returns the affected ranges of the package the advisory was assessed against. ok is
// false when the advisory artifact is missing or unreadable.
func assessedRanges(store artifact.Store, caseID string) ([]affectedRange, bool) {
	if sel, ok := extractSelectedPackage(store, caseID); ok {
		return sel.AffectedRanges, true
	}
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return nil, false
	}
	var adv struct {
		AffectedRanges []affectedRange `json:"affected_ranges"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return nil, false
	}
	return adv.AffectedRanges, true
}

func anyBounded(ranges []affectedRange) bool {
	for _, r := range ranges {
		if r.UpperExclusive != "" || (r.LowerInclusive == "" && r.LastAffected == "") {
			return true
		}
	}
	return false
}
