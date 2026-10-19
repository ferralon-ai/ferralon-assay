package pipeline

import (
	"encoding/json"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// AdvisoryRangeAbsent reports whether the normalized advisory carries no affected range the version
// axis can bound for the package it was assessed against: the selected affected_packages[] element
// when the advisory targets a secondary package, else the advisory's primary.
//
// A range is bounded when its type orders versions (versionOutsideRange reads its introduced and
// fixed bounds), and an unfixed range from zero is "every version from here on", a declared range. A range whose type does not order versions (GIT, or
// anything unrecognized) bounds nothing the version axis can read, so an advisory with only such
// ranges counts as absent, as does one with no range at all.
//
// Such an advisory is admitted at every installed version, because the version axis has nothing
// to compare against. A missing or unreadable advisory artifact reports false.
func AdvisoryRangeAbsent(store artifact.Store, caseID string) bool {
	ranges, ok := assessedRanges(store, caseID)
	return ok && !anyBounded(ranges)
}

// RecordedBound is what one affected range of a range-absent advisory does record: its OSV range
// type and its introduced (above zero), fixed and last_affected events, in the range's own ordering
// (commits, for a GIT range), which the version axis does not read.
type RecordedBound struct {
	Type         string
	Introduced   string
	Fixed        string
	LastAffected string
}

// AdvisoryRecordedBounds returns the bounds of the affected ranges AdvisoryRangeAbsent read that
// record at least one event, in advisory order. It returns nil when the advisory has
// a range the version axis can bound, so it never describes an advisory that is not range-absent.
func AdvisoryRecordedBounds(store artifact.Store, caseID string) []RecordedBound {
	ranges, ok := assessedRanges(store, caseID)
	if !ok || anyBounded(ranges) {
		return nil
	}
	var out []RecordedBound
	for _, r := range ranges {
		if r.LowerInclusive != "" || r.UpperExclusive != "" || r.LastAffected != "" {
			out = append(out, RecordedBound{Type: r.Type, Introduced: r.LowerInclusive, Fixed: r.UpperExclusive, LastAffected: r.LastAffected})
		}
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
		if rangeTypeOrderable(r.Type) {
			return true
		}
	}
	return false
}
