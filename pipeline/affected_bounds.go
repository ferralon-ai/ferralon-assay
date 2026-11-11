// ferralon-assay/pipeline/affected_bounds.go
//
// The per-range reading of an advisory's affected set for the version axis: introduced and
// upper-exclusive bounds under each ecosystem's comparator.

package pipeline

import (
	"golang.org/x/mod/semver"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// versionOutsideRange reports whether ver is provably outside one affected range: below its
// inclusive LowerInclusive bound, or at or past its UpperExclusive bound. A LastAffected bound
// never places a version outside. It is the single in-range test the version axis applies per range.
//
// Not being outside admits the advisory, so every uncertainty resolves toward admission. A bound
// the scheme cannot order contributes no proof; a range type other than SEMVER or ECOSYSTEM (GIT,
// or anything unrecognized) proves nothing at all. ok is true only when ver is placed against every
// bound the range carries, or when one bound alone already places it outside: a version below an
// orderable LowerInclusive is outside whatever the upper bound says.
func versionOutsideRange(ver string, rng affectedRange) (outside bool, ok bool) {
	if !rangeTypeOrderable(rng.Type) {
		return false, false
	}
	below, lowerOK := versionBelowIntroduced(ver, rng)
	if lowerOK && below {
		return true, true
	}
	above, upperOK := versionAboveRangeTop(ver, rng)
	if upperOK && above {
		return true, true
	}
	return false, lowerOK && upperOK
}

// rangeTypeOrderable reports whether an OSV range type orders its bounds as versions. An absent type
// is the corpus's ordinary case and is read as the ecosystem's own ordering.
func rangeTypeOrderable(rangeType string) bool {
	switch rangeType {
	case "", "SEMVER", "ECOSYSTEM":
		return true
	default:
		return false
	}
}

// versionBelowIntroduced reports whether ver orders strictly below rng's inclusive lower bound. An
// absent LowerInclusive, or OSV's "0", is unbounded below.
func versionBelowIntroduced(ver string, rng affectedRange) (below bool, ok bool) {
	if rng.LowerInclusive == "" || rng.LowerInclusive == "0" {
		return false, true
	}
	cmp, ok := compareVersions(ver, rng.LowerInclusive, rng.Scheme)
	if !ok {
		return false, false
	}
	return cmp < 0, true
}

// versionAboveRangeTop reports whether ver orders past rng's upper end. Only UpperExclusive is an
// upper end. A range with a LastAffected bound and no UpperExclusive is open-ended above, as is one
// floored by LowerInclusive alone: GHSA writes "<= X" for an advisory with no patch yet, so a
// release past X may still be affected. versionOutsideRanges first caps such a range when a later
// range in the same set bounds it (capOpenLastAffected). A range with no bound at all keeps the upper-exclusive
// reading of an empty bound.
func versionAboveRangeTop(ver string, rng affectedRange) (above bool, ok bool) {
	switch {
	case rng.UpperExclusive != "":
		return versionOutsideUpper(ver, rng)
	case rng.LastAffected != "" || rng.LowerInclusive != "":
		return false, true
	default:
		return versionOutsideUpper(ver, rng)
	}
}

// capOpenLastAffected returns rngs with each range that ends at LastAffected alone capped at the
// lowest introduced, among the set's other ranges from the same source, that orders above its
// LastAffected and above its own introduced: a record that describes a later branch line in its own
// range has said where the earlier line stops. Legacy ranges merged beside an element's
// (withDisagreeingLegacyRanges) are another source, and one never caps the other. The
// cap reads an upper end the record implies, so it only ever places more versions outside; a
// version between LastAffected and the cap stays inside. The topmost such range, and the one range
// of a single-range set, has nothing above it and stays open-ended. Any bound the scheme cannot
// order leaves that range uncapped. rngs is never modified.
func capOpenLastAffected(rngs []affectedRange) []affectedRange {
	if len(rngs) < 2 {
		return rngs
	}
	out := make([]affectedRange, len(rngs))
	copy(out, rngs)
	for i, r := range rngs {
		if r.UpperExclusive != "" || r.LastAffected == "" || !rangeTypeOrderable(r.Type) {
			continue
		}
		if c, ok := nextIntroduced(i, rngs); ok {
			out[i].UpperExclusive = c
		}
	}
	return out
}

// nextIntroduced returns the lowest LowerInclusive among the other ranges of rngs from rngs[i]'s
// source that orders strictly above rngs[i]'s LastAffected and its own LowerInclusive, under its
// scheme. ok is false when there is none, or when any ordering it needs is unknown.
func nextIntroduced(i int, rngs []affectedRange) (string, bool) {
	r := rngs[i]
	var low string
	for j, c := range rngs {
		if j == i || c.Legacy != r.Legacy || c.LowerInclusive == "" || c.Scheme != r.Scheme || !rangeTypeOrderable(c.Type) {
			continue
		}
		cmp, ok := compareVersions(c.LowerInclusive, r.LastAffected, r.Scheme)
		if !ok {
			return "", false
		}
		if cmp <= 0 {
			continue
		}
		if low != "" {
			if cmp, ok = compareVersions(c.LowerInclusive, low, r.Scheme); !ok {
				return "", false
			}
			if cmp >= 0 {
				continue
			}
		}
		low = c.LowerInclusive
	}
	if low != "" && r.LowerInclusive != "" {
		if cmp, ok := compareVersions(low, r.LowerInclusive, r.Scheme); !ok || cmp <= 0 {
			return "", false
		}
	}
	return low, low != ""
}

// rangesForFloorVersion drops the LowerInclusive bounds when the resolved version is only a floor on the
// true one: a toolchain subject whose ToolchainFact is a minimum. Being past an upper bound carries
// from a floor to every version above it; being below a lower bound does not, so a floor can be
// excluded only by its upper bounds.
func rangesForFloorVersion(store artifact.Store, caseID string, rngs []affectedRange) []affectedRange {
	if !ToolchainSubject(store, caseID) {
		return rngs
	}
	return rangesForToolchainFloor(store, caseID, rngs)
}

// rangesForToolchainFloor drops the LowerInclusive bounds of a toolchain package's ranges when the
// subject's ToolchainFact is a minimum, for the reason rangesForFloorVersion gives.
func rangesForToolchainFloor(store artifact.Store, caseID string, rngs []affectedRange) []affectedRange {
	tc, ok := Toolchain(store, caseID)
	if !ok || tc.Bound != ToolchainBoundMinimum {
		return rngs
	}
	out := make([]affectedRange, len(rngs))
	for i, r := range rngs {
		r.LowerInclusive = ""
		out[i] = r
	}
	return out
}

// compareVersions orders a against b under scheme's comparator, returning -1/0/+1. ok is false when
// the scheme has no comparator or either version falls outside its grammar. The default Go path
// rejects prereleases, pseudo-versions included, as versionOutsideUpper does.
func compareVersions(a, b, scheme string) (int, bool) {
	switch scheme {
	case "maven":
		return compareMaven(a, b)
	case "npm":
		x, xok := parseNPMVersion(a)
		y, yok := parseNPMVersion(b)
		if !xok || !yok {
			return 0, false
		}
		return compareNPMVersion(x, y), true
	case "pypi":
		x, xok := parsePEP440(a)
		y, yok := parsePEP440(b)
		if !xok || !yok {
			return 0, false
		}
		return comparePEP440(x, y), true
	case "nuget":
		x, xok := parseNuGetVersion(a)
		y, yok := parseNuGetVersion(b)
		if !xok || !yok {
			return 0, false
		}
		return compareNuGetVersion(x, y), true
	case "go-toolchain":
		x, xok := parseGoToolchainBound(a)
		y, yok := parseGoToolchainBound(b)
		if !xok || !yok {
			return 0, false
		}
		return compareGoToolchain(x, y), true
	case "", "gomod":
		if !semver.IsValid(a) || !semver.IsValid(b) || semver.Prerelease(a) != "" || semver.Prerelease(b) != "" {
			return 0, false
		}
		return semver.Compare(a, b), true
	default:
		return 0, false
	}
}

// withDisagreeingLegacyRanges adds the advisory-level legacy ranges to the element they describe when
// the two disagree, so the element admits wherever either one admits.
//
// A published record can carry both affected[] (read into the element) and the legacy
// affected_ranges (read into the advisory's scalar ranges). The legacy field cannot carry
// introduced, so its missing lower bounds are a projection loss, not a disagreement. A disagreement
// is any other difference in the bounds. Only the element the scalar block names is compared: the
// legacy ranges describe that package and no other.
func withDisagreeingLegacyRanges(rngs []affectedRange, pkg AffectedPackage, facts AdvisoryFacts, scheme string) []affectedRange {
	if len(facts.AffectedRanges) == 0 || !describesPrimary(pkg, facts) {
		return rngs
	}
	if !legacyRangesDisagree(pkg.AffectedRanges, facts.AffectedRanges) {
		return rngs
	}
	legacy := buildAffectedRanges(facts.AffectedRanges, "", scheme)
	for i := range legacy {
		legacy[i].Legacy = true
	}
	return append(rngs, legacy...)
}

// describesPrimary reports whether pkg is the element the advisory's scalar block names.
func describesPrimary(pkg AffectedPackage, facts AdvisoryFacts) bool {
	return (pkg.PURL != "" && pkg.PURL == facts.PURL) || (pkg.Coordinate != "" && pkg.Coordinate == facts.Coordinate)
}

// legacyRangesDisagree reports whether the legacy ranges fail to pair one-to-one with the element's
// on their upper bounds, and on introduced wherever the legacy range states one.
func legacyRangesDisagree(elem, legacy []Range) bool {
	if len(elem) != len(legacy) {
		return true
	}
	used := make([]bool, len(elem))
	for _, l := range legacy {
		paired := false
		for i, e := range elem {
			if used[i] || e.Fixed != l.Fixed || e.LastAffected != l.LastAffected {
				continue
			}
			if l.Introduced != "" && l.Introduced != e.Introduced {
				continue
			}
			used[i] = true
			paired = true
			break
		}
		if !paired {
			return true
		}
	}
	return false
}
