// ferralon-assay/pipeline/affected_bounds.go
//
// The per-range reading of an advisory's affected set for the version axis: introduced,
// upper-exclusive and last_affected bounds under each ecosystem's comparator.
package pipeline

import (
	"golang.org/x/mod/semver"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// versionOutsideRange reports whether ver is provably outside one affected range: below its
// inclusive Introduced bound, at or past its UpperExclusive bound, or past its inclusive
// LastAffected bound. It is the single in-range test the version axis applies per range.
//
// Not being outside admits the advisory, so every uncertainty resolves toward admission. A bound
// the scheme cannot order contributes no proof; a range type other than SEMVER or ECOSYSTEM (GIT,
// or anything unrecognized) proves nothing at all. ok is true only when ver is placed against every
// bound the range carries, or when one bound alone already places it outside: a version below an
// orderable Introduced is outside whatever the upper bound says.
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
// absent Introduced, or OSV's "0", is unbounded below.
func versionBelowIntroduced(ver string, rng affectedRange) (below bool, ok bool) {
	if rng.Introduced == "" || rng.Introduced == "0" {
		return false, true
	}
	cmp, ok := compareVersions(ver, rng.Introduced, rng.Scheme)
	if !ok {
		return false, false
	}
	return cmp < 0, true
}

// versionAboveRangeTop reports whether ver orders past rng's upper end. UpperExclusive wins when
// present; LastAffected is inclusive; a range floored by Introduced with neither is open-ended
// above. A range with no bound at all keeps the upper-exclusive reading of an empty bound.
func versionAboveRangeTop(ver string, rng affectedRange) (above bool, ok bool) {
	switch {
	case rng.UpperExclusive != "":
		return versionOutsideUpper(ver, rng)
	case rng.LastAffected != "":
		cmp, ok := compareVersions(ver, rng.LastAffected, rng.Scheme)
		if !ok {
			return false, false
		}
		return cmp > 0, true
	case rng.Introduced != "":
		return false, true
	default:
		return versionOutsideUpper(ver, rng)
	}
}

// rangesForFloorVersion drops the Introduced bounds when the resolved version is only a floor on the
// true one: a toolchain subject whose ToolchainFact is a minimum. Being past an upper bound carries
// from a floor to every version above it; being below a lower bound does not, so a floor can be
// excluded only by its upper bounds.
func rangesForFloorVersion(store artifact.Store, caseID string, rngs []affectedRange) []affectedRange {
	tc, ok := Toolchain(store, caseID)
	if !ok || tc.Bound != ToolchainBoundMinimum || !ToolchainSubject(store, caseID) {
		return rngs
	}
	out := make([]affectedRange, len(rngs))
	for i, r := range rngs {
		r.Introduced = ""
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
		x, xok := parseGoToolchainVersion(a)
		y, yok := parseGoToolchainVersion(b)
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
