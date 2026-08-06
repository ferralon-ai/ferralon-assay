// internal/pipeline/nuget_version.go
//
// NuGet (NuGet.Versioning) version comparison and interval-range matching for the
// .NET/C# disqualification axis. NuGet is the hardest of the three schemes and, unlike
// Maven and npm, expresses affected sets as bracketed INTERVALS rather than a single
// "<X" bound, so this file carries both an ordering comparator and an interval matcher.
//
// NuGetVersion diverges from SemVer in ways the npm/Maven comparators do not model, so
// this is a focused, dependency-free port of the NuGet.Versioning subset needed for a
// SOUND disqualification decision:
//
//   - FOUR numeric segments: Major.Minor.Patch.Revision (npm's 3-tuple is insufficient).
//   - Only Major is required; missing segments default to 0, so "1", "1.0", "1.0.0", and
//     "1.0.0.0" are ALL EQUAL. A zero 4th segment is omitted on normalization but that is
//     purely cosmetic here — equality falls out of the padded compare.
//   - Leading zeroes are insignificant ("1.01.1" == "1.1.1"); "+build" metadata never
//     affects ordering and is dropped.
//   - Pre-release is CASE-INSENSITIVE ("1.0-Alpha" == "1.0-alpha"); a release sorts ABOVE
//     any pre-release; among pre-releases SemVer 2.0.0 identifier rules apply.
//
// Both entry points FAIL OPEN (ok=false) on ANY input outside the modelled grammar
// (inv.5): an exotic version, an invalid bracket form, an inverted/empty interval, or a
// floating token reaching an ordering decision must never yield a confident, possibly
// wrong ordering that fabricates a not-affected.
//
// Two entry points mirroring npm_version.go:
//   - nugetVersionOutsideRange(ver, upperExclusive): the "affects < upper" bound — the
//     advisory fixed-version X becomes upper-exclusive [,X); outside == compare(ver,X) >= 0.
//   - nugetVersionInRange(ver, rangeExpr): the interval-notation matcher ([ ] inclusive,
//     ( ) exclusive, a missing endpoint = ±∞, a bare version = minimum-inclusive).
//
// The prerelease identifiers are lowercased at parse time, so this file reuses the
// package-level comparePrerelease / atoiNonNeg / cmpInt helpers (from npm_version.go) to
// get NuGet's case-insensitive SemVer2 prerelease ordering for free.
package pipeline

import "strings"

// nugetVersionOutsideRange reports whether ver is provably outside the affected set
// affects<upper under NuGet ordering. ok is false (no proof) on any input the comparator
// cannot confidently order — including a floating token. Provably-outside means
// compareNuGetVersion(ver, upper) >= 0.
func nugetVersionOutsideRange(ver, upper string) (outside bool, ok bool) {
	if isNuGetFloating(ver) || isNuGetFloating(upper) {
		return false, false
	}
	a, aok := parseNuGetVersion(ver)
	b, bok := parseNuGetVersion(upper)
	if !aok || !bok {
		return false, false
	}
	return compareNuGetVersion(a, b) >= 0, true
}

// nugetVersionInRange reports whether ver satisfies the NuGet interval expression
// rangeExpr. Bracket forms: "[1.0,2.0)" (1.0<=x<2.0), "(1.0,)" (x>1.0), "(,1.0]" (x<=1.0),
// "[1.0]" (x==1.0, the only exact form), and a BARE "1.0" (x>=1.0, minimum-inclusive — NOT
// exact, the critical NuGet gotcha). ok is false when ver or the range falls outside the
// modelled grammar (invalid bracket form, inverted/empty interval, a floating token, or an
// out-of-alphabet character), so the caller fails open.
func nugetVersionInRange(ver, rangeExpr string) (inRange bool, ok bool) {
	if isNuGetFloating(ver) || isNuGetFloating(rangeExpr) {
		return false, false // a floating token reaching an ordering decision fails open (§2e)
	}
	if !nugetAllowedChars(rangeExpr) {
		return false, false
	}
	v, vok := parseNuGetVersion(ver)
	if !vok {
		return false, false
	}
	iv, iok := parseNuGetInterval(strings.TrimSpace(rangeExpr))
	if !iok {
		return false, false
	}
	return iv.contains(v), true
}

// --- version model -----------------------------------------------------------

// nugetVersion is a parsed NuGetVersion: four numeric segments plus ordered, lowercased
// prerelease identifiers. Build metadata is parsed away (it never affects ordering).
type nugetVersion struct {
	major, minor, patch, revision int
	prerelease                    []string // empty for a release version; lowercased
}

// parseNuGetVersion parses "Major[.Minor[.Patch[.Revision]]][-pre][+build]". Only Major is
// required; missing segments default to 0 so 1 == 1.0 == 1.0.0 == 1.0.0.0. ok is false on
// any malformed input (no segment, >4 segments, a non-numeric core segment, an empty
// prerelease identifier, or an out-of-alphabet character) so the caller fails open.
func parseNuGetVersion(s string) (nugetVersion, bool) {
	s = strings.TrimSpace(s)
	if s == "" || !nugetAllowedChars(s) {
		return nugetVersion{}, false
	}
	// Strip build metadata (never affects ordering).
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	core := s
	var pre string
	hasPre := false
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core, pre = s[:i], s[i+1:]
		hasPre = true
	}
	if hasPre && pre == "" {
		return nugetVersion{}, false // a '-' marker with no prerelease identifier is malformed
	}
	parts := strings.Split(core, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nugetVersion{}, false
	}
	var seg [4]int
	for i, p := range parts {
		n, ok := atoiNonNeg(p)
		if !ok {
			return nugetVersion{}, false
		}
		seg[i] = n
	}
	v := nugetVersion{major: seg[0], minor: seg[1], patch: seg[2], revision: seg[3]}
	if pre != "" {
		ids := strings.Split(strings.ToLower(pre), ".")
		for _, id := range ids {
			if id == "" || !nugetPrereleaseID(id) {
				return nugetVersion{}, false
			}
		}
		v.prerelease = ids
	}
	return v, true
}

// nugetPrereleaseID reports whether id is a well-formed SemVer2 prerelease identifier:
// non-empty and composed only of [0-9A-Za-z-] (already lowercased by the caller).
func nugetPrereleaseID(id string) bool {
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c == '-') {
			return false
		}
	}
	return true
}

// compareNuGetVersion compares two parsed versions, returning -1/0/+1: the four numeric
// segments component-wise, then prerelease precedence (a release orders ABOVE any
// prerelease; prerelease identifiers by SemVer2 §11, reusing comparePrerelease).
func compareNuGetVersion(a, b nugetVersion) int {
	if c := cmpInt(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpInt(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpInt(a.patch, b.patch); c != 0 {
		return c
	}
	if c := cmpInt(a.revision, b.revision); c != 0 {
		return c
	}
	return comparePrerelease(a.prerelease, b.prerelease)
}

// --- interval model ----------------------------------------------------------

// nugetInterval is a parsed NuGet version interval: an optional lower and upper bound,
// each inclusive or exclusive. A missing bound (hasLo/hasHi false) is ±∞.
type nugetInterval struct {
	hasLo, loIncl bool
	lo            nugetVersion
	hasHi, hiIncl bool
	hi            nugetVersion
}

// contains reports whether v falls inside the interval.
func (iv nugetInterval) contains(v nugetVersion) bool {
	if iv.hasLo {
		c := compareNuGetVersion(v, iv.lo)
		if c < 0 || (c == 0 && !iv.loIncl) {
			return false
		}
	}
	if iv.hasHi {
		c := compareNuGetVersion(v, iv.hi)
		if c > 0 || (c == 0 && !iv.hiIncl) {
			return false
		}
	}
	return true
}

// parseNuGetInterval parses a NuGet range expression into an interval. It handles the
// bracket forms and the bare "1.0" minimum-inclusive shortcut. ok is false on any invalid
// form (single-value parens "(1.0)", missing/extra comma, both endpoints missing, inverted
// or empty interval, or an endpoint failing the version grammar).
func parseNuGetInterval(expr string) (nugetInterval, bool) {
	if expr == "" {
		return nugetInterval{}, false
	}
	open := expr[0]
	if open != '[' && open != '(' {
		// Bare version → minimum-inclusive [x,) — NOT an exact match (the NuGet gotcha).
		v, ok := parseNuGetVersion(expr)
		if !ok {
			return nugetInterval{}, false
		}
		return nugetInterval{hasLo: true, loIncl: true, lo: v}, true
	}
	close := expr[len(expr)-1]
	if close != ']' && close != ')' {
		return nugetInterval{}, false
	}
	inner := expr[1 : len(expr)-1]

	if !strings.Contains(inner, ",") {
		// Single value: only "[x]" is legal (exact). "(x)", "(x]", "[x)" are invalid.
		if open != '[' || close != ']' {
			return nugetInterval{}, false
		}
		v, ok := parseNuGetVersion(strings.TrimSpace(inner))
		if !ok {
			return nugetInterval{}, false
		}
		return nugetInterval{hasLo: true, loIncl: true, lo: v, hasHi: true, hiIncl: true, hi: v}, true
	}

	loStr, hiStr, found := strings.Cut(inner, ",")
	if !found || strings.Contains(hiStr, ",") {
		return nugetInterval{}, false // more than one comma
	}
	loStr = strings.TrimSpace(loStr)
	hiStr = strings.TrimSpace(hiStr)
	if loStr == "" && hiStr == "" {
		return nugetInterval{}, false // "[,]" / "(,)" — both endpoints missing (§2e)
	}

	iv := nugetInterval{}
	if loStr != "" {
		lo, ok := parseNuGetVersion(loStr)
		if !ok {
			return nugetInterval{}, false
		}
		iv.hasLo, iv.loIncl, iv.lo = true, open == '[', lo
	}
	if hiStr != "" {
		hi, ok := parseNuGetVersion(hiStr)
		if !ok {
			return nugetInterval{}, false
		}
		iv.hasHi, iv.hiIncl, iv.hi = true, close == ']', hi
	}
	if iv.hasLo && iv.hasHi {
		switch c := compareNuGetVersion(iv.lo, iv.hi); {
		case c > 0:
			return nugetInterval{}, false // inverted "[2.0,1.0]"
		case c == 0 && !(iv.loIncl && iv.hiIncl):
			return nugetInterval{}, false // empty "[1.0,1.0)" / "(1.0,1.0)"
		}
	}
	return iv, true
}

// --- lexical guards ----------------------------------------------------------

// isNuGetFloating reports whether s is a NuGet floating version token (contains '*', e.g.
// "1.0.*", "1.*", "*"). Floating versions are manifest-side resolution hints (§2c), not
// advisory ranges; the comparator recognizes them but declines any ordering decision (§2e).
func isNuGetFloating(s string) bool {
	return strings.ContainsRune(s, '*')
}

// nugetAllowedChars reports whether s contains only characters in the modelled NuGet
// range/version alphabet [0-9A-Za-z.\-+*,\[\]()] plus surrounding whitespace. Anything
// else fails open (§2e).
func nugetAllowedChars(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9',
			c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z':
		case c == '.' || c == '-' || c == '+' || c == '*' || c == ',' ||
			c == '[' || c == ']' || c == '(' || c == ')':
		case c == ' ' || c == '\t':
		default:
			return false
		}
	}
	return true
}
