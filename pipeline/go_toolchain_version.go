// internal/pipeline/go_toolchain_version.go
//
// Go stdlib/toolchain RELEASE version comparison for the disqualification axis. This is a
// SEPARATE scheme from the default gomod path: gomod versions are module semver
// (golang.org/x/mod/semver, which REQUIRES a leading "v" and rejects "go1.21.3"), whereas a
// Go stdlib/toolchain advisory (e.g. CVE-2023-39325, the HTTP/2 rapid-reset) is fixed at
// TOOLCHAIN releases like go1.20.10 / go1.21.3 — a scheme x/mod/semver cannot order at all.
//
// The advisory carries the "go-toolchain" scheme token EXPLICITLY (there is no module PURL for
// the toolchain itself, so schemeFromPURL never derives it — pkg:golang stays gomod). A
// backport advisory whose fix spans two release branches (1.20.x and mainline 1.21.x) declares
// TWO disjoint AffectedRanges; each range's Fixed is the per-branch upper-exclusive bound, and
// U2's versionOutsideRanges reducer reasons over the whole set — this comparator plugs into that
// for free.
//
// Grammar accepted: an OPTIONAL "go" prefix (go1.21.3) — as the toolchain reports it — or the
// BARE form (1.21.3) — as OSV records the fix versions — followed by two or three dot-separated
// NON-NEGATIVE integer segments (major.minor[.patch]; a missing patch is 0, so go1.21 == go1.21.0).
//
// A corpus BOUND (an advisory's introduced / fixed value, never a resolved toolchain) may also be
// one of exactly two semver prerelease forms on a full MAJOR.MINOR.PATCH: "-0" (the minimum
// prerelease of that release, how the corpus writes "from the start of the 1.26 line") and
// "-rc.N". They order X.Y.Z-0 < X.Y.Z-rc.N (by N) < X.Y.Z. See parseGoToolchainBound.
//
// Both entry points FAIL OPEN (ok=false) on ANY input outside that grammar (inv.5): an empty or
// unbounded value, any other prerelease/rc/beta (go1.21rc1, go1.22beta1, go1.21.0-rc), a
// v-prefixed module semver (v0.17.0 — the WRONG scheme), too few/many segments, or any exotic
// token. A mis-parsed version must never yield a confident, possibly-wrong ordering that
// fabricates a not-affected.

package pipeline

import "strings"

// goToolchainVersionOutsideRange reports whether ver is provably outside the affected set
// affects<upper under Go toolchain/stdlib release ordering. ok is false (no proof) on any input
// the comparator cannot confidently order. Provably-outside means
// compareGoToolchain(ver, upper) >= 0 — i.e. the resolved toolchain is at or past the fix.
func goToolchainVersionOutsideRange(ver, upper string) (outside bool, ok bool) {
	a, aok := parseGoToolchainBound(ver)
	b, bok := parseGoToolchainBound(upper)
	if !aok || !bok {
		return false, false
	}
	return compareGoToolchain(a, b) >= 0, true
}

// goToolchainVersion is a parsed Go release version: three numeric segments. A missing patch
// segment is 0 (go1.21 == go1.21.0). pre is set only by parseGoToolchainBound.
type goToolchainVersion struct {
	major, minor, patch int
	pre                 goPrerelease
}

// goPrerelease is the prerelease of a corpus bound. The zero value is the release itself.
type goPrerelease struct {
	set  bool
	rank int // -1 for "-0", N for "-rc.N"
}

// parseGoToolchainVersion parses "[go]MAJOR.MINOR[.PATCH]" into its numeric segments. ok is
// false on ANY malformed input so the caller fails open (inv.5): empty, a bare "go"/"go1" with
// no minor, fewer than 2 or more than 3 segments, a non-numeric segment (this is how a
// prerelease/rc/beta such as "1.21rc1" or a v-prefixed module version such as "v0.17.0" fails
// open), or a negative/`+`-signed segment.
func parseGoToolchainVersion(s string) (goToolchainVersion, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return goToolchainVersion{}, false
	}
	// Optional toolchain "go" prefix. The bare form (OSV's fix versions) has none.
	s = strings.TrimPrefix(s, "go")
	if s == "" {
		return goToolchainVersion{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return goToolchainVersion{}, false
	}
	var seg [3]int
	for i, p := range parts {
		n, ok := atoiNonNeg(p)
		if !ok {
			return goToolchainVersion{}, false
		}
		seg[i] = n
	}
	return goToolchainVersion{major: seg[0], minor: seg[1], patch: seg[2]}, true
}

// parseGoToolchainBound parses a version on the comparison axis: everything
// parseGoToolchainVersion accepts, plus the corpus's prerelease bound forms "-0" and "-rc.N" on a
// full MAJOR.MINOR.PATCH (optional "go" prefix). Any other suffix is ok=false.
//
// It is for bounds and for a version compared against them. The resolved ToolchainFact reads its
// sources through parseGoToolchainVersion, which stays release-only: formatGoToolchainVersion
// writes no prerelease, so a prerelease admitted there would be reported as the release above it.
func parseGoToolchainBound(s string) (goToolchainVersion, bool) {
	core, pre, hasPre := strings.Cut(strings.TrimSpace(s), "-")
	if !hasPre {
		return parseGoToolchainVersion(s)
	}
	if strings.Count(strings.TrimPrefix(core, "go"), ".") != 2 {
		return goToolchainVersion{}, false
	}
	v, ok := parseGoToolchainVersion(core)
	if !ok {
		return goToolchainVersion{}, false
	}
	switch {
	case pre == "0":
		v.pre = goPrerelease{set: true, rank: -1}
	case strings.HasPrefix(pre, "rc."):
		num := strings.TrimPrefix(pre, "rc.")
		n, nok := atoiNonNeg(num)
		if !nok || (len(num) > 1 && num[0] == '0') {
			return goToolchainVersion{}, false
		}
		v.pre = goPrerelease{set: true, rank: n}
	default:
		return goToolchainVersion{}, false
	}
	return v, true
}

// compareGoToolchain returns -1/0/+1 comparing two parsed versions: release segments
// component-wise, then a prerelease below the release it precedes, "-0" below every "-rc.N", and
// "-rc.N" by N.
func compareGoToolchain(a, b goToolchainVersion) int {
	if c := cmpInt(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpInt(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpInt(a.patch, b.patch); c != 0 {
		return c
	}
	switch {
	case a.pre.set && b.pre.set:
		return cmpInt(a.pre.rank, b.pre.rank)
	case a.pre.set:
		return -1
	case b.pre.set:
		return 1
	}
	return 0
}
