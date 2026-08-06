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
// Both entry points FAIL OPEN (ok=false) on ANY input outside that grammar (inv.5): an empty or
// unbounded value, a prerelease/rc/beta (go1.21rc1, go1.21.0-rc.1 — a non-numeric segment), a
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
	a, aok := parseGoToolchainVersion(ver)
	b, bok := parseGoToolchainVersion(upper)
	if !aok || !bok {
		return false, false
	}
	return compareGoToolchain(a, b) >= 0, true
}

// goToolchainVersion is a parsed Go release version: three numeric segments. A missing patch
// segment is 0 (go1.21 == go1.21.0).
type goToolchainVersion struct {
	major, minor, patch int
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

// compareGoToolchain returns -1/0/+1 comparing two parsed release versions component-wise.
func compareGoToolchain(a, b goToolchainVersion) int {
	if c := cmpInt(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpInt(a.minor, b.minor); c != 0 {
		return c
	}
	return cmpInt(a.patch, b.patch)
}
