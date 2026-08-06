// internal/pipeline/disqual_gotoolchain_u7_test.go
//
// U7 end-to-end proof: a Go stdlib/toolchain advisory carrying the EXPLICIT "go-toolchain"
// VersionScheme flows through advisory_intake → the emitted affected-range set → the
// disqualification_discovery version axis, selecting the goToolchainVersionOutsideRange comparator
// and adjudicating a two-range backport correctly. Reuses runIntakeDisqual from the U5 test.
//
// SOUNDNESS (inv.5): the version axis disqualifies (records a not-affected) ONLY when the resolved
// toolchain is provably at/past the fix on EVERY release branch; a version inside any branch range
// stays affected and PROCEEDS to reachability. No path fabricates a not-affected.
package pipeline

import "testing"

// The required anchor, CVE-2023-39325 (HTTP/2 rapid reset): fixed go1.20.10 on the 1.20.x branch
// AND go1.21.3 on mainline, two disjoint go-toolchain ranges. go1.21.5 clears BOTH bounds → the
// two-range spanning DISQUALIFIES; go1.21.0 is inside the mainline range → still affected, PROCEEDS.
func TestGoToolchainDisqual_RapidResetBackport(t *testing.T) {
	if res, scheme := runIntakeDisqual(t, "CVE-2023-39325", "go1.21.5"); scheme != "go-toolchain" || !res.Disqualified || res.Reason != ReasonVersionNotInRange {
		t.Fatalf("patched go1.21.5: scheme=%q res=%+v; want scheme go-toolchain, disqualified version_not_in_affected_range", scheme, res)
	}
	if res, scheme := runIntakeDisqual(t, "CVE-2023-39325", "go1.21.0"); scheme != "go-toolchain" || res.Disqualified || res.Reason != ReasonInsufficient {
		t.Fatalf("vulnerable go1.21.0: scheme=%q res=%+v; want scheme go-toolchain, proceed insufficient", scheme, res)
	}
	// A toolchain still on the old 1.20 branch below its branch fix is inside the 1.20 range.
	if res, _ := runIntakeDisqual(t, "CVE-2023-39325", "go1.20.5"); res.Disqualified {
		t.Fatalf("vulnerable go1.20.5 must PROCEED, got disqualified %+v", res)
	}
}

// CVE-2023-45283 (path/filepath): fixed go1.20.11 / go1.21.4. go1.21.4 clears both → disqualified.
func TestGoToolchainDisqual_FilepathBackport(t *testing.T) {
	if res, scheme := runIntakeDisqual(t, "CVE-2023-45283", "go1.21.4"); scheme != "go-toolchain" || !res.Disqualified || res.Reason != ReasonVersionNotInRange {
		t.Fatalf("patched go1.21.4: scheme=%q res=%+v; want disqualified", scheme, res)
	}
	if res, _ := runIntakeDisqual(t, "CVE-2023-45283", "go1.21.3"); res.Disqualified {
		t.Fatalf("vulnerable go1.21.3 must PROCEED, got disqualified %+v", res)
	}
}

// CVE-2024-24790 (net/netip): fixed go1.21.11 / go1.22.4. go1.22.4 clears both → disqualified.
func TestGoToolchainDisqual_NetipBackport(t *testing.T) {
	if res, scheme := runIntakeDisqual(t, "CVE-2024-24790", "go1.22.4"); scheme != "go-toolchain" || !res.Disqualified || res.Reason != ReasonVersionNotInRange {
		t.Fatalf("patched go1.22.4: scheme=%q res=%+v; want disqualified", scheme, res)
	}
	if res, _ := runIntakeDisqual(t, "CVE-2024-24790", "go1.22.0"); res.Disqualified {
		t.Fatalf("vulnerable go1.22.0 must PROCEED, got disqualified %+v", res)
	}
}

// inv.5 fail-open: a prerelease resolved toolchain (go1.21rc1) cannot be ordered, so the version
// axis fails OPEN and the case PROCEEDS — never a fabricated not-affected.
func TestGoToolchainDisqual_PrereleaseFailsOpen(t *testing.T) {
	if res, _ := runIntakeDisqual(t, "CVE-2023-39325", "go1.21rc1"); res.Disqualified {
		t.Fatalf("prerelease toolchain must FAIL OPEN, got disqualified %+v", res)
	}
}
