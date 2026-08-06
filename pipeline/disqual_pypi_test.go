// internal/pipeline/disqual_pypi_test.go
//
// Hermetic proof of the Python (PyPI) disqualification path: a normalized advisory
// carrying a PEP 440 upper-exclusive bound (scheme "pypi") plus a resolved installed
// version drive disqualification_discovery. patched (installed >= fixed) → DISQUALIFIED;
// vulnerable (installed < fixed) → PROCEEDS; UNRESOLVED/unparseable → PROCEEDS (fail
// open, never a false not-affected — inv.5). It mirrors disqual_npm_test.go's shape,
// exercising the PEP 440 gotchas at the pipeline seam (epoch, post-release, numeric
// ordering) that a naive comparator would get wrong.
package pipeline

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

func runPypiDisqual(t *testing.T, resolvedVersion, upper string) DisqualResult {
	t.Helper()
	store := artifact.NewMemStore()
	caseID := "case-pypi-dep"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id":         "CVE-2025-5120",
		"affected_ranges": []map[string]string{{"upper_exclusive": upper, "scheme": "pypi"}},
		"trust_tier":      "first_party", // curated-corpus provenance intake would stamp (inv.5 gate)
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"resolved_version": resolvedVersion,
	})
	return runDisqual(t, store, caseID)
}

// PATCHED: installed 1.4.0 == fixed 1.4.0 (affects < 1.4.0) → provably outside → DISQUALIFIED.
func TestPypiDisqual_PatchedVersion_Disqualifies(t *testing.T) {
	res := runPypiDisqual(t, "1.4.0", "1.4.0")
	if !res.Disqualified {
		t.Fatalf("patched (1.4.0 >= fixed 1.4.0) must DISQUALIFY, got %+v", res)
	}
	if res.Reason != ReasonVersionNotInRange {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonVersionNotInRange)
	}
}

// VULNERABLE: installed 1.3.9 < fixed 1.4.0 → inside affected → PROCEEDS.
func TestPypiDisqual_VulnerableVersion_Proceeds(t *testing.T) {
	res := runPypiDisqual(t, "1.3.9", "1.4.0")
	if res.Disqualified {
		t.Fatalf("vulnerable (1.3.9 < fixed 1.4.0) must PROCEED, got %+v", res)
	}
	if res.Reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonInsufficient)
	}
}

// A prerelease of the fixed version sorts BELOW the release, so it is still inside the
// affected set → PROCEEDS (the honesty guard against a naive "a1 looks bigger" bug).
func TestPypiDisqual_PrereleaseOfFixed_Proceeds(t *testing.T) {
	res := runPypiDisqual(t, "1.4.0a1", "1.4.0")
	if res.Disqualified {
		t.Fatalf("prerelease 1.4.0a1 < fixed 1.4.0 must PROCEED, got %+v", res)
	}
}

// A post-release of the fixed version sorts ABOVE it → outside affected → DISQUALIFIED.
func TestPypiDisqual_PostreleaseOfFixed_Disqualifies(t *testing.T) {
	res := runPypiDisqual(t, "1.4.0.post1", "1.4.0")
	if !res.Disqualified {
		t.Fatalf("post-release 1.4.0.post1 >= fixed 1.4.0 must DISQUALIFY, got %+v", res)
	}
}

// A numeric-ordering trap: had the comparator been lexical, "1.10.0" would sort BELOW
// "1.9.0" and wrongly fail to disqualify. PEP 440 numeric ordering disqualifies it.
func TestPypiDisqual_NumericOrdering_NotLexical(t *testing.T) {
	res := runPypiDisqual(t, "1.10.0", "1.9.0")
	if !res.Disqualified {
		t.Fatalf("1.10.0 >= 1.9.0 (numeric) must DISQUALIFY; a lexical compare would wrongly proceed: %+v", res)
	}
}

// UNRESOLVED / unparseable installed version must FAIL OPEN (proceed), never a false
// not-affected (inv.5).
func TestPypiDisqual_UnparseableVersion_FailsOpen(t *testing.T) {
	res := runPypiDisqual(t, "not-a-version", "1.4.0")
	if res.Disqualified {
		t.Fatalf("unparseable installed version must FAIL OPEN (proceed), got %+v", res)
	}
}
