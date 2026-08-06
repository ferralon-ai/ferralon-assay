package pipeline

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// --- Pure predicate: disqualify ----------------------------------------------

// mkRange wraps one upper-exclusive bound as the single-range affected set the extractor returns.
func mkRange(upperExclusive string) []affectedRange {
	return []affectedRange{{UpperExclusive: upperExclusive}}
}

func TestDisqualify_VersionProvablyOutsideRange(t *testing.T) {
	// x/text@v0.3.7 against "affects < v0.3.7" → resolved version is OUTSIDE the affected set.
	got, reason := disqualify(
		mkRange("v0.3.7"), true,
		"v0.3.7", true,
		"", false,
		TrustFirstParty,
	)
	if !got {
		t.Fatalf("disqualify = false, want true (version outside affected range)")
	}
	if reason != ReasonVersionNotInRange {
		t.Fatalf("reason = %q, want %q", reason, ReasonVersionNotInRange)
	}
}

func TestDisqualify_VersionInsideRange_Proceeds(t *testing.T) {
	// x/text@v0.3.6 against "affects < v0.3.7" → version IS affected → proceed.
	got, reason := disqualify(
		mkRange("v0.3.7"), true,
		"v0.3.6", true,
		"", false,
		TrustFirstParty,
	)
	if got {
		t.Fatalf("disqualify = true, want false (version inside affected range)")
	}
	if reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", reason, ReasonInsufficient)
	}
}

func TestDisqualify_CVE202445337_VulnerableVersion_Proceeds(t *testing.T) {
	// x/crypto@v0.30.0 against "affects < v0.31.0" → version IS affected → proceed.
	got, reason := disqualify(
		mkRange("v0.31.0"), true,
		"v0.30.0", true,
		"", false,
		TrustFirstParty,
	)
	if got {
		t.Fatalf("disqualify = true, want false (v0.30.0 inside affects<v0.31.0)")
	}
	if reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", reason, ReasonInsufficient)
	}
}

func TestDisqualify_CVE202445337_PatchedVersion_Disqualifies(t *testing.T) {
	// x/crypto@v0.31.0 against "affects < v0.31.0" → resolved version is OUTSIDE the affected set.
	got, reason := disqualify(
		mkRange("v0.31.0"), true,
		"v0.31.0", true,
		"", false,
		TrustFirstParty,
	)
	if !got {
		t.Fatalf("disqualify = false, want true (v0.31.0 outside affects<v0.31.0)")
	}
	if reason != ReasonVersionNotInRange {
		t.Fatalf("reason = %q, want %q", reason, ReasonVersionNotInRange)
	}
}

func TestDisqualify_RangeUnknown_FailsOpen(t *testing.T) {
	got, reason := disqualify(nil, false, "v0.3.7", true, "", false, TrustFirstParty)
	if got {
		t.Fatalf("disqualify = true, want false (range unknown must fail open)")
	}
	if reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", reason, ReasonInsufficient)
	}
}

func TestDisqualify_VersionUnknown_FailsOpen(t *testing.T) {
	got, reason := disqualify(mkRange("v0.3.7"), true, "", false, "", false, TrustFirstParty)
	if got {
		t.Fatalf("disqualify = true, want false (version unknown must fail open)")
	}
	if reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", reason, ReasonInsufficient)
	}
}

func TestDisqualify_AmbiguousSemver_FailsOpen(t *testing.T) {
	cases := []struct {
		name       string
		upper, ver string
	}{
		{"non-semver upper", "not-a-version", "v0.3.7"},
		{"non-semver version", "v0.3.7", "garbage"},
		{"prerelease version", "v0.3.7", "v0.3.7-rc1"},
		{"prerelease bound", "v0.3.7-rc1", "v0.3.7"},
		{"empty upper", "", "v0.3.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := disqualify(mkRange(tc.upper), true, tc.ver, true, "", false, TrustFirstParty)
			if got {
				t.Fatalf("disqualify = true, want false (ambiguity must fail open): %q vs %q", tc.upper, tc.ver)
			}
			if reason != ReasonInsufficient {
				t.Fatalf("reason = %q, want %q", reason, ReasonInsufficient)
			}
		})
	}
}

func TestDisqualify_SymbolProvablyAbsent(t *testing.T) {
	// No version data, but a structured "vulnerable symbol absent" signal is present.
	got, reason := disqualify(nil, false, "", false, "absent", true, TrustFirstParty)
	if !got {
		t.Fatalf("disqualify = false, want true (vulnerable symbol provably absent)")
	}
	if reason != ReasonSymbolAbsent {
		t.Fatalf("reason = %q, want %q", reason, ReasonSymbolAbsent)
	}
}

func TestDisqualify_SymbolPresent_Proceeds(t *testing.T) {
	got, reason := disqualify(nil, false, "", false, "present", true, TrustFirstParty)
	if got {
		t.Fatalf("disqualify = true, want false (symbol present is not a disqualifier)")
	}
	if reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", reason, ReasonInsufficient)
	}
}

func TestDisqualify_NoSignals_FailsOpen(t *testing.T) {
	got, reason := disqualify(nil, false, "", false, "", false, TrustFirstParty)
	if got {
		t.Fatalf("disqualify = true, want false (no signals must fail open)")
	}
	if reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", reason, ReasonInsufficient)
	}
}

// --- Stage Run integration ----------------------------------------------------

// runDisqual seeds the upstream advisory + inventory artifacts the way stage 1/2 do,
// optionally augmented with structured signals, then runs stage 3 and returns the
// recorded discovery payload.
func runDisqual(t *testing.T, store *artifact.MemStore, caseID string) DisqualResult {
	t.Helper()
	c := &assessment.Assessment{ID: caseID}
	if err := (disqualificationDiscovery{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("Run: %v", err)
	}
	arts, err := store.Query(caseID, artifact.TypeDiscovery)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(arts) != 1 {
		t.Fatalf("got %d discovery artifacts, want 1", len(arts))
	}
	var res DisqualResult
	if err := json.Unmarshal(arts[len(arts)-1].Payload, &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return res
}

func putJSON(t *testing.T, store *artifact.MemStore, caseID string, ty artifact.Type, v any) {
	t.Helper()
	payload, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := store.Put(&artifact.Artifact{AssessmentID: caseID, Type: ty, ProducedBy: "test", Payload: payload}); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

// Phase-1 daemon inputs: stage 1 wrote only {vuln_id, source}, stage 2 only {repo, revision,
// build_dir}. No structured range or resolved version → stage 3 MUST fail open.
func TestRun_BarePhase1Inputs_FailOpen(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-bare"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]string{"vuln_id": "GO-2021-0113", "source": "osv"})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]string{"repo": "r", "revision": "rev", "build_dir": ""})

	res := runDisqual(t, store, caseID)
	if res.Disqualified {
		t.Fatalf("Disqualified = true, want false (bare Phase-1 inputs must fail open)")
	}
	if res.Reason != ReasonInsufficient {
		t.Fatalf("Reason = %q, want %q", res.Reason, ReasonInsufficient)
	}
}

// When the advisory carries a structured affected range AND the inventory carries a resolved
// version that is provably outside it, stage 3 disqualifies. (GO-2021-0113-patched, x/text@v0.3.7)
func TestRun_StructuredOutsideRange_Disqualifies(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-patched"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id":         "GO-2021-0113",
		"source":          "osv",
		"affected_ranges": []map[string]string{{"upper_exclusive": "v0.3.7"}},
		"trust_tier":      "first_party", // curated-corpus provenance intake would stamp (inv.5 gate)
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"repo":             "r",
		"revision":         "rev",
		"resolved_version": "v0.3.7",
	})

	res := runDisqual(t, store, caseID)
	if !res.Disqualified {
		t.Fatalf("Disqualified = false, want true (v0.3.7 outside affects<v0.3.7)")
	}
	if res.Reason != ReasonVersionNotInRange {
		t.Fatalf("Reason = %q, want %q", res.Reason, ReasonVersionNotInRange)
	}
}

// GO-2021-0113-trivial: x/text@v0.3.6 IS inside affects<v0.3.7 → proceed even with structured data.
func TestRun_StructuredInsideRange_Proceeds(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-trivial"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id":         "GO-2021-0113",
		"source":          "osv",
		"affected_ranges": []map[string]string{{"upper_exclusive": "v0.3.7"}},
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"repo":             "r",
		"revision":         "rev",
		"resolved_version": "v0.3.6",
	})

	res := runDisqual(t, store, caseID)
	if res.Disqualified {
		t.Fatalf("Disqualified = true, want false (v0.3.6 inside affects<v0.3.7)")
	}
}

// GO-2022-0322-absent: version IS affected (1.11.0 < 1.11.1); reachability handles absence
// downstream. Disqualifying here on a version basis would be a FALSE disqualification.
func TestRun_AbsentSymbolButAffectedVersion_Proceeds(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-absent"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id":         "GO-2022-0322",
		"source":          "osv",
		"affected_ranges": []map[string]string{{"upper_exclusive": "v1.11.1"}},
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"repo":             "r",
		"revision":         "rev",
		"resolved_version": "v1.11.0",
	})

	res := runDisqual(t, store, caseID)
	if res.Disqualified {
		t.Fatalf("Disqualified = true, want false (v1.11.0 IS affected; reachability handles absence downstream)")
	}
}

// --- Advisory table facts -----------------------------------------------------

// TestAdvisoryTable_CVE202445337_Facts pins the CVE-2024-45337 (x/crypto/ssh) facts against the
// GHSA-v778-237x-gjrc advisory so a future edit that drifts them fails loudly.
func TestAdvisoryTable_CVE202445337_Facts(t *testing.T) {
	facts, ok := AdvisoryTable["CVE-2024-45337"]
	if !ok {
		t.Fatalf("AdvisoryTable[%q] missing", "CVE-2024-45337")
	}
	if facts.Module != "golang.org/x/crypto" {
		t.Errorf("Module = %q, want %q", facts.Module, "golang.org/x/crypto")
	}
	if facts.UpperExclusive != "v0.31.0" {
		t.Errorf("UpperExclusive = %q, want %q", facts.UpperExclusive, "v0.31.0")
	}
	if facts.FixedVersion != "v0.31.0" {
		t.Errorf("FixedVersion = %q, want %q", facts.FixedVersion, "v0.31.0")
	}
	if facts.PURL != "pkg:golang/golang.org/x/crypto" {
		t.Errorf("PURL = %q, want %q", facts.PURL, "pkg:golang/golang.org/x/crypto")
	}
	wantSymbols := []string{"golang.org/x/crypto/ssh.NewServerConn"}
	if !reflect.DeepEqual(facts.Symbols, wantSymbols) {
		t.Errorf("Symbols = %v, want %v", facts.Symbols, wantSymbols)
	}
	wantCWEs := []string{"CWE-285"}
	if !reflect.DeepEqual(facts.CWEs, wantCWEs) {
		t.Errorf("CWEs = %v, want %v", facts.CWEs, wantCWEs)
	}
	if len(facts.GuardSymbols) != 0 {
		t.Errorf("GuardSymbols = %v, want empty (no declared mitigation function)", facts.GuardSymbols)
	}
}
