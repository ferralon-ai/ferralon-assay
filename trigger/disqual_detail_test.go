package trigger

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// seedDisqualReason records a disqualifying discovery artifact carrying an explicit reason
// code, so a Report finding can be built for any axis the pipeline can disqualify on.
func seedDisqualReason(t *testing.T, store *artifact.MemStore, assessmentID, reason string) {
	t.Helper()
	payload, err := json.Marshal(pipeline.DisqualResult{Disqualified: true, Reason: reason})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := store.Put(&artifact.Artifact{
		AssessmentID: assessmentID, Type: artifact.TypeDiscovery, ProducedBy: "test", Payload: payload,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

func disqualFinding(t *testing.T, reason string) report.AdvisoryFinding {
	t.Helper()
	store := artifact.NewMemStore()
	seedDisqualReason(t, store, "a1", reason)
	return finding(store, "a1", report.Advisory{ID: "TEST-0001", Source: "test"}, nil)
}

// The defect: every disqualification reason code outside the version and symbol axes fell to a
// default arm reading "provably not affected". An advisory disqualified at intake — the package
// is absent from the manifest, or the advisory belongs to another ecosystem — reached the
// customer asserting a comparison that never ran. These codes record "not adjudicable here at
// all" (pipeline/stages.go), not an adjudicated clearance.
//
// This test fails if any non-version, non-symbol reason code ever again produces a detail string
// asserting a version or symbol comparison.
func TestDisqualDetail_NonAdjudicatedAxesClaimNoComparison(t *testing.T) {
	// Phrases that assert an adjudicated comparison against the subject. None may appear on a
	// reason code that records no comparison having been performed.
	adjudicatedClaims := []string{
		"provably not affected",
		"outside the advisory's affected range",
		"absent from the built artifact",
	}

	for _, reason := range []string{
		pipeline.ReasonAdvisoryEcosystemMismatch,
		pipeline.ReasonNoManifestEntry,
		// A reason code this function has never seen. The default arm must be honest for it
		// too: an unrecognized axis is the case with the least standing to claim a comparison.
		"some_axis_added_later",
	} {
		t.Run(reason, func(t *testing.T) {
			f := disqualFinding(t, reason)
			if f.Verdict != report.VerdictDisqualified {
				t.Fatalf("verdict = %q, want %q", f.Verdict, report.VerdictDisqualified)
			}
			detail := f.Evidence.Detail
			if detail == "" {
				t.Fatal("detail is empty — a disqualification must state its grounds")
			}
			for _, claim := range adjudicatedClaims {
				if strings.Contains(detail, claim) {
					t.Errorf("detail %q asserts %q, but reason %q records no comparison having been performed",
						detail, claim, reason)
				}
			}
			if !strings.Contains(detail, "comparison was performed") {
				t.Errorf("detail %q does not say which comparison was skipped; reason %q is not adjudicable "+
					"against this subject and the detail must say so", detail, reason)
			}
			// The structured half of the same claim. An absent Basis is how this Report
			// states "no refutation grounds" (report.go:94); a reason code that adjudicated
			// nothing must not carry grounds a consumer can act on.
			if f.Evidence.Basis != verdict.BasisNone {
				t.Errorf("basis = %q, want none: reason %q adjudicated nothing", f.Evidence.Basis, reason)
			}
		})
	}
}

// The two adjudicated axes keep their grounds: this test would otherwise pass by emptying every
// detail string.
func TestDisqualDetail_AdjudicatedAxesKeepTheirGrounds(t *testing.T) {
	for reason, want := range map[string]string{
		pipeline.ReasonVersionNotInRange: "outside the advisory's affected range",
		pipeline.ReasonSymbolAbsent:      "absent from the built artifact",
	} {
		f := disqualFinding(t, reason)
		if !strings.Contains(f.Evidence.Detail, want) {
			t.Errorf("reason %q: detail = %q, want it to contain %q", reason, f.Evidence.Detail, want)
		}
	}
}
