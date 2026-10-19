package report

import (
	"strings"
	"testing"
)

// TestUndeterminedDetail_RangeAbsent: the range-absent row explains itself in words, not through
// the raw-code fallback.
func TestUndeterminedDetail_RangeAbsent(t *testing.T) {
	got := UndeterminedDetail(ReasonAdvisoryRangeAbsent)
	if strings.Contains(got, ReasonAdvisoryRangeAbsent) || !strings.Contains(got, "version range") {
		t.Errorf("UndeterminedDetail(%q) = %q, want the range-absent explanation", ReasonAdvisoryRangeAbsent, got)
	}
}

// TestValidate_AdvisoryBoundsOnlyOnRangeAbsent: partial bounds describe a range-absent advisory and
// nothing else, so another finding carrying them is malformed.
func TestValidate_AdvisoryBoundsOnlyOnRangeAbsent(t *testing.T) {
	bounds := []AdvisoryBound{{Introduced: "2.0.0"}}
	for _, tc := range []struct {
		name    string
		f       AdvisoryFinding
		wantErr bool
	}{
		{
			name: "range absent",
			f: AdvisoryFinding{Verdict: VerdictUndetermined, UndeterminedReason: ReasonAdvisoryRangeAbsent,
				Evidence: EvidenceSummary{AdvisoryBounds: bounds}},
		},
		{
			name: "another undetermined reason",
			f: AdvisoryFinding{Verdict: VerdictUndetermined, UndeterminedReason: ReasonGoToolchainNotScanned,
				Evidence: EvidenceSummary{AdvisoryBounds: bounds}},
			wantErr: true,
		},
		{
			name:    "a candidate",
			f:       AdvisoryFinding{Verdict: VerdictReachableCandidate, Evidence: EvidenceSummary{ReachablePath: "a → b", AdvisoryBounds: bounds}},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.f.Advisory = Advisory{ID: "GHSA-x", Source: "corpus"}
			r := Report{SchemaVersion: SchemaVersion, Advisories: []AdvisoryFinding{tc.f}}
			err := r.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "advisory_bounds") {
				t.Errorf("Validate() = %v, want the advisory_bounds check", err)
			}
		})
	}
}
