package report

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// TestValidateSymbolUnreachableBasisOnlyOnNotExploitable: the reachability basis grounds a
// not_exploitable and nothing else. Each rejected finding validates without the basis, so the
// rejection is the basis rule's.
func TestValidateSymbolUnreachableBasisOnlyOnNotExploitable(t *testing.T) {
	cases := []struct {
		name   string
		f      AdvisoryFinding
		wantOK bool
	}{
		{"not_exploitable", AdvisoryFinding{Verdict: VerdictNotExploitable, Evidence: EvidenceSummary{Detail: "no path"}}, true},
		{"disqualified", AdvisoryFinding{Verdict: VerdictDisqualified, Evidence: EvidenceSummary{Detail: "d"}}, false},
		{"reachable_candidate", AdvisoryFinding{Verdict: VerdictReachableCandidate, Evidence: EvidenceSummary{ReachablePath: "a → b"}}, false},
		{"undetermined", AdvisoryFinding{Verdict: VerdictUndetermined, UndeterminedReason: ReasonAnalysisDidNotRun,
			Evidence: EvidenceSummary{Detail: UndeterminedDetail(ReasonAnalysisDidNotRun)}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.f
			f.Advisory = Advisory{ID: "X", Source: "osv"}
			if !tc.wantOK {
				if err := NewBuilder(Subject{ResolvedCommit: "c"}).AddFinding(f).Build().Validate(); err != nil {
					t.Fatalf("fixture invalid without the basis: %v", err)
				}
			}
			f.Evidence.Basis = verdict.BasisSymbolUnreachable
			err := NewBuilder(Subject{ResolvedCommit: "c"}).AddFinding(f).Build().Validate()
			if tc.wantOK && err != nil {
				t.Fatalf("want accepted, got %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatal("want rejected, got nil")
			}
		})
	}
}
