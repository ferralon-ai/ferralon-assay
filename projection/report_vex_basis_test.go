package projection_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// TestReportVEX_NotAffectedAlwaysJustifiedOrExplained: the OpenVEX spec requires a not_affected
// statement to carry a justification or an impact_statement. Every basis, including none and one
// this version does not know, yields one or the other, and only a basis that establishes absence
// yields vulnerable_code_not_present.
func TestReportVEX_NotAffectedAlwaysJustifiedOrExplained(t *testing.T) {
	bases := []struct {
		basis    verdict.NonExploitableBasis
		wantJust string // "" = no justification; the impact_statement must explain why
	}{
		{verdict.BasisNone, ""},
		{verdict.BasisVersionNotAffected, projection.VEXJustNotPresent},
		{verdict.BasisSymbolAbsent, projection.VEXJustNotPresent},
		{verdict.BasisSymbolUnreachable, projection.VEXJustNotInExecutePath},
		{verdict.BasisStaticRefutation, ""},
		{verdict.NonExploitableBasis("some_future_basis"), ""},
	}
	verdicts := []report.Verdict{report.VerdictDisqualified, report.VerdictNotExploitable}
	for _, v := range verdicts {
		for _, b := range bases {
			for _, detail := range []string{"", "recorded grounds"} {
				t.Run(string(v)+"/"+string(b.basis)+"/detail="+detail, func(t *testing.T) {
					r := report.Report{
						SchemaVersion: report.SchemaVersion,
						Advisories: []report.AdvisoryFinding{{
							Advisory: report.Advisory{ID: "GHSA-test", Source: "osv"},
							Verdict:  v,
							Evidence: report.EvidenceSummary{Basis: b.basis, Detail: detail},
						}},
					}
					s := statementFor(t, r)
					if s.Status != projection.VEXStatusNotAffected {
						t.Fatalf("status = %q, want not_affected", s.Status)
					}
					if s.Justification == "" && strings.TrimSpace(s.ImpactStatement) == "" {
						t.Fatal("not_affected with neither justification nor impact_statement")
					}
					if s.Justification != b.wantJust {
						t.Errorf("justification = %q, want %q", s.Justification, b.wantJust)
					}
					if b.wantJust == "" && !strings.Contains(s.ImpactStatement, "no basis") {
						t.Errorf("impact_statement = %q, want it to say no basis was recorded", s.ImpactStatement)
					}
					if b.wantJust == "" && detail != "" && !strings.Contains(s.ImpactStatement, detail) {
						t.Errorf("impact_statement = %q, want it to carry the recorded grounds %q", s.ImpactStatement, detail)
					}
				})
			}
		}
	}
}
