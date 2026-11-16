package projection_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// An intake disqualification carries its own basis into both projections. SARIF states it as a
// property; OpenVEX keeps not_affected but earns no justification, since nothing was adjudicated.
func TestReportProjections_IntakeBasisRendered(t *testing.T) {
	for _, basis := range []verdict.NonExploitableBasis{
		verdict.BasisAdvisoryEcosystemMismatch,
		verdict.BasisNoManifestEntry,
	} {
		r := disqualReport(t, basis, "no version or symbol comparison was performed")

		log, err := projection.ProjectReportSARIF(r)
		if err != nil {
			t.Fatalf("%s: ProjectReportSARIF: %v", basis, err)
		}
		var got any
		for _, res := range log.Runs[0].Results {
			if res.RuleID == r.Advisories[0].Advisory.ID && res.Properties != nil {
				got = res.Properties.Scanner["basis"]
			}
		}
		if got != string(basis) {
			t.Errorf("SARIF basis property = %v, want %q", got, basis)
		}

		s := statementFor(t, r)
		if s.Status != projection.VEXStatusNotAffected || s.Justification != "" {
			t.Errorf("%s: VEX status %q justification %q, want not_affected with none", basis, s.Status, s.Justification)
		}
		if !strings.Contains(s.ImpactStatement, "no basis") {
			t.Errorf("%s: impact_statement = %q", basis, s.ImpactStatement)
		}
	}
}
