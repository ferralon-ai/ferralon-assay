package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// TestFinding_BasisPerGround: each ground of a not_exploitable stamps the basis it establishes, and
// the OpenVEX statement claims no more than that basis. Code that is present but unreached is
// vulnerable_code_not_in_execute_path; only code the build never holds or loads is
// vulnerable_code_not_present.
func TestFinding_BasisPerGround(t *testing.T) {
	cases := []struct {
		name      string
		finding   func(*testing.T) report.AdvisoryFinding
		wantBasis verdict.NonExploitableBasis
		wantJust  string
	}{
		{
			name:      "arm A: every symbol searched in the package, no path",
			finding:   yamlSearched().finding,
			wantBasis: verdict.BasisSymbolUnreachable,
			wantJust:  projection.VEXJustNotInExecutePath,
		},
		{
			name:      "arm A: present symbols unreached, target-conditional symbols undefined",
			finding:   newTargetConditionalFixture().finding,
			wantBasis: verdict.BasisSymbolUnreachable,
			wantJust:  projection.VEXJustNotInExecutePath,
		},
		{
			name:      "arm B: call-graph refutation",
			finding:   netNotReached().finding,
			wantBasis: verdict.BasisSymbolUnreachable,
			wantJust:  projection.VEXJustNotInExecutePath,
		},
		{
			name: "arm B: package_not_loaded",
			finding: func(t *testing.T) report.AdvisoryFinding {
				fx := yamlSearched()
				fx.advisorySymbols = nil
				fx.reach.Searched = nil
				fx.affected = []string{"pkg:pypi/pyyaml"}
				fx.reach.Refutation = refutation("pkg:pypi/PyYAML")
				return fx.finding(t)
			},
			wantBasis: verdict.BasisSymbolUnreachable,
			wantJust:  projection.VEXJustNotInExecutePath,
		},
		{
			name: "arm B: a refutation basis this version does not know",
			finding: func(t *testing.T) report.AdvisoryFinding {
				fx := netNotReached()
				fx.reach.Refutation.Basis = "some_future_basis"
				return fx.finding(t)
			},
			wantBasis: verdict.BasisSymbolUnreachable,
			wantJust:  projection.VEXJustNotInExecutePath,
		},
		{
			name:      "outside the build: no module holds or declares it",
			finding:   gogsOutsideBuild().finding,
			wantBasis: verdict.BasisSymbolAbsent,
			wantJust:  projection.VEXJustNotPresent,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.finding(t)
			if f.Verdict != report.VerdictNotExploitable {
				t.Fatalf("got %s/%q, want not_exploitable", f.Verdict, f.UndeterminedReason)
			}
			if f.Evidence.Basis != tc.wantBasis {
				t.Errorf("basis = %q, want %q", f.Evidence.Basis, tc.wantBasis)
			}
			r := report.Report{SchemaVersion: report.SchemaVersion, Advisories: []report.AdvisoryFinding{f}}
			if err := r.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			doc, err := projection.ProjectReportVEX(r)
			if err != nil {
				t.Fatalf("ProjectReportVEX: %v", err)
			}
			s := doc.Statements[0]
			if s.Status != projection.VEXStatusNotAffected || s.Justification != tc.wantJust {
				t.Errorf("VEX = %s/%q, want not_affected/%q", s.Status, s.Justification, tc.wantJust)
			}
		})
	}
}
