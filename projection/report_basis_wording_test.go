package projection

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// TestReportBasisWording: with no Detail to quote, SARIF and HTML fall back to what the basis
// establishes, and say no more than the OpenVEX justification does. Present-but-unreachable code
// is never called absent, and a basis that names nothing claims nothing.
func TestReportBasisWording(t *testing.T) {
	cases := []struct {
		basis   verdict.NonExploitableBasis
		want    string // "" = no grounds stated
		notWant []string
	}{
		{verdict.BasisSymbolUnreachable, "no path from an entry point reaches it", []string{"absent", "not present"}},
		{verdict.BasisSymbolAbsent, "absent from the build", nil},
		{verdict.BasisVersionNotAffected, "outside the advisory's affected range", nil},
		{verdict.BasisNone, "", []string{"absent", "range", "reaches"}},
		{verdict.NonExploitableBasis("some_future_basis"), "", []string{"absent", "range", "reaches"}},
	}
	for _, v := range []report.Verdict{report.VerdictNotExploitable, report.VerdictDisqualified} {
		for _, tc := range cases {
			if tc.basis == verdict.BasisSymbolUnreachable && v == report.VerdictDisqualified {
				continue // report.Validate rejects it
			}
			t.Run(string(v)+"/"+string(tc.basis), func(t *testing.T) {
				f := report.AdvisoryFinding{
					Advisory: report.Advisory{ID: "GHSA-test", Source: "osv"},
					Verdict:  v,
					Evidence: report.EvidenceSummary{Basis: tc.basis},
				}
				sarif := reportSARIFMessage(f)
				html := reportHTMLFindingFrom(f).Detail
				for name, got := range map[string]string{"SARIF": sarif, "HTML": html} {
					if tc.want != "" && !strings.Contains(got, tc.want) {
						t.Errorf("%s = %q, want it to state %q", name, got, tc.want)
					}
					for _, bad := range tc.notWant {
						if strings.Contains(got, bad) {
							t.Errorf("%s = %q claims %q", name, got, bad)
						}
					}
				}
				if tc.want == "" && html != "" {
					t.Errorf("HTML detail = %q, want none for a basis that names nothing", html)
				}
			})
		}
	}
}
