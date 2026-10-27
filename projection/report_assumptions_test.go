package projection_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// TestReportProjections_CarryAssumptions: a not_exploitable that holds only under a stated
// assumption says so on every projection, not only in report.json; one without states none.
func TestReportProjections_CarryAssumptions(t *testing.T) {
	const assumption = `library-entrypoints "none": no code outside the build imports example.com/m/lib, which reach golang.org/x/net`
	project := func(assumptions []string) (vex, sarif, html string) {
		t.Helper()
		r := report.NewBuilder(report.Subject{ResolvedCommit: "c"}).
			AddFinding(report.AdvisoryFinding{
				Advisory: report.Advisory{ID: "GO-2099-0001", Source: "osv"},
				Verdict:  report.VerdictNotExploitable,
				Evidence: report.EvidenceSummary{Basis: verdict.BasisSymbolAbsent, Detail: "no path reaches it", Assumptions: assumptions},
			}).Build()
		doc, err := projection.ProjectReportVEX(r)
		if err != nil {
			t.Fatal(err)
		}
		log, err := projection.ProjectReportSARIF(r)
		if err != nil {
			t.Fatal(err)
		}
		page, err := projection.ProjectReportHTML(r)
		if err != nil {
			t.Fatal(err)
		}
		return doc.Statements[0].ImpactStatement, log.Runs[0].Results[0].Message.Text, string(page)
	}
	vex, sarif, html := project([]string{assumption})
	if !strings.Contains(vex, assumption) {
		t.Errorf("VEX impact_statement = %q, want the assumption", vex)
	}
	if !strings.Contains(sarif, assumption) {
		t.Errorf("SARIF message = %q, want the assumption", sarif)
	}
	if !strings.Contains(html, "Holds only under the stated assumption: library-entrypoints &#34;none&#34;") {
		t.Errorf("HTML does not state the assumption")
	}
	vex, sarif, html = project(nil)
	if vex != "" || strings.Contains(sarif, "assumption") || strings.Contains(html, "Holds only under") {
		t.Errorf("unconditional refutation states an assumption: vex %q, sarif %q", vex, sarif)
	}
}
