package projection_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
)

func cleanSARIFReport() report.Report {
	return report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		AddFinding(report.AdvisoryFinding{
			Advisory: report.Advisory{ID: "GO-2021-0113", Source: "osv"},
			Package:  &report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"},
			Verdict:  report.VerdictNotExploitable,
			Evidence: report.EvidenceSummary{Detail: "no reachable path to the advisory symbol was found"},
		}).
		Build()
}

func partialSARIFReport(notes ...report.PartialityNote) report.Report {
	b := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		AddFinding(report.AdvisoryFinding{
			Advisory: report.Advisory{ID: "GO-2021-0113", Source: "osv"},
			Package:  &report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"},
			Verdict:  report.VerdictNotExploitable,
			Evidence: report.EvidenceSummary{Detail: "no reachable path to the advisory symbol was found"},
		})
	b.AddPartiality(notes...)
	return b.Build()
}

// The SARIF sink was the one surface that rendered a partial scan as safety: a log
// whose results are all "note"/"none" is exactly how code scanning spells "no alerts",
// so an analysis that never ran showed a green check. A disclosed limit must surface as
// a visible result.
func TestReportSARIF_PartialityEmitsVisibleResult(t *testing.T) {
	r := partialSARIFReport(report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"})

	log, err := projection.ProjectReportSARIF(r)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	run := log.Runs[0]

	var got *projection.SARIFResult
	for i := range run.Results {
		if run.Results[i].RuleID == projection.PartialCoverageRuleID {
			got = &run.Results[i]
		}
	}
	if got == nil {
		t.Fatalf("no %q result; results = %+v", projection.PartialCoverageRuleID, run.Results)
	}
	if got.Level != "warning" {
		t.Errorf("level = %q, want warning (a note-level result does not surface as an alert)", got.Level)
	}
	// "review" is SARIF for "the tool could not decide, a human must look" — a
	// disclosure. "fail" would assert a finding about the code, which this is not.
	if got.Kind != "review" {
		t.Errorf("kind = %q, want review", got.Kind)
	}
	if len(got.Locations) == 0 {
		t.Error("a result with no location is rejected by code-scanning ingestion")
	}
	if !strings.Contains(got.Message.Text, "no_manifest") {
		t.Errorf("message %q does not name the reason code", got.Message.Text)
	}
}

// The spec-native slot is also populated, so a machine consumer can read completeness
// without parsing result text. executionSuccessful stays true: the results are real and
// must not be discarded, they simply cover less.
func TestReportSARIF_PartialityRecordedOnInvocation(t *testing.T) {
	r := partialSARIFReport(report.PartialityNote{Reason: "tool_failure", Detail: "symbol_mapping (GO-2021-0113)"})

	log, err := projection.ProjectReportSARIF(r)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	invs := log.Runs[0].Invocations
	if len(invs) != 1 {
		t.Fatalf("invocations = %d, want 1", len(invs))
	}
	if !invs[0].ExecutionSuccessful {
		t.Error("executionSuccessful = false; a partial scan's results are valid and must not be discarded")
	}
	if len(invs[0].ToolExecutionNotifications) != 1 {
		t.Fatalf("notifications = %+v, want 1", invs[0].ToolExecutionNotifications)
	}
	if !strings.Contains(invs[0].ToolExecutionNotifications[0].Message.Text, "symbol_mapping") {
		t.Errorf("notification %q does not name the failed step",
			invs[0].ToolExecutionNotifications[0].Message.Text)
	}
}

// An unrecognized reason code is disclosed verbatim. Dropping it restores the silent
// clean-looking scan the field exists to prevent.
func TestReportSARIF_UnknownReasonStillDisclosed(t *testing.T) {
	r := partialSARIFReport(report.PartialityNote{Reason: "future_reason_code", Ecosystem: "PyPI"})

	log, err := projection.ProjectReportSARIF(r)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	var found bool
	for _, res := range log.Runs[0].Results {
		if strings.Contains(res.Message.Text, "future_reason_code") {
			found = true
		}
	}
	if !found {
		t.Error("unknown reason code was dropped from the SARIF log")
	}
}

// The regression gate. A fully-resolved scan must project exactly the results it always
// has — one per finding, no coverage result, and no verdict touched. This is what keeps
// the disclosure from becoming a blunt instrument that alerts on every scan.
func TestReportSARIF_CleanReportUnchanged(t *testing.T) {
	r := cleanSARIFReport()

	log, err := projection.ProjectReportSARIF(r)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	run := log.Runs[0]

	if len(run.Results) != len(r.Advisories) {
		t.Fatalf("results = %d, want %d (one per finding, no coverage result)",
			len(run.Results), len(r.Advisories))
	}
	for _, res := range run.Results {
		if res.RuleID == projection.PartialCoverageRuleID {
			t.Error("a clean scan emitted a coverage disclosure")
		}
	}
	if len(run.Invocations) != 1 || !run.Invocations[0].ExecutionSuccessful {
		t.Errorf("clean invocation = %+v, want one successful invocation", run.Invocations)
	}
	if len(run.Invocations[0].ToolExecutionNotifications) != 0 {
		t.Errorf("clean scan emitted notifications: %+v", run.Invocations[0].ToolExecutionNotifications)
	}
	// The verdict projection itself is untouched by any of this.
	if run.Results[0].Level != "note" || run.Results[0].Kind != "informational" {
		t.Errorf("not_exploitable projected as %q/%q, want note/informational",
			run.Results[0].Level, run.Results[0].Kind)
	}
}
