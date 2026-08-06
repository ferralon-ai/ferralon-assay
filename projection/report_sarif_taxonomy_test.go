package projection_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// The SARIF encoding of the taxonomy.
//
//   - did_not_run  → a visible result (level warning, kind review) on
//     PartialCoverageRuleID, AND a warning notification. Results are what code
//     scanning renders as alerts, and a run that skipped a step must not present as
//     alert-free.
//   - inherent_limit → a visible result (level note, kind informational) on the
//     DISTINCT AnalysisLimitsRuleID, AND a note notification. GitHub code scanning
//     does not ingest invocations[].toolExecutionNotifications (confirmed against its
//     "SARIF support for code scanning" reference — the supported run properties are
//     tool.driver, tool.extensions[], invocation.workingDirectory.uri and results[]
//     only), so a limit that lived only in the notification block was, in that sink,
//     disclosed nowhere. Both arms are therefore results; they stay distinguishable by
//     rule id, level, and prose. See report_sarif.go's reportSARIFPartialityResults
//     doc comment for the full accounting of what this does and does not achieve.

// resultsByRule filters an already-projected result slice down to one rule id.
func resultsByRule(results []projection.SARIFResult, ruleID string) []projection.SARIFResult {
	var out []projection.SARIFResult
	for _, res := range results {
		if res.RuleID == ruleID {
			out = append(out, res)
		}
	}
	return out
}

// partialityResultsByRule projects r and returns its results matching one rule id.
func partialityResultsByRule(t *testing.T, r report.Report, ruleID string) []projection.SARIFResult {
	t.Helper()
	log, err := projection.ProjectReportSARIF(r)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	return resultsByRule(log.Runs[0].Results, ruleID)
}

// partialityNotifications returns the run's notifications with their levels.
func partialityNotifications(t *testing.T, r report.Report) []projection.SARIFNotification {
	t.Helper()
	log, err := projection.ProjectReportSARIF(r)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	return log.Runs[0].Invocations[0].ToolExecutionNotifications
}

func partialityResults(t *testing.T, r report.Report) []projection.SARIFResult {
	t.Helper()
	return partialityResultsByRule(t, r, projection.PartialCoverageRuleID)
}

func analysisLimitsResults(t *testing.T, r report.Report) []projection.SARIFResult {
	t.Helper()
	return partialityResultsByRule(t, r, projection.AnalysisLimitsRuleID)
}

// AC — an inherent limit is visible as a code-scanning result: distinct rule, lowest
// severity, methodological prose — and is also notified in the spec-native slot.
func TestReportSARIF_InherentLimit_VisibleAsNoteResult(t *testing.T) {
	r := partialSARIFReport(
		report.PartialityNote{Reason: "reflection", Ecosystem: "Go"},
		report.PartialityNote{Reason: "dynamic_dispatch", Ecosystem: "Go"},
	)

	if got := partialityResults(t, r); len(got) != 0 {
		t.Errorf("inherent limits emitted %d did-not-run result(s) on %s; must stay on the distinct analysis-limits rule: %+v", len(got), projection.PartialCoverageRuleID, got)
	}

	results := analysisLimitsResults(t, r)
	if len(results) != 2 {
		t.Fatalf("analysis-limits results = %+v, want 2 — GitHub code scanning does not ingest toolExecutionNotifications, so this rule is the only visible disclosure in that sink", results)
	}
	for _, res := range results {
		if res.Level != "note" {
			t.Errorf("result level = %q, want note (the lowest SARIF severity — a warning escalates methodology into a run condition)", res.Level)
		}
		if len(res.Locations) == 0 {
			t.Error("a result with no location is rejected by code-scanning ingestion")
		}
		if class, _ := res.Properties.Tegron["partiality_class"].(string); class != string(report.PartialityInherentLimit) {
			t.Errorf("result partiality_class = %q, want %q", class, report.PartialityInherentLimit)
		}
		if !strings.Contains(res.Message.Text, "inherent limit of static analysis") {
			t.Errorf("result %q does not say the limit is methodological", res.Message.Text)
		}
		if strings.Contains(res.Message.Text, "Partial coverage") {
			t.Errorf("result %q borrows the did-not-run prose", res.Message.Text)
		}
	}

	notes := partialityNotifications(t, r)
	if len(notes) != 2 {
		t.Fatalf("notifications = %+v, want 2 — quiet is not suppression", notes)
	}
	for _, n := range notes {
		if n.Level != "note" {
			t.Errorf("notification level = %q, want note", n.Level)
		}
		if !strings.Contains(n.Message.Text, "inherent limit of static analysis") {
			t.Errorf("notification %q does not say the limit is methodological", n.Message.Text)
		}
	}
}

// AC — the loud arm is exactly as task 02 left it: a visible warning/review result
// plus a warning notification.
func TestReportSARIF_DidNotRun_StillAlerts(t *testing.T) {
	for _, reason := range []string{"no_manifest", "no_language_plugin", "tool_failure", "unsupported_phase1", "no_known_ingress", "cgo", "future_reason_code"} {
		r := partialSARIFReport(report.PartialityNote{Reason: reason, Ecosystem: "Go"})

		res := partialityResults(t, r)
		if len(res) != 1 {
			t.Fatalf("%s: coverage results = %d, want 1", reason, len(res))
		}
		if res[0].Level != "warning" || res[0].Kind != "review" {
			t.Errorf("%s: result = %q/%q, want warning/review", reason, res[0].Level, res[0].Kind)
		}
		if !strings.Contains(res[0].Message.Text, "Partial coverage") {
			t.Errorf("%s: result message %q lost the did-not-run framing", reason, res[0].Message.Text)
		}

		notes := partialityNotifications(t, r)
		if len(notes) != 1 || notes[0].Level != "warning" {
			t.Errorf("%s: notifications = %+v, want one at level warning", reason, notes)
		}
	}
}

// A mixed run puts the did-not-run limit on PartialCoverageRuleID and the inherent
// limit on the distinct AnalysisLimitsRuleID — never the same rule — and notifies
// both. Same split the Markdown sinks render, carried into the rule dimension SARIF
// adds.
func TestReportSARIF_MixedArms_SeparateRules(t *testing.T) {
	r := partialSARIFReport(
		report.PartialityNote{Reason: "reflection", Ecosystem: "Go"},
		report.PartialityNote{Reason: "no_language_plugin", Ecosystem: "Go"},
	)

	res := partialityResults(t, r)
	if len(res) != 1 {
		t.Fatalf("did-not-run results = %d, want 1: %+v", len(res), res)
	}
	if !strings.Contains(res[0].Message.Text, "no_language_plugin") {
		t.Errorf("the surfaced did-not-run result is %q, want the no_language_plugin limit", res[0].Message.Text)
	}
	if class, _ := res[0].Properties.Tegron["partiality_class"].(string); class != string(report.PartialityDidNotRun) {
		t.Errorf("result partiality_class = %q, want %q", class, report.PartialityDidNotRun)
	}

	limits := analysisLimitsResults(t, r)
	if len(limits) != 1 {
		t.Fatalf("analysis-limits results = %d, want 1: %+v", len(limits), limits)
	}
	if !strings.Contains(limits[0].Message.Text, "reflection") {
		t.Errorf("the surfaced analysis-limits result is %q, want the reflection limit", limits[0].Message.Text)
	}

	if got := len(partialityNotifications(t, r)); got != 2 {
		t.Errorf("notifications = %d, want 2 — both arms stay machine-readable", got)
	}
}

// A note whose Class was never stamped alerts. The loud default lives in
// EffectiveClass, so it survives a Report assembled without the Builder.
func TestReportSARIF_UnstampedNote_Alerts(t *testing.T) {
	r := partialSARIFReport()
	r.Partiality = append(r.Partiality, report.PartialityNote{Reason: "no_manifest", Ecosystem: "Go"})

	res := partialityResults(t, r)
	if len(res) != 1 || res[0].Level != "warning" {
		t.Errorf("an unstamped note must alert; results = %+v", res)
	}
}

// A limit a writer explicitly classified as inherent is honoured, even under an
// unknown reason code — that is what carrying the arm on the note buys. It still
// surfaces (on the analysis-limits rule, never partial-coverage), because
// notification-only is no longer readable in the code-scanning sink.
func TestReportSARIF_ExplicitInherentClass_OnAnalysisLimitsRule(t *testing.T) {
	r := partialSARIFReport(report.PartialityNote{Reason: "future_limit_code", Class: report.PartialityInherentLimit})

	if got := partialityResults(t, r); len(got) != 0 {
		t.Errorf("an explicitly-inherent limit landed on the did-not-run rule: %+v", got)
	}
	limits := analysisLimitsResults(t, r)
	if len(limits) != 1 || limits[0].Level != "note" {
		t.Fatalf("analysis-limits results = %+v, want one at level note", limits)
	}
	if !strings.Contains(limits[0].Message.Text, "future_limit_code") {
		t.Errorf("result %q dropped the unrecognized code", limits[0].Message.Text)
	}

	notes := partialityNotifications(t, r)
	if len(notes) != 1 || notes[0].Level != "note" {
		t.Fatalf("notifications = %+v, want one at level note", notes)
	}
	if !strings.Contains(notes[0].Message.Text, "future_limit_code") {
		t.Errorf("notification %q dropped the unrecognized code", notes[0].Message.Text)
	}
}

// An inherent-limits-only scan must still project its FINDINGS exactly as a clean
// scan does — the split changes disclosure volume, never a verdict. The scan itself
// now also carries one additional analysis-limits result (this is the fix: it must be
// visible in the code-scanning sink), so this test scopes its comparison to the
// finding-derived results only, by count and by identity (advisory rule ids never
// collide with either partiality rule).
func TestReportSARIF_InherentLimitsOnly_FindingsUnchanged(t *testing.T) {
	clean, err := projection.ProjectReportSARIF(cleanSARIFReport())
	if err != nil {
		t.Fatalf("ProjectReportSARIF(clean): %v", err)
	}
	limited, err := projection.ProjectReportSARIF(partialSARIFReport(report.PartialityNote{Reason: "reflection", Ecosystem: "Go"}))
	if err != nil {
		t.Fatalf("ProjectReportSARIF(limited): %v", err)
	}

	cleanFindings := findingResults(clean.Runs[0].Results)
	limitedFindings := findingResults(limited.Runs[0].Results)
	if len(cleanFindings) != len(limitedFindings) {
		t.Fatalf("finding results = %d, want %d (an inherent limit adds a coverage result, never a finding)",
			len(limitedFindings), len(cleanFindings))
	}
	for i := range cleanFindings {
		c, l := cleanFindings[i], limitedFindings[i]
		if c.RuleID != l.RuleID || c.Level != l.Level || c.Kind != l.Kind {
			t.Errorf("finding result %d changed: %q/%q/%q vs %q/%q/%q", i, l.RuleID, l.Level, l.Kind, c.RuleID, c.Level, c.Kind)
		}
	}

	limits := resultsByRule(limited.Runs[0].Results, projection.AnalysisLimitsRuleID)
	if len(limits) != 1 {
		t.Fatalf("analysis-limits results = %d, want 1 — the limit must be visible in the code-scanning sink", len(limits))
	}
	if got := resultsByRule(clean.Runs[0].Results, projection.AnalysisLimitsRuleID); len(got) != 0 {
		t.Error("a clean scan emitted an analysis-limits result")
	}

	if !limited.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("executionSuccessful = false; an inherent limit is not a failed run")
	}
}

// findingResults filters out both partiality rules, leaving only per-advisory
// results.
func findingResults(results []projection.SARIFResult) []projection.SARIFResult {
	var out []projection.SARIFResult
	for _, res := range results {
		if res.RuleID == projection.PartialCoverageRuleID || res.RuleID == projection.AnalysisLimitsRuleID {
			continue
		}
		out = append(out, res)
	}
	return out
}
