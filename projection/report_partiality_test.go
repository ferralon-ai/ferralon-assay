// report_partiality_test.go
//
// The coverage disclosure must SURVIVE every projection. A verdict withheld for honesty that renders
// nowhere is not an improvement on a false verdict — it is the same false impression delivered by
// omission instead of by assertion. So each projector is asserted to carry the withheld ids, and the
// OpenVEX projector is asserted NOT to attest them.
package projection_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// withheldReport is a Report in the exact shape M2 produces: one genuinely disqualified toolchain
// advisory (M3's lit version axis derived it) plus three withheld ones named in a single disclosure,
// alongside an unrelated coverage limit that withheld nothing.
func withheldReport() report.Report {
	pkgText := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"}
	return report.NewBuilder(report.Subject{
		Repo:           "github.com/example/widget",
		ResolvedCommit: "abc123",
	}).
		AddPackages(pkgText).
		Disqualified(
			report.Advisory{ID: "CVE-2024-24790", Source: "corpus"},
			nil,
			verdict.BasisVersionNotAffected,
			"the subject's Go toolchain floor is past every branch fix",
		).
		NotExploitable(
			report.Advisory{ID: "GO-2021-0001", Source: "osv"},
			&pkgText,
			verdict.BasisSymbolAbsent,
			"the vulnerable path is not present",
		).
		AddPartiality(report.PartialityNote{
			Reason:     report.ReasonGoToolchainNotScanned,
			Ecosystem:  "Go",
			Advisories: []string{"CVE-2023-39325", "CVE-2023-45283", "GO-2021-0264"},
		}).
		AddPartiality(report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"}).
		WithProvenance(report.Provenance{
			AnalyzerVersion: "ferralon-assay v0.2.0",
			Timestamp:       time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
		}).
		Build()
}

// TestReportVEX_WithheldAdvisoriesAreNotAttested is the property that had to fall out of the
// withholding rather than need projector code. An advisory absent from advisories[] gets no statement,
// so the OpenVEX not_affected / vulnerable_code_not_present attestation simply stops being emitted.
// Had this required a change in report_vex.go it would have meant the suppression was cosmetic and the
// claim still had a path to the wire.
func TestReportVEX_WithheldAdvisoriesAreNotAttested(t *testing.T) {
	doc, err := projection.ProjectReportVEX(withheldReport())
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}
	withheld := map[string]bool{"CVE-2023-39325": true, "CVE-2023-45283": true, "GO-2021-0264": true}
	seen := map[string]bool{}
	for _, s := range doc.Statements {
		if withheld[s.Vulnerability.ID] {
			t.Errorf("OpenVEX attests withheld advisory %s as %q/%q", s.Vulnerability.ID, s.Status, s.Justification)
		}
		seen[s.Vulnerability.ID] = true
	}
	// The DERIVED not-affected must still be attested — M3 earned that claim and M2 must not eat it.
	if !seen["CVE-2024-24790"] {
		t.Error("the disqualified toolchain advisory lost its OpenVEX statement; a derived not-affected is a claim the scanner did establish")
	}
}

// TestReportSARIF_WithheldAdvisoriesNamedInPartialityResult pins the SARIF surface after the
// gotoolchain/partiality-producer reconciliation (cycle 2026-07-31, task 05): a withheld-advisory
// limit is ONE result per note — under PartialCoverageRuleID/AnalysisLimitsRuleID, carrying no
// verdict and no basis — not one result per withheld advisory id. The ids survive as a
// properties.scanner.withheld_advisories enrichment on that result, and as a
// toolExecutionNotification on the run's invocation.
//
// REVISED 2026-07-31 (merge-backlog cycle) when this stack met tegron.report.v2 on main.
// The original test also asserted that a per-id row (main's reportSARIFNotAssessed shape)
// does NOT appear. Both surfaces are now kept, deliberately, because they serve different
// eras of the wire and neither subsumes the other:
//
//   - The per-note result is what THIS analyzer produces. v2 retired withholding in favour of
//     `undetermined` rows, so nothing here populates PartialityNote.Advisories any more; the
//     per-note result carries the loud/quiet arm and the ids ride along as enrichment.
//   - The per-id results are reachable only from a v1 document upgraded on read, or a foreign
//     producer that still populates Advisories. They exist because GitHub code scanning ingests
//     results[] and DISCARDS properties — so for those documents, a property-only disclosure is
//     invisible in the one sink most readers use. That is the same argument this stack made
//     against leaving limits in toolExecutionNotifications.
//
// They cannot double-render: reportSARIFNotAssessed skips any id already present as a row
// (rowIDs), and this analyzer emits no Advisories to render in the first place.
func TestReportSARIF_WithheldAdvisoriesNamedInPartialityResult(t *testing.T) {
	log, err := projection.ProjectReportSARIF(withheldReport())
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	run := log.Runs[0]

	// A withheld id may appear as its own row (the legacy/foreign shape), but never more than
	// once — a duplicated advisory reads as two distinct alerts in a code-scanning UI.
	for _, id := range []string{"CVE-2023-39325", "CVE-2023-45283", "GO-2021-0264"} {
		n := 0
		for _, res := range run.Results {
			if res.RuleID == id {
				n++
			}
		}
		if n > 1 {
			t.Errorf("withheld advisory %s rendered %d times; it must appear at most once", id, n)
		}
	}

	var toolchainResult *projection.SARIFResult
	for i := range run.Results {
		if run.Results[i].RuleID == projection.PartialCoverageRuleID &&
			run.Results[i].Properties != nil &&
			run.Results[i].Properties.Tegron["partiality_reason"] == report.ReasonGoToolchainNotScanned {
			toolchainResult = &run.Results[i]
		}
	}
	if toolchainResult == nil {
		t.Fatal("no SARIF result for the go-toolchain coverage limit")
	}
	if toolchainResult.Level != "warning" || toolchainResult.Kind != "review" {
		t.Errorf("go-toolchain limit = level %q / kind %q, want warning/review (loud arm)", toolchainResult.Level, toolchainResult.Kind)
	}
	if _, hasVerdict := toolchainResult.Properties.Tegron["verdict"]; hasVerdict {
		t.Error("the coverage-limit result carries a verdict property; it asserts none")
	}
	ids, ok := toolchainResult.Properties.Tegron["withheld_advisories"].([]string)
	if !ok {
		t.Fatalf("withheld_advisories = %v (%T), want []string", toolchainResult.Properties.Tegron["withheld_advisories"], toolchainResult.Properties.Tegron["withheld_advisories"])
	}
	wantIDs := []string{"CVE-2023-39325", "CVE-2023-45283", "GO-2021-0264"}
	if len(ids) != len(wantIDs) {
		t.Fatalf("withheld_advisories = %v, want %v", ids, wantIDs)
	}
	for i, want := range wantIDs {
		if ids[i] != want {
			t.Errorf("withheld_advisories[%d] = %q, want %q", i, ids[i], want)
		}
	}

	// Findings that DO carry a verdict are untouched.
	var disqualifiedResult *projection.SARIFResult
	for i := range run.Results {
		if run.Results[i].RuleID == "CVE-2024-24790" {
			disqualifiedResult = &run.Results[i]
		}
	}
	if disqualifiedResult == nil {
		t.Fatal("no SARIF result for the disqualified advisory")
	}
	if got := disqualifiedResult.Properties.Tegron["verdict"]; got != string(report.VerdictDisqualified) {
		t.Errorf("the disqualified finding's verdict = %v, want %q", got, report.VerdictDisqualified)
	}

	// The run's invocation carries one notification per coverage limit — the SARIF-spec-complete
	// slot for non-GitHub consumers, belt-and-suspenders alongside the results above.
	if len(run.Invocations) != 1 {
		t.Fatalf("run carries %d invocations, want 1", len(run.Invocations))
	}
	if got := len(run.Invocations[0].ToolExecutionNotifications); got != 2 {
		t.Fatalf("invocation carries %d notifications, want 2 (one per coverage limit)", got)
	}
}

// TestReportSARIF_CleanScanCarriesNoPartialityResults keeps the silence-when-clean guarantee: a scan
// that established everything discloses nothing, so a reader may still treat a bare SARIF as a clean
// scan.
func TestReportSARIF_CleanScanCarriesNoPartialityResults(t *testing.T) {
	log, err := projection.ProjectReportSARIF(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	for _, res := range log.Runs[0].Results {
		if res.RuleID == projection.PartialCoverageRuleID || res.RuleID == projection.AnalysisLimitsRuleID {
			t.Errorf("a fully-resolved scan emitted a coverage-limit result: %+v", res)
		}
	}
	for _, inv := range log.Runs[0].Invocations {
		if len(inv.ToolExecutionNotifications) != 0 {
			t.Errorf("a fully-resolved scan's invocation carries notifications: %+v", inv.ToolExecutionNotifications)
		}
	}
}

// TestReportHTML_WithheldAdvisoriesRenderAsAPanel asserts the disclosure is a first-class panel with
// the ids visible in the SERVER-RENDERED markup — not only inside the embedded JSON, and not only
// after the inline JS runs. A reader with JS disabled must still see what was not assessed.
func TestReportHTML_WithheldAdvisoriesRenderAsAPanel(t *testing.T) {
	out, err := projection.ProjectReportHTML(withheldReport())
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	// Strip the embedded JSON block so every assertion below is about rendered markup, not about the
	// data that happens to travel alongside it.
	html := string(out)
	if i := strings.Index(html, `id="report-data"`); i >= 0 {
		html = html[:i]
	}

	for _, want := range []string{
		"Coverage limits",
		"3 advisories not assessed",
		"not assessed",
		"no verdict",
		report.ReasonGoToolchainNotScanned,
		"CVE-2023-39325", "CVE-2023-45283", "GO-2021-0264",
		"no_manifest",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered HTML is missing %q", want)
		}
	}
	// The limit that withheld nothing must not claim otherwise.
	if strings.Count(html, `badge notassessed`) != 1 {
		t.Errorf("got %d not-assessed badges, want 1 — a limit that withheld no verdict is partial coverage, not a withholding", strings.Count(html, `badge notassessed`))
	}
	if !strings.Contains(html, "partial coverage") {
		t.Error("the no_manifest limit must render as partial coverage")
	}
}

// TestReportHTML_CleanScanRendersNoLimitsPanel is the silence-when-clean guarantee at the HTML layer.
func TestReportHTML_CleanScanRendersNoLimitsPanel(t *testing.T) {
	out, err := projection.ProjectReportHTML(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	if strings.Contains(string(out), "Coverage limits") {
		t.Error("a fully-resolved scan must render no coverage-limits panel")
	}
}

// TestReportHTML_UnrecognizedReasonCodeIsStillRendered pins the OPEN vocabulary at the render layer.
// Dropping a code a renderer does not recognize restores the silent-clean-scan failure the disclosure
// exists to prevent, so the raw code must survive even with no human sentence for it.
func TestReportHTML_UnrecognizedReasonCodeIsStillRendered(t *testing.T) {
	r := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "c"}).
		AddPartiality(report.PartialityNote{Reason: "some_future_limit_code", Advisories: []string{"CVE-9999-0001"}}).
		Build()
	out, err := projection.ProjectReportHTML(r)
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	html := string(out)
	if i := strings.Index(html, `id="report-data"`); i >= 0 {
		html = html[:i]
	}
	if !strings.Contains(html, "some_future_limit_code") || !strings.Contains(html, "CVE-9999-0001") {
		t.Error("an unrecognized reason code and its withheld ids must still render")
	}
}

// TestPartialityNote_AdvisoriesRoundTripAndOmit pins the wire shape: additive, omitted when empty, so
// a reader predating the field is unaffected (contract §11).
func TestPartialityNote_AdvisoriesRoundTripAndOmit(t *testing.T) {
	withIDs, err := json.Marshal(report.PartialityNote{Reason: "r", Advisories: []string{"B", "A"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(withIDs), `"advisories":["B","A"]`) {
		t.Errorf("advisories did not serialize: %s", withIDs)
	}
	bare, err := json.Marshal(report.PartialityNote{Reason: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bare), "advisories") {
		t.Errorf("an empty advisories list must be omitted, got %s", bare)
	}
}
