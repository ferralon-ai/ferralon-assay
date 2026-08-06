// report_undetermined_test.go
//
// The tegron.report.v2 `undetermined` verdict must survive every projection, and must survive it as
// a NON-verdict. The v1 predecessor of this property is in report_partiality_test.go, where the
// carrier was a scan-level note; here the carrier is the row, and the risk inverts. Withholding
// risked an advisory rendering nowhere; a first-class row risks it rendering as something —
// specifically as a fourth flavour of "fine", which is the impression the whole cycle exists to
// remove.
//
// So each projector is asserted on two axes: the advisory is VISIBLE, and it is not presented as an
// alert, a refutation, or an attestation.
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

// undeterminedReport is the shape this analyzer produces under v2: one derived disqualification
// (M3's version axis established it), one grounded refutation, two undetermined rows, and the
// scan-level limit that explains them — naming no ids, because the rows carry them.
func undeterminedReport() report.Report {
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
		Undetermined(report.Advisory{ID: "CVE-2023-39325", Source: "corpus"}, nil, report.ReasonGoToolchainNotScanned).
		Undetermined(report.Advisory{ID: "GO-2021-0264", Source: "corpus"}, nil, report.ReasonGoToolchainNotScanned).
		AddPartiality(report.PartialityNote{Reason: report.ReasonGoToolchainNotScanned, Ecosystem: "Go"}).
		WithProvenance(report.Provenance{
			AnalyzerVersion: "ferralon-assay v0.2.0",
			Timestamp:       time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
		}).
		Build()
}

var undeterminedIDs = []string{"CVE-2023-39325", "GO-2021-0264"}

// TestReportVEX_UndeterminedIsUnderInvestigationWithNoJustification is the wire-level assertion the
// cycle turns on. `not_affected` was the harm; `under_investigation` asserts nothing, and the
// justification field is the one that would let an unestablished claim back in.
func TestReportVEX_UndeterminedIsUnderInvestigationWithNoJustification(t *testing.T) {
	doc, err := projection.ProjectReportVEX(undeterminedReport())
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}

	seen := map[string]projection.VEXStatement{}
	for _, s := range doc.Statements {
		seen[s.Vulnerability.ID] = s
	}
	for _, id := range undeterminedIDs {
		s, ok := seen[id]
		if !ok {
			t.Errorf("no OpenVEX statement for %s — under v2 the advisory is attested under_investigation, not omitted", id)
			continue
		}
		if s.Status != projection.VEXStatusUnderInvestigation {
			t.Errorf("%s status = %q, want %q", id, s.Status, projection.VEXStatusUnderInvestigation)
		}
		if s.Justification != "" {
			t.Errorf("%s justification = %q, want empty — nothing was established, so there is nothing to justify", id, s.Justification)
		}
		if s.ImpactStatement != "" {
			t.Errorf("%s impact_statement = %q, want empty — an impact statement characterizes a finding, and there is none", id, s.ImpactStatement)
		}
	}
	// The established verdicts are untouched.
	if s := seen["CVE-2024-24790"]; s.Status != projection.VEXStatusNotAffected {
		t.Errorf("CVE-2024-24790 status = %q, want %q — a DERIVED not-affected is still attested", s.Status, projection.VEXStatusNotAffected)
	}
}

// TestReportSARIF_UndeterminedIsReviewNeverAnAlert pins the presentation M2 built for the withheld
// case, now driven off the row: visible in the log, never an alert, never counted as a finding.
func TestReportSARIF_UndeterminedIsReviewNeverAnAlert(t *testing.T) {
	log, err := projection.ProjectReportSARIF(undeterminedReport())
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	results := log.Runs[0].Results

	for _, id := range undeterminedIDs {
		var found int
		for _, res := range results {
			if res.RuleID != id {
				continue
			}
			found++
			if res.Level != "none" {
				t.Errorf("%s level = %q, want \"none\" — an unassessed advisory is not an alert", id, res.Level)
			}
			if res.Kind != "review" {
				t.Errorf("%s kind = %q, want \"review\" (SARIF's requires-human-review)", id, res.Kind)
			}
			if !strings.Contains(res.Message.Text, "NOT ASSESSED") {
				t.Errorf("%s message does not say NOT ASSESSED: %q", id, res.Message.Text)
			}
			if !strings.Contains(res.Message.Text, "not a statement that the codebase is unaffected") {
				t.Errorf("%s message omits the closing disclaimer, which is the load-bearing sentence: %q", id, res.Message.Text)
			}
			props := res.Properties.Tegron
			if props["verdict"] != "undetermined" {
				t.Errorf("%s properties.verdict = %v, want undetermined", id, props["verdict"])
			}
			if props["assessed"] != false {
				t.Errorf("%s properties.assessed = %v, want false — this is the field a consumer filters on", id, props["assessed"])
			}
			if props["undetermined_reason"] != report.ReasonGoToolchainNotScanned {
				t.Errorf("%s properties.undetermined_reason = %v, want %q", id, props["undetermined_reason"], report.ReasonGoToolchainNotScanned)
			}
			if _, ok := props["basis"]; ok {
				t.Errorf("%s carries a basis property: %v", id, props["basis"])
			}
			if len(res.Locations) == 0 {
				t.Errorf("%s has no location — GitHub code scanning rejects a result with none", id)
			}
		}
		if found != 1 {
			t.Errorf("%s appears %d times in the SARIF results, want exactly 1", id, found)
		}
	}
}

// TestReportSARIF_NoDoubleRenderWhenARowAndAResidualNoteShareAnID is the mixed-shape guard. It is
// reachable through a partiality note another producer populated, or a hand-assembled report that
// both converted an id and left it in the list; either way one advisory must render once. Under v1
// the note-driven results were the only carrier, so this could not arise.
func TestReportSARIF_NoDoubleRenderWhenARowAndAResidualNoteShareAnID(t *testing.T) {
	r := undeterminedReport()
	r.Partiality = []report.PartialityNote{{
		Reason:    report.ReasonGoToolchainNotScanned,
		Ecosystem: "Go",
		// CVE-2023-39325 is already an undetermined ROW above; CVE-2099-0001 is not.
		Advisories: []string{"CVE-2023-39325", "CVE-2099-0001"},
	}}

	log, err := projection.ProjectReportSARIF(r)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	counts := map[string]int{}
	for _, res := range log.Runs[0].Results {
		counts[res.RuleID]++
	}
	if counts["CVE-2023-39325"] != 1 {
		t.Errorf("CVE-2023-39325 renders %d times — an id that is both a row and a withheld id must render once", counts["CVE-2023-39325"])
	}
	if counts["CVE-2099-0001"] != 1 {
		t.Errorf("CVE-2099-0001 renders %d times, want 1 — an id ONLY in the note still has to be surfaced or it vanishes", counts["CVE-2099-0001"])
	}
}

// TestReportHTML_UndeterminedRendersAsNotAssessed asserts the server-rendered markup, not the
// embedded JSON: a reader with JS disabled must see the row and its badge. The count in the coverage
// heading is asserted too, because that heading is what a skimming reader takes away.
func TestReportHTML_UndeterminedRendersAsNotAssessed(t *testing.T) {
	out, err := projection.ProjectReportHTML(undeterminedReport())
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	html := string(out)

	for _, want := range []string{
		`<span class="badge notassessed">Not assessed</span>`,
		"2 advisories not assessed",
		report.ReasonGoToolchainNotScanned,
		`id="n-undetermined"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML is missing %q", want)
		}
	}
	for _, id := range undeterminedIDs {
		if !strings.Contains(html, id) {
			t.Errorf("HTML does not name %s", id)
		}
	}
	// The badge must not reuse the not_exploitable class: a reader scanning colours would read an
	// unassessed advisory as a grounded-safe one.
	if strings.Contains(html, `<span class="badge info">Not assessed</span>`) {
		t.Error("the not-assessed badge reuses the not_exploitable class")
	}
}

// TestReportHTML_NoDoubleCountWhenARowAndAResidualNoteShareAnID mirrors the SARIF guard on the
// surface where the miscount would be loudest: the "N advisories not assessed" heading.
func TestReportHTML_NoDoubleCountWhenARowAndAResidualNoteShareAnID(t *testing.T) {
	r := undeterminedReport()
	r.Partiality = []report.PartialityNote{{
		Reason:     report.ReasonGoToolchainNotScanned,
		Ecosystem:  "Go",
		Advisories: []string{"CVE-2023-39325", "GO-2021-0264", "CVE-2099-0001"},
	}}

	out, err := projection.ProjectReportHTML(r)
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	html := string(out)
	// Two rows plus one genuinely withheld id = three, not five.
	if !strings.Contains(html, "3 advisories not assessed") {
		t.Errorf("coverage heading does not read \"3 advisories not assessed\"; the two ids that are also rows were counted twice")
	}
}

// TestReportHTML_EmbeddedJSONCarriesTheVerdictVerbatim keeps the page's two halves honest with each
// other: the inline JS counts verdicts off the embedded JSON, so a verdict string the JS does not
// know would silently drop out of the donut and the legend.
func TestReportHTML_EmbeddedJSONCarriesTheVerdictVerbatim(t *testing.T) {
	out, err := projection.ProjectReportHTML(undeterminedReport())
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	html := string(out)
	if !strings.Contains(html, `"verdict": "undetermined"`) {
		t.Error("embedded JSON does not carry the undetermined verdict")
	}
	if !strings.Contains(html, "undetermined: 0") {
		t.Error("the inline JS counts object has no undetermined key, so the donut and legend would drop those rows")
	}
}

// TestReportJSON_UndeterminedSerializesAsTheContractDescribes is the wire-shape assertion a
// downstream reader is coded against: verdict, reason, and NO basis.
func TestReportJSON_UndeterminedSerializesAsTheContractDescribes(t *testing.T) {
	raw, err := json.MarshalIndent(undeterminedReport(), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Advisories    []struct {
			Advisory struct {
				ID string `json:"id"`
			} `json:"advisory"`
			Verdict            string `json:"verdict"`
			UndeterminedReason string `json:"undetermined_reason"`
			Evidence           struct {
				Basis  string `json:"basis"`
				Detail string `json:"detail"`
			} `json:"evidence"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.SchemaVersion != "tegron.report.v2" {
		t.Errorf("schema_version = %q, want tegron.report.v2", doc.SchemaVersion)
	}
	var checked int
	for _, f := range doc.Advisories {
		if f.Verdict != "undetermined" {
			continue
		}
		checked++
		if f.UndeterminedReason != report.ReasonGoToolchainNotScanned {
			t.Errorf("%s undetermined_reason = %q", f.Advisory.ID, f.UndeterminedReason)
		}
		if f.Evidence.Basis != "" {
			t.Errorf("%s serialized a basis %q", f.Advisory.ID, f.Evidence.Basis)
		}
		if f.Evidence.Detail == "" {
			t.Errorf("%s serialized no detail — the human sentence is what a report reader sees first", f.Advisory.ID)
		}
	}
	if checked != len(undeterminedIDs) {
		t.Errorf("found %d undetermined rows in the JSON, want %d", checked, len(undeterminedIDs))
	}
	// The field must be absent, not empty, on a verdict that established something.
	if strings.Contains(string(raw), `"undetermined_reason": ""`) {
		t.Error("undetermined_reason serialized as an empty string; it is omitempty for a reason")
	}
}
