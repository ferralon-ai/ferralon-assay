package projection_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// maliciousReport builds a minimal Report carrying one VerdictMaliciousPresent finding — the one
// decisive OSS "affected" — so each projector can be asserted for the new verdict.
func maliciousReport() report.Report {
	pkg := report.Package{Ecosystem: "npm", Name: "evil-pkg", Version: "1.0.1", PURL: "pkg:npm/evil-pkg@1.0.1"}
	return report.NewBuilder(report.Subject{Repo: "github.com/example/app", ResolvedCommit: "deadbeef"}).
		AddPackage(pkg).
		AddFinding(report.AdvisoryFinding{
			Advisory: report.Advisory{ID: "MAL-2024-1", Source: "osv"},
			Package:  &pkg,
			Verdict:  report.VerdictMaliciousPresent,
			Evidence: report.EvidenceSummary{Detail: "the resolved dependency version 1.0.1 is listed by the advisory as a known-malicious package release"},
		}).
		WithProvenance(report.Provenance{AnalyzerVersion: "ferralon-assay test", Timestamp: time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)}).
		Build()
}

// VEX: the one honest OSS "affected". It carries an action_statement (remediation), not a
// justification (justifications are a not_affected field).
func TestReportVEX_MaliciousPresent_MapsToAffected(t *testing.T) {
	doc, err := projection.ProjectReportVEX(maliciousReport())
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(doc.Statements))
	}
	s := doc.Statements[0]
	if s.Status != projection.VEXStatusAffected {
		t.Fatalf("status = %q, want %q", s.Status, projection.VEXStatusAffected)
	}
	if s.Justification != "" {
		t.Errorf("justification = %q, want empty (affected carries no justification)", s.Justification)
	}
	if s.ActionStatement == "" {
		t.Error("action_statement is empty; an affected statement must carry remediation")
	}
}

// SARIF: the one verdict for which "error" is honest — a decisive, determined finding.
func TestReportSARIF_MaliciousPresent_MapsToError(t *testing.T) {
	log, err := projection.ProjectReportSARIF(maliciousReport())
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	results := log.Runs[0].Results
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].Level != "error" {
		t.Fatalf("level = %q, want error", results[0].Level)
	}
	if v, _ := results[0].Properties.Tegron["verdict"].(string); v != string(report.VerdictMaliciousPresent) {
		t.Errorf("verdict property = %q, want %q", v, report.VerdictMaliciousPresent)
	}
}

// HTML: the finding renders with the decisive "affected" badge and its own label, and the page is
// self-contained (no external references introduced by the new CSS/legend).
func TestReportHTML_MaliciousPresent_RendersAffectedBadge(t *testing.T) {
	b, err := projection.ProjectReportHTML(maliciousReport())
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	html := string(b)
	if !strings.Contains(html, "Malicious package present") {
		t.Error("HTML omits the 'Malicious package present' label")
	}
	if !strings.Contains(html, `badge affected`) {
		t.Error("HTML omits the affected badge class for the malicious-present finding")
	}
	// Self-containment (no external script/style references) is asserted comprehensively by the
	// existing report_html_test.go invariants; here we only guard the new external-reference vectors
	// the added CSS/legend could plausibly introduce.
	for _, banned := range []string{`<script src=`, `<link `} {
		if strings.Contains(html, banned) {
			t.Errorf("HTML introduced an external reference %q — the page must stay self-contained", banned)
		}
	}
}
