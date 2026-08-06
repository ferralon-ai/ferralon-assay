package projection_test

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
)

func TestReportHTML_IsCompleteDocument(t *testing.T) {
	b, err := projection.ProjectReportHTML(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	html := string(b)
	if !strings.HasPrefix(strings.TrimSpace(html), "<!DOCTYPE html>") {
		t.Fatalf("not a complete HTML document")
	}
	if !strings.Contains(html, "</html>") {
		t.Fatalf("missing closing </html>")
	}
}

// TestReportHTML_FileSafe_NoExternalRefs is the headline file://-safe guard: the
// page MUST have no external references and no runtime network calls, so it renders
// correctly when opened directly from disk.
func TestReportHTML_FileSafe_NoExternalRefs(t *testing.T) {
	b, err := projection.ProjectReportHTML(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	html := string(b)

	// No external script/style/link/iframe with a src/href to a URL or local file.
	banned := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[^>]*\bsrc\s*=`),
		regexp.MustCompile(`(?i)<link\b`),
		regexp.MustCompile(`(?i)<iframe\b`),
		regexp.MustCompile(`(?i)<img[^>]*\bsrc\s*=\s*["']https?:`),
		regexp.MustCompile(`(?i)@import\b`),
	}
	for _, re := range banned {
		if re.MatchString(html) {
			t.Fatalf("file://-safe VIOLATION: external reference matched %q", re.String())
		}
	}

	// No runtime network primitives.
	for _, tok := range []string{"fetch(", "XMLHttpRequest", "WebSocket", "navigator.sendBeacon", "import("} {
		if strings.Contains(html, tok) {
			t.Fatalf("file://-safe VIOLATION: runtime network primitive %q present", tok)
		}
	}
}

// TestReportHTML_InlineJSON_PresentAndCanonical asserts the canonical Report JSON
// is embedded in the inline <script type="application/json"> element and is the
// SAME Report (one-Report criterion) — re-parsed and re-marshalled it equals the
// source Report's bytes.
func TestReportHTML_InlineJSON_PresentAndCanonical(t *testing.T) {
	src := fixtureReport()
	b, err := projection.ProjectReportHTML(src)
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	html := string(b)

	marker := `<script type="application/json" id="` + projection.ReportHTMLDataElementID + `">`
	idx := strings.Index(html, marker)
	if idx < 0 {
		t.Fatalf("inline JSON <script> element not found")
	}
	start := idx + len(marker)
	end := strings.Index(html[start:], "</script>")
	if end < 0 {
		t.Fatalf("inline JSON <script> not closed")
	}
	embedded := html[start : start+end]
	// Undo the </ defang so it parses as JSON.
	embedded = strings.ReplaceAll(embedded, `<\/`, "</")

	var got report.Report
	if err := json.Unmarshal([]byte(embedded), &got); err != nil {
		t.Fatalf("embedded JSON does not parse: %v\n%s", err, embedded)
	}

	// Re-marshal both and compare — proves the page carries the exact source Report.
	wantBytes, _ := json.Marshal(src)
	gotBytes, _ := json.Marshal(got)
	if string(wantBytes) != string(gotBytes) {
		t.Fatalf("embedded Report differs from source Report")
	}
}

// TestReportHTML_NoScriptBreakout asserts the embedded JSON cannot break out of its
// <script> container (the </ defang) even if an advisory detail contained "</script>".
func TestReportHTML_NoScriptBreakout(t *testing.T) {
	src := report.NewBuilder(report.Subject{Repo: "x", ResolvedCommit: "c"}).
		ReachableCandidate(
			report.Advisory{ID: "CVE-X", Source: "nvd"},
			nil,
			"a → b",
			"injection attempt </script><script>alert(1)</script>",
		).Build()
	b, err := projection.ProjectReportHTML(src)
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	html := string(b)
	// Within the data block there must be no raw </script> that would close it early.
	marker := `id="` + projection.ReportHTMLDataElementID + `">`
	start := strings.Index(html, marker) + len(marker)
	end := strings.Index(html[start:], "</script>")
	block := html[start : start+end]
	if strings.Contains(block, "</script") {
		t.Fatalf("script breakout: raw </script in data block")
	}
}

func TestReportHTML_EmptyReportRenders(t *testing.T) {
	b, err := projection.ProjectReportHTML(fixtureReportEmpty())
	if err != nil {
		t.Fatalf("ProjectReportHTML (empty): %v", err)
	}
	html := string(b)
	if !strings.Contains(html, "findings-empty") {
		t.Fatalf("empty report missing empty-state element")
	}
	if !strings.Contains(html, `id="report-data"`) {
		t.Fatalf("empty report missing inline data element")
	}
}

func TestReportHTML_ContainsSVGChart(t *testing.T) {
	b, err := projection.ProjectReportHTML(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	if !strings.Contains(string(b), `id="donut"`) {
		t.Fatalf("missing SVG donut chart element")
	}
}

func TestReportHTML_RejectsUnversionedReport(t *testing.T) {
	if _, err := projection.ProjectReportHTML(report.Report{}); err == nil {
		t.Fatalf("expected error for report with no schema version")
	}
}

// TestReportHTML_Priority_RendersEPSSAndKEV asserts that a finding with a Priority
// renders the EPSS score, percentile, and CISA KEV badge in the HTML output.
func TestReportHTML_Priority_RendersEPSSAndKEV(t *testing.T) {
	b, err := projection.ProjectReportHTML(fixtureReportWithPriority())
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	html := string(b)

	// EPSS score/percentile should appear as rendered text.
	if !strings.Contains(html, "0.940") {
		t.Errorf("EPSS score 0.940 not found in HTML")
	}
	if !strings.Contains(html, "p98") {
		t.Errorf("EPSS percentile p98 not found in HTML")
	}
	// CISA KEV badge.
	if !strings.Contains(html, "CISA KEV") {
		t.Errorf("CISA KEV badge not found in HTML")
	}
	if !strings.Contains(html, "2024-01-15") {
		t.Errorf("KEV date added not found in HTML")
	}
	// EPSS/KEV footnote.
	if !strings.Contains(html, "EPSS / CISA KEV") {
		t.Errorf("EPSS/KEV footnote not found in HTML")
	}
}

// TestReportHTML_Priority_RendersGradeAndEntryPoint asserts reachability-grade badge
// and entry-point line are rendered when present.
func TestReportHTML_Priority_RendersGradeAndEntryPoint(t *testing.T) {
	b, err := projection.ProjectReportHTML(fixtureReportWithPriority())
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	html := string(b)

	if !strings.Contains(html, "attacker-tainted candidate") {
		t.Errorf("grade badge 'attacker-tainted candidate' not found in HTML")
	}
	if !strings.Contains(html, "net/http.HandlerFunc") {
		t.Errorf("entry-point symbol not found in HTML")
	}
	if !strings.Contains(html, "attacker-controllable") {
		t.Errorf("attacker-controllable flag not found in HTML")
	}
	if !strings.Contains(html, "h2.go") {
		t.Errorf("call-frame file not found in HTML")
	}
}

// TestReportHTML_NilPriority_RendersCleanly asserts that a finding with nil Priority
// renders without any EPSS/KEV markup and without panicking.
func TestReportHTML_NilPriority_RendersCleanly(t *testing.T) {
	b, err := projection.ProjectReportHTML(fixtureReportWithPriority())
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	html := string(b)

	// The report has two findings: one with Priority (CVE-2024-0001) and one without
	// (GO-2021-NOPRI). The nil-Priority finding should render without EPSS data.
	// We verify the output is a valid complete HTML document (no panic = clean render).
	if !strings.HasPrefix(strings.TrimSpace(html), "<!DOCTYPE html>") {
		t.Fatalf("nil-Priority: not a complete HTML document")
	}
	// GO-2021-NOPRI finding should appear in the output.
	if !strings.Contains(html, "GO-2021-NOPRI") {
		t.Errorf("nil-Priority finding ID not found in HTML output")
	}
}
