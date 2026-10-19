package projection

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestReportHTMLLimitLabel_RangeAbsent: the range-absent limit renders a sentence, not the raw code.
func TestReportHTMLLimitLabel_RangeAbsent(t *testing.T) {
	got := reportHTMLLimitLabel(report.ReasonAdvisoryRangeAbsent)
	if got == report.ReasonAdvisoryRangeAbsent || !strings.Contains(got, "version range") {
		t.Errorf("reportHTMLLimitLabel(%q) = %q, want the range-absent sentence", report.ReasonAdvisoryRangeAbsent, got)
	}
}
