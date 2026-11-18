package projection

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestReportHTMLLimitLabel_RangeAbsent: the range-absent limit renders a sentence, not the raw code.
func TestReportHTMLLimitLabel_RangeAbsent(t *testing.T) {
	got := reportHTMLLimitLabel(report.ReasonAdvisoryRangeAbsent)
	if got == report.ReasonAdvisoryRangeAbsent || !strings.Contains(got, "version range") {
		t.Errorf("reportHTMLLimitLabel(%q) = %q, want the range-absent sentence", report.ReasonAdvisoryRangeAbsent, got)
	}
}

// TestReportHTMLLimitLabel_DependencyNotFetched: the dependency_not_fetched limit renders a
// sentence, not the raw code.
func TestReportHTMLLimitLabel_DependencyNotFetched(t *testing.T) {
	got := reportHTMLLimitLabel(report.ReasonDependencyNotFetched)
	if got == report.ReasonDependencyNotFetched || !strings.Contains(got, "withheld") {
		t.Errorf("reportHTMLLimitLabel(%q) = %q, want the dependency-not-fetched sentence", report.ReasonDependencyNotFetched, got)
	}
}

// TestReportHTMLLimitLabel_PartialRunUnversioned: the limit a partial run declares for the scanned
// module's own advisories renders a sentence, not the raw code.
func TestReportHTMLLimitLabel_PartialRunUnversioned(t *testing.T) {
	const want = "The scanned module's own version could not be established and the analysis searched only " +
		"part of the build, so no verdict is reported for advisories on the module itself."
	if got := reportHTMLLimitLabel(plugin.PartialReasonPartialRunUnversioned); got != want {
		t.Errorf("reportHTMLLimitLabel(%q) = %q, want %q", plugin.PartialReasonPartialRunUnversioned, got, want)
	}
}
