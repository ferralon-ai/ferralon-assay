package report

import (
	"strings"
	"testing"
)

// TestUndeterminedDetail_RangeAbsent: the range-absent row explains itself in words, not through
// the raw-code fallback.
func TestUndeterminedDetail_RangeAbsent(t *testing.T) {
	got := UndeterminedDetail(ReasonAdvisoryRangeAbsent)
	if strings.Contains(got, ReasonAdvisoryRangeAbsent) || !strings.Contains(got, "version range") {
		t.Errorf("UndeterminedDetail(%q) = %q, want the range-absent explanation", ReasonAdvisoryRangeAbsent, got)
	}
}
