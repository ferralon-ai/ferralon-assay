package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestDisqualDetailReadsBackToItsBasis holds report's copy of the disqualification detail lines in
// step with disqualDetail: report.Upgrade backfills a stored empty-basis disqualification from its
// detail, so every line this package writes must read back as the basis disqualBasis records for
// the same reason, with or without the source attribution appended to it.
func TestDisqualDetailReadsBackToItsBasis(t *testing.T) {
	src := &pipeline.RefuteSource{Advisory: "GO-2021-0001", Record: "sha256:0123456789abcdef", Feed: "osv", BuiltIn: true}
	for _, reason := range []string{
		pipeline.ReasonVersionNotInRange,
		pipeline.ReasonSymbolAbsent,
		pipeline.ReasonAdvisoryEcosystemMismatch,
		pipeline.ReasonNoManifestEntry,
		"an_axis_nobody_named",
	} {
		for _, detail := range []string{disqualDetail(reason), disqualDetail(reason) + refuteAttribution(src)} {
			if got, want := report.DisqualBasisFromDetail(detail), disqualBasis(reason); got != want {
				t.Errorf("reason %q: detail %q reads back as basis %q, want %q", reason, detail, got, want)
			}
		}
	}
}
