package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// TestDisqualDetailReadsBackToItsBasis holds report's copy of the disqualification detail lines in
// step with disqualDetail: report.Upgrade backfills a stored empty-basis intake disqualification from
// its detail, so every intake line this package writes must read back as the basis disqualBasis
// records for the same reason, and no version or symbol line may read back as any basis, with or without the source attribution appended to it.
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
			want := disqualBasis(reason)
			if reason == pipeline.ReasonVersionNotInRange || reason == pipeline.ReasonSymbolAbsent {
				// These always carried their basis; a stored one without it is refused, not backfilled.
				want = verdict.BasisNone
			}
			if got := report.DisqualBasisFromDetail(detail); got != want {
				t.Errorf("reason %q: detail %q reads back as basis %q, want %q", reason, detail, got, want)
			}
		}
	}
}
