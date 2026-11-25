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
// records for the same reason, and no version or symbol line may read back as any basis, with or without the source attribution or cross-check note appended to it.
func TestDisqualDetailReadsBackToItsBasis(t *testing.T) {
	src := &pipeline.RefuteSource{Advisory: "GO-2021-0001", Record: "sha256:0123456789abcdef", Feed: "osv", BuiltIn: true}
	for _, reason := range []string{
		pipeline.ReasonVersionNotInRange,
		pipeline.ReasonFixCommitInHistory,
		pipeline.ReasonSymbolAbsent,
		pipeline.ReasonAdvisoryEcosystemMismatch,
		pipeline.ReasonNoManifestEntry,
		"an_axis_nobody_named",
	} {
		for _, detail := range []string{disqualDetail(reason), disqualDetail(reason) + refuteAttribution(src), disqualDetail(reason) + refuteAttribution(src) + crossCheckNote("govulncheck's database could not be consulted: build failed")} {
			want := disqualBasis(reason)
			if reason == pipeline.ReasonVersionNotInRange || reason == pipeline.ReasonFixCommitInHistory || reason == pipeline.ReasonSymbolAbsent {
				// These always carried their basis; a stored one without it is refused, not backfilled.
				want = verdict.BasisNone
			}
			if got := report.DisqualBasisFromDetail(detail); got != want {
				t.Errorf("reason %q: detail %q reads back as basis %q, want %q", reason, detail, got, want)
			}
		}
	}
}

// TestDisqualFixCommitInHistory pins what a row cleared by its fix commit says: it is a version
// ground, and the detail names the commit's place in history rather than a compared version.
func TestDisqualFixCommitInHistory(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		basis        verdict.NonExploitableBasis
		detail       string
	}{
		{
			name:   "fix commit in history",
			reason: pipeline.ReasonFixCommitInHistory,
			basis:  verdict.BasisVersionNotAffected,
			detail: "the commit the advisory names as its fix is in the scanned commit's history, and every range the advisory affects the project's own package by ends at a fixed version",
		},
		{
			name:   "version outside the range keeps its own line",
			reason: pipeline.ReasonVersionNotInRange,
			basis:  verdict.BasisVersionNotAffected,
			detail: "resolved dependency version is outside the advisory's affected range",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := disqualBasis(tc.reason); got != tc.basis {
				t.Errorf("basis = %q, want %q", got, tc.basis)
			}
			if got := disqualDetail(tc.reason); got != tc.detail {
				t.Errorf("detail = %q, want %q", got, tc.detail)
			}
		})
	}
}

// TestCrossCheckNote: a version clear the analyzer's database could not cross-check says so after its
// attribution; a cross-checked clear adds nothing.
func TestCrossCheckNote(t *testing.T) {
	if got := crossCheckNote(""); got != "" {
		t.Errorf("crossCheckNote(\"\") = %q, want empty", got)
	}
	const note = "govulncheck's database could not be consulted over the whole build: tool_failure:govulncheck_partial_run"
	if got, want := crossCheckNote(note), "; not cross-checked: "+note; got != want {
		t.Errorf("crossCheckNote = %q, want %q", got, want)
	}
}
