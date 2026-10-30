package github_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

const (
	noAnalyzerDetail   = "no analyzer for the detected C/C++ (cfamily) source is installed: assay-plugin-cfamily is not on PATH, so nothing was assessed"
	noAnalyzerHeadline = "**Not analyzed — no analyzer ran for this codebase's language, so nothing was assessed.**"
	noAnalyzerLead     = "**Not analyzed.** No analyzer ran for this codebase:"
)

// noAnalyzerReport is the Report a scan publishes when the detected language's analyzer is not
// installed: no packages, no advisories, and one no_language_plugin note carrying detail.
func noAnalyzerReport(detail string) report.Report {
	return report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		AddPartiality(report.PartialityNote{Reason: plugin.PartialReasonNoPlugin, Detail: detail}).
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()
}

// TestBothSurfaces_NoAnalyzer_HeadlineSaysNotAnalyzed: when no analyzer ran, both surfaces say the
// codebase was not analyzed and print the note's detail, which names the language; a scan that
// assessed something keeps the partial-coverage framing.
func TestBothSurfaces_NoAnalyzer_HeadlineSaysNotAnalyzed(t *testing.T) {
	cases := []struct {
		name     string
		r        report.Report
		want     []string
		dontWant []string
	}{
		{
			name:     "nothing assessed, detail set",
			r:        noAnalyzerReport(noAnalyzerDetail),
			want:     []string{noAnalyzerHeadline, noAnalyzerLead, "(`" + noAnalyzerDetail + "`)", "C/C++"},
			dontWant: []string{"Partial coverage", "in what was assessed", "The advisories below"},
		},
		{
			name:     "nothing assessed, no detail",
			r:        noAnalyzerReport(""),
			want:     []string{noAnalyzerHeadline, noAnalyzerLead},
			dontWant: []string{"Partial coverage"},
		},
		{
			name:     "something assessed keeps partial coverage",
			r:        goScanReport(report.PartialityNote{Reason: plugin.PartialReasonNoPlugin, Ecosystem: "Go", Detail: noAnalyzerDetail}),
			want:     []string{"**Partial coverage — no reachable candidates in what was assessed.**", disclosureHeading, "(`" + noAnalyzerDetail + "`)"},
			dontWant: []string{noAnalyzerHeadline, noAnalyzerLead},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for surface, s := range bothSurfaces(t, tc.r) {
				for _, w := range tc.want {
					if !strings.Contains(s, w) {
						t.Errorf("%s: missing %q\n---\n%s", surface, w, s)
					}
				}
				for _, w := range tc.dontWant {
					if strings.Contains(s, w) {
						t.Errorf("%s: carries %q\n---\n%s", surface, w, s)
					}
				}
			}
		})
	}
}
