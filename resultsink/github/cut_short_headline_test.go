package github_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

const cutShortTail = "The scan was cut short by its time limit before every advisory was assessed; see below for how to give it more time."

// cutShortReport is a scan the time limit stopped after one advisory: one verdict, two rows the
// scan did not reach, and the scan-level note.
func cutShortReport() report.Report {
	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.6"}
	b := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		NotExploitable(report.Advisory{ID: "GO-2021-0113", Source: "corpus"}, &pkg, verdict.BasisSymbolAbsent, "vulnerable symbol absent")
	for _, id := range []string{"GO-2022-0322", "GO-2023-1571"} {
		b.Undetermined(report.Advisory{ID: id, Source: "corpus"}, nil, report.ReasonScanCutShort)
	}
	return b.AddPartiality(report.PartialityNote{
		Reason: report.ReasonScanCutShort,
		Detail: "2 of 3 advisories were not assessed: the scan reached its 30m time limit",
	}).
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()
}

// TestBothSurfaces_CutShort_HeadlineNamesTheStop: a cut-short scan's headline says the scan was cut
// short in place of the generic qualifier, and the disclosure below it carries the note's detail.
func TestBothSurfaces_CutShort_HeadlineNamesTheStop(t *testing.T) {
	cases := []struct {
		name         string
		r            report.Report
		wantHeadline string
		wantLine     string
	}{
		{
			name:         "cut short",
			r:            cutShortReport(),
			wantHeadline: "**Partial coverage — no reachable candidates in what was assessed.** 1 advisory finding(s) are grounded-safe (1 not exploitable, 0 disqualified, 2 not assessed). " + cutShortTail,
			wantLine:     "The scan was cut short before it finished (`2 of 3 advisories were not assessed: the scan reached its 30m time limit`).",
		},
		{
			name:         "another limit keeps the generic qualifier",
			r:            noManifestReport(),
			wantHeadline: wantHeadlineTail,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for surface, s := range bothSurfaces(t, tc.r) {
				if !strings.Contains(s, tc.wantHeadline) {
					t.Errorf("%s: headline missing %q\n---\n%s", surface, tc.wantHeadline, s)
				}
				if tc.wantLine != "" && !strings.Contains(s, tc.wantLine) {
					t.Errorf("%s: disclosure missing %q\n---\n%s", surface, tc.wantLine, s)
				}
				if tc.r.Partiality[0].Reason != report.ReasonScanCutShort && strings.Contains(s, cutShortTail) {
					t.Errorf("%s: a scan that was not cut short carries the cut-short tail\n---\n%s", surface, s)
				}
			}
		})
	}
}
