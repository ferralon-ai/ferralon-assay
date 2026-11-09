package github_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
)

const nothingMatchedLine = "None of the advisories this run was given applies to this repository's dependencies."

// A run whose work-set input chose no advisory for the repository publishes a findings-free Report
// that says so on both surfaces; a Report with no recorded work set keeps its plain headline.
func TestBothSurfaces_NothingMatched_SaysSo(t *testing.T) {
	matchedNothing := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		WithProvenance(report.Provenance{
			CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC(),
			Intel: &report.IntelProvenance{WorkSetSource: report.WorkSetPolicy, WorkSetSize: 0},
		}).
		Build()
	for name, s := range bothSurfaces(t, matchedNothing) {
		if !strings.Contains(s, "**No advisory findings.** "+nothingMatchedLine) {
			t.Errorf("%s: headline does not say nothing matched\n---\n%s", name, s)
		}
	}
	degraded := map[string]report.Report{
		"no recorded work set":  emptyReport(),
		"selection did not run": withIntel(emptyReport(), report.WorkSetNone),
		"partial selection":     withIntel(emptyReport(report.PartialityNote{Reason: "advisory_facts_unavailable", Ecosystem: "Maven"}), report.WorkSetOSVQuery),
	}
	for label, r := range degraded {
		for name, s := range bothSurfaces(t, r) {
			if strings.Contains(s, nothingMatchedLine) {
				t.Errorf("%s, %s: claims nothing matched\n---\n%s", label, name, s)
			}
		}
	}
}

func withIntel(r report.Report, source string) report.Report {
	r.Provenance.Intel = &report.IntelProvenance{WorkSetSource: source}
	return r
}
