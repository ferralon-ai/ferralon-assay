package github_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
)

// maliciousResult builds a Result whose Report carries one decisive malicious-present finding
// alongside a candidate, so the summary's leading-arm ordering and the ::error:: annotation are
// both exercised.
func maliciousResult() resultsink.Result {
	npmPkg := report.Package{Ecosystem: "npm", Name: "evil-pkg", Version: "1.0.1"}
	goPkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"}
	r := report.NewBuilder(report.Subject{Repo: "github.com/example/app", ResolvedCommit: "abc123"}).
		AddFinding(report.AdvisoryFinding{
			Advisory: report.Advisory{ID: "MAL-2024-1", Source: "osv"},
			Package:  &npmPkg,
			Verdict:  report.VerdictMaliciousPresent,
			Evidence: report.EvidenceSummary{Detail: "resolved version 1.0.1 is listed as a known-malicious release"},
		}).
		ReachableCandidate(report.Advisory{ID: "CVE-2023-39325", Source: "nvd"}, &goPkg, "net/http.Handler → x/text.Vuln", "candidate").
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()
	return resultsink.Result{Report: r}
}

// The decisive malicious-present verdict leads the Tier-0 headline, appears as its own counts-table
// row, and emits an ::error:: annotation (not the candidate's ::warning::).
func TestTier0_MaliciousPresent_LeadsHeadlineAndErrorsAnnotation(t *testing.T) {
	summaryPath := filepath.Join(t.TempDir(), "summary.md")
	var annotations bytes.Buffer

	sink := &ghsink.Tier0Summary{SummaryPath: summaryPath, Annotations: &annotations, Workspace: "/work"}
	if err := sink.Publish(context.Background(), maliciousResult()); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	summary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	s := string(summary)
	for _, want := range []string{
		"known-malicious package(s) present", // headline leads with the decisive verdict
		"| Malicious package present | 1 |",  // counts-table row
	} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q\n---\n%s", want, s)
		}
	}

	ann := annotations.String()
	if !strings.Contains(ann, "::error") {
		t.Errorf("annotations missing an ::error line for the malicious-present finding\n---\n%s", ann)
	}
	if !strings.Contains(ann, "MAL-2024-1") {
		t.Errorf("error annotation does not name the advisory\n---\n%s", ann)
	}
	// The npm package anchors to package.json (manifest inference), and the message is clinical.
	if !strings.Contains(ann, "Remove or replace") {
		t.Errorf("error annotation is not clinical/remediation-framed\n---\n%s", ann)
	}
}
