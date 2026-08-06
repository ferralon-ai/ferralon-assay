package github_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
)

// TestTier1Body_DefaultBuild_Unchanged locks the shared Tier-1 render: the heading is
// brand.Tier1SummaryHeading and the analyzer provenance line is still shown verbatim
// (brand.Tier1RenderAnalyzer is unconditionally true) — parallel to
// tier0_summary_default_test.go.
func TestTier1Body_DefaultBuild_Unchanged(t *testing.T) {
	body := renderedTier1Body(t, newResult())

	wantHeading := "## " + brand.Tier1SummaryHeading
	if !strings.Contains(body, wantHeading) {
		t.Errorf("default heading missing %q\n---\n%s", wantHeading, body)
	}
	// fixtureReport stamps provenance.AnalyzerVersion = "v0.2.0"; the default build
	// renders it verbatim.
	if !strings.Contains(body, "**Analyzer:** `v0.2.0`") {
		t.Errorf("default build must render the analyzer line\n---\n%s", body)
	}

	wantTitle := brand.Tier1IssueTitle
	if ghsink.IssueTitle != wantTitle {
		t.Errorf("default IssueTitle = %q, want %q", ghsink.IssueTitle, wantTitle)
	}
}
