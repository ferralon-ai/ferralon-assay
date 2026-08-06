package github_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
)

// TestTier0_DefaultBuild_HeadingAndAnalyzer locks the Tier-0 render (AC4): the heading
// is brand.Tier0SummaryHeading and the analyzer provenance line is shown verbatim
// (brand.Tier0RenderAnalyzer is unconditionally true).
func TestTier0_DefaultBuild_HeadingAndAnalyzer(t *testing.T) {
	summaryPath := filepath.Join(t.TempDir(), "summary.md")
	sink := &ghsink.Tier0Summary{SummaryPath: summaryPath, Annotations: io.Discard}
	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	b, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	s := string(b)
	wantHeading := "## " + brand.Tier0SummaryHeading
	if !strings.Contains(s, wantHeading) {
		t.Errorf("default heading missing %q\n---\n%s", wantHeading, s)
	}
	// fixtureReport stamps provenance.AnalyzerVersion = "v0.2.0"; the default build
	// renders it verbatim.
	if !strings.Contains(s, "**Analyzer:** `v0.2.0`") {
		t.Errorf("default build must render the analyzer line\n---\n%s", s)
	}
}
