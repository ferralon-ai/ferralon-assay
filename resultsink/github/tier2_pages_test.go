package github_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
)

// newHTMLResult returns a Result with Projections.HTML populated from fixtureReport()
// via projection.MarshalReportHTML, matching the caller contract the sink expects.
func newHTMLResult(t *testing.T) resultsink.Result {
	t.Helper()
	r := fixtureReport()
	html, err := projection.MarshalReportHTML(r)
	if err != nil {
		t.Fatalf("MarshalReportHTML: %v", err)
	}
	return resultsink.Result{
		Report:      r,
		Projections: resultsink.Projections{HTML: html},
	}
}

// TestTier2Pages_DisabledByDefault asserts that when the opt-in env is unset,
// Publish is a clean no-op: no files staged, nil returned.
func TestTier2Pages_DisabledByDefault(t *testing.T) {
	// Ensure opt-in is not set.
	t.Setenv(ghsink.EnvPagesOptIn, "")
	// Token set to confirm CanWrite alone is not enough.
	t.Setenv(ghsink.EnvToken, "ghp_fake")
	t.Setenv(ghsink.EnvActions, "true")

	env := ghsink.DetectEnv()
	sink := ghsink.NewTier2Pages(env)

	// Verify the sink reports itself disabled.
	if sink.Enabled {
		t.Fatal("NewTier2Pages: Enabled should be false when TEGRON_PAGES is unset")
	}

	// Point StagingDir at a temp dir so we can assert nothing is written.
	dir := t.TempDir()
	sink.StagingDir = dir

	res := newHTMLResult(t)
	if err := sink.Publish(context.Background(), res); err != nil {
		t.Fatalf("Publish (disabled): %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("Publish (disabled): expected no files written, got: %v", names)
	}
}

// TestTier2Pages_OptInWithToken asserts that when TEGRON_PAGES=true and a token is
// present, Publish stages report.html and index.html into StagingDir.
func TestTier2Pages_OptInWithToken(t *testing.T) {
	t.Setenv(ghsink.EnvPagesOptIn, "true")
	t.Setenv(ghsink.EnvToken, "ghp_fake")
	t.Setenv(ghsink.EnvActions, "true")

	env := ghsink.DetectEnv()
	sink := ghsink.NewTier2Pages(env)

	if !sink.Enabled {
		t.Fatal("NewTier2Pages: Enabled should be true when TEGRON_PAGES=true and token present")
	}

	dir := t.TempDir()
	sink.StagingDir = dir

	res := newHTMLResult(t)
	if err := sink.Publish(context.Background(), res); err != nil {
		t.Fatalf("Publish (enabled): %v", err)
	}

	// report.html must exist and contain valid HTML with the scan data.
	reportPath := filepath.Join(dir, "report.html")
	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("report.html not written: %v", err)
	}
	reportHTML := string(reportBytes)
	for _, want := range []string{
		"<!DOCTYPE html>",
		brand.Name,
		"report-data", // the embedded JSON script element ID
	} {
		if !strings.Contains(reportHTML, want) {
			t.Errorf("report.html missing %q", want)
		}
	}

	// index.html must exist and redirect to report.html.
	indexPath := filepath.Join(dir, "index.html")
	indexBytes, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("index.html not written: %v", err)
	}
	if !strings.Contains(string(indexBytes), "report.html") {
		t.Errorf("index.html does not reference report.html:\n%s", indexBytes)
	}
}

// TestTier2Pages_OptInWithoutToken asserts that opt-in env alone is not enough —
// without a write token, the sink stays disabled (CanPages requires both).
func TestTier2Pages_OptInWithoutToken(t *testing.T) {
	t.Setenv(ghsink.EnvPagesOptIn, "true")
	t.Setenv(ghsink.EnvToken, "") // no token
	t.Setenv(ghsink.EnvActions, "true")

	env := ghsink.DetectEnv()
	sink := ghsink.NewTier2Pages(env)

	if sink.Enabled {
		t.Fatal("NewTier2Pages: Enabled should be false when token is absent, even with TEGRON_PAGES=true")
	}
}

// TestTier2Pages_Inv5_NoPayService asserts that the staged HTML contains only
// deterministic verdict framing (inv. 5): no "affected", no "Case", no "Assessment",
// no "living-verdict".
func TestTier2Pages_Inv5_NoPayService(t *testing.T) {
	t.Setenv(ghsink.EnvPagesOptIn, "true")
	t.Setenv(ghsink.EnvToken, "ghp_fake")
	t.Setenv(ghsink.EnvActions, "true")

	env := ghsink.DetectEnv()
	sink := ghsink.NewTier2Pages(env)
	dir := t.TempDir()
	sink.StagingDir = dir

	res := newHTMLResult(t)
	if err := sink.Publish(context.Background(), res); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	html, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatalf("report.html not written: %v", err)
	}
	content := string(html)
	// inv. 5: paid-service concepts must not appear in the OSS output.
	for _, forbidden := range []string{"Case", "Assessment", "living-verdict", `"affected"`} {
		if strings.Contains(content, forbidden) {
			t.Errorf("inv.5 violation: report.html contains %q", forbidden)
		}
	}
}

// TestTier2Pages_EmptyHTML_NoOp asserts that when Projections.HTML is nil/empty,
// Publish (even when enabled) writes nothing and returns nil. This is the defensive
// guard for a caller that didn't populate the projection.
func TestTier2Pages_EmptyHTML_NoOp(t *testing.T) {
	sink := &ghsink.Tier2Pages{
		Enabled:    true,
		StagingDir: t.TempDir(),
	}
	res := resultsink.Result{Report: fixtureReport()} // no HTML projection
	if err := sink.Publish(context.Background(), res); err != nil {
		t.Fatalf("Publish with empty HTML: %v", err)
	}
	entries, _ := os.ReadDir(sink.StagingDir)
	if len(entries) != 0 {
		t.Errorf("expected no files written for empty HTML, got: %v", entries)
	}
}
