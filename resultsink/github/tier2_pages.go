// tier2_pages.go — Tier 2 GitHub Pages ResultSink: an opt-in surface that stages
// report.html into a Pages publish directory for consumption by a workflow's
// deploy-pages step. OFF BY DEFAULT.
//
// # Sink / workflow split
//
// This sink's only job is to STAGE the artifact: it writes report.html (and an
// index.html redirect) into a local publish directory on disk. It does NOT deploy
// to GitHub Pages. The actual deployment is a separate workflow step:
//
//   - uses: actions/upload-pages-artifact@v3
//     with:
//     path: ./_site           # the staging dir this sink writes to
//   - uses: actions/deploy-pages@v4
//
// Decoupling staging from deployment keeps the sink dependency-free (stdlib only)
// and lets the workflow control when/whether to deploy (e.g. only on push to main,
// never on PRs). The sink's contract is deterministic: given the same Report, the
// same bytes are written to the same path.
//
// # Off by default
//
// Tier 2 is an opt-in surface. It is disabled unless the operator explicitly sets
// TEGRON_PAGES=true in the workflow. The capability check in detect.go:
//   - caps.CanPages = env.PagesOptIn && caps.CanWrite
//
// When CanPages is false (the default), Publish is a clean no-op: no files are
// staged, no directories created, and nil is returned. The Tier 0 summary still
// runs unaffected — Tier 2 is additive, never a dependency of Tier 0.
//
// # Invariant 5 (deterministic verdicts only)
//
// The staged HTML is the output of projection.MarshalReportHTML, which renders
// only the four deterministic verdicts (disqualified / not_exploitable /
// reachable_candidate / undetermined). No Case/Assessment/living-verdict concept can appear —
// the Report type enforces this boundary structurally.
package github

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
)

// defaultStagingDir is the publish directory staged for actions/upload-pages-artifact.
// Matches the conventional _site path expected by the Actions Pages workflow step.
const defaultStagingDir = "_site"

// Tier2Pages is a resultsink.ResultSink that stages report.html into a Pages
// publish directory when the Tier 2 opt-in is active. When disabled (the default),
// Publish is a complete no-op.
type Tier2Pages struct {
	// Enabled gates all staging. When false, Publish returns nil immediately.
	// Driven by caps.CanPages; constructor sets it from the Env.
	Enabled bool
	// StagingDir is the publish directory written for actions/upload-pages-artifact.
	// Defaults to "_site" (relative to the process working directory, which is the
	// workspace root in a GitHub Actions runner).
	StagingDir string
}

// Compile-time assurance that Tier2Pages implements the sink contract.
var _ resultsink.ResultSink = (*Tier2Pages)(nil)

// NewTier2Pages builds a Tier2Pages from a detected Env snapshot. The sink is
// enabled only when the Tier 2 opt-in flag (TEGRON_PAGES) is set and a write token
// is present — checked indirectly via Detect(env).CanPages rather than re-deriving
// the policy here.
//
// Constructor shape mirrors NewTier0Summary(env Env) so Item 5's sink selector
// can compose all tiers uniformly.
func NewTier2Pages(env Env) *Tier2Pages {
	caps := Detect(env)
	return &Tier2Pages{
		Enabled:    caps.CanPages,
		StagingDir: defaultStagingDir,
	}
}

// Publish stages report.html and index.html into StagingDir, ready for the
// workflow's upload-pages-artifact step to pick up. When Enabled is false,
// Publish returns nil immediately and writes nothing.
func (s *Tier2Pages) Publish(_ context.Context, res Result) error {
	if !s.Enabled {
		return nil
	}

	html := res.Projections.HTML
	if len(html) == 0 {
		// No rendered HTML in the projection — skip rather than write an empty file.
		// The caller should populate Projections.HTML via projection.MarshalReportHTML
		// before handing the Result to this sink. This is a defensive guard, not an
		// expected path in a correctly wired run.
		return nil
	}

	dir := s.StagingDir
	if dir == "" {
		dir = defaultStagingDir
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("resultsink/github: create pages staging dir %q: %w", dir, err)
	}

	reportPath := filepath.Join(dir, "report.html")
	if err := os.WriteFile(reportPath, html, 0o644); err != nil {
		return fmt.Errorf("resultsink/github: write report.html: %w", err)
	}

	// index.html redirects to report.html so the Pages root URL resolves correctly.
	// A meta-refresh is used rather than a JS redirect so the page works with JS
	// disabled and in environments that block scripted navigation.
	index := []byte(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0; url=report.html">
<title>%s</title>
</head>
<body>
<p><a href="report.html">View scan report</a></p>
</body>
</html>
`, brand.ReportTitle()))
	indexPath := filepath.Join(dir, "index.html")
	if err := os.WriteFile(indexPath, index, 0o644); err != nil {
		return fmt.Errorf("resultsink/github: write index.html: %w", err)
	}

	return nil
}
