// tier1_sarif.go — the Tier 1 SARIF surface: it materializes report.sarif.json into
// an output directory so a workflow step can upload it to GitHub code scanning.
//
// # R5 decision: DELEGATE the upload to github/codeql-action/upload-sarif
//
// The actual code-scanning ingestion is NOT a REST call this sink makes; it is a
// workflow step (github/codeql-action/upload-sarif) that picks up the file this sink
// writes. Rationale (R5 default, taken): codeql-action is the supported, maintained
// path for code-scanning uploads — it handles the SARIF-receipt/processing-status
// dance, ref/commit attribution, base-ref diffing for PRs, and the /code-scanning
// /sarifs polling that a hand-rolled REST upload would have to re-implement and keep
// in step with API changes. A direct REST upload would also need the `security-events:
// write` permission and gzip+base64 framing, duplicating logic the action already
// owns. So this sink's job is narrow and deterministic: write report.sarif.json where
// the workflow step expects it. The file is produced from projection.MarshalReportSARIF
// (the Report-driven projector — inv. 5: a candidate maps to "warning", never "error").
//
// # Auto-skip
//
// The sink no-ops cleanly (no error) when SARIF projection bytes are absent. It needs
// no token and makes no network call, so it is safe on forked PRs too; the selector
// (Item 5) still only composes it when caps.CanWrite, because code scanning ingestion
// on a fork is blocked upstream by the action — but the materialized file itself is
// harmless. Writing the file requires only a writable OutputDir.
package github

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
)

// SARIFFileName is the conventional file the codeql-action upload step reads.
const SARIFFileName = "report.sarif.json"

// Tier1SARIF materializes the SARIF projection into OutputDir as report.sarif.json.
// The code-scanning upload itself is a workflow step (codeql-action), not a call this
// sink makes — see the file header (R5).
type Tier1SARIF struct {
	// OutputDir is the directory the report.sarif.json is written into. Empty means no
	// output location is configured and the sink skips cleanly.
	OutputDir string
}

var _ resultsink.ResultSink = (*Tier1SARIF)(nil)

// NewTier1SARIF builds the SARIF sink writing into outputDir. outputDir is the
// workflow's shared output location (the selector, Item 5, supplies it — typically the
// same directory the Local sink writes to, which the codeql-action step references).
func NewTier1SARIF(outputDir string) *Tier1SARIF {
	return &Tier1SARIF{OutputDir: outputDir}
}

// Publish writes report.sarif.json into OutputDir. It auto-skips (returns nil) when no
// output directory is configured. The SARIF bytes are taken from the pre-rendered
// projection when present, else projected from the Report so the file is always
// materialized deterministically.
func (s *Tier1SARIF) Publish(_ context.Context, res Result) error {
	if s.OutputDir == "" {
		return nil
	}

	data := res.Projections.SARIF
	if len(data) == 0 {
		b, err := projection.MarshalReportSARIF(res.Report)
		if err != nil {
			return fmt.Errorf("resultsink/github: project SARIF: %w", err)
		}
		data = b
	}

	if err := os.MkdirAll(s.OutputDir, 0o755); err != nil {
		return fmt.Errorf("resultsink/github: create SARIF output dir: %w", err)
	}
	path := filepath.Join(s.OutputDir, SARIFFileName)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("resultsink/github: write %s: %w", SARIFFileName, err)
	}
	return nil
}
