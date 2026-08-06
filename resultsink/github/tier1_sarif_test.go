package github_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
)

// TestTier1SARIF_MaterializesFile asserts the sink writes report.sarif.json into the
// output dir, projected from the Report, and that the SARIF carries only deterministic
// severities (inv. 5: candidate → warning, never error).
func TestTier1SARIF_MaterializesFile(t *testing.T) {
	dir := t.TempDir()
	sink := ghsink.NewTier1SARIF(dir)
	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	path := filepath.Join(dir, ghsink.SARIFFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", ghsink.SARIFFileName, err)
	}

	// Must be valid JSON (a SARIF log).
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	s := string(data)
	// inv. 5: a candidate maps to "warning"; no result may be level "error".
	if strings.Contains(s, `"level":"error"`) || strings.Contains(s, `"level": "error"`) {
		t.Errorf("inv.5 violation: SARIF contains an error-level result\n%s", s)
	}
}

// TestTier1SARIF_NoOutputDir_Skips asserts the sink no-ops cleanly when no output dir
// is configured (nothing to write to).
func TestTier1SARIF_NoOutputDir_Skips(t *testing.T) {
	sink := ghsink.NewTier1SARIF("")
	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("Publish with empty OutputDir should be a clean no-op, got: %v", err)
	}
}

// TestTier1SARIF_UsesPreRenderedProjection asserts the sink prefers the pre-rendered
// SARIF bytes on the Result when present rather than re-projecting.
func TestTier1SARIF_UsesPreRenderedProjection(t *testing.T) {
	dir := t.TempDir()
	res := newResult()
	res.Projections.SARIF = []byte(`{"sentinel":true}`)
	sink := ghsink.NewTier1SARIF(dir)
	if err := sink.Publish(context.Background(), res); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ghsink.SARIFFileName))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "sentinel") {
		t.Errorf("expected pre-rendered SARIF bytes to be written, got:\n%s", data)
	}
}
