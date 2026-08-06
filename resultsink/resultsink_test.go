package resultsink_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
)

func fixtureResult(t *testing.T) resultsink.Result {
	t.Helper()
	r := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		ReachableCandidate(report.Advisory{ID: "CVE-2023-39325", Source: "nvd"}, nil, "a → b", "candidate").
		WithProvenance(report.Provenance{AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()

	vex, err := projection.MarshalReportVEX(r)
	if err != nil {
		t.Fatalf("MarshalReportVEX: %v", err)
	}
	sarif, err := projection.MarshalReportSARIF(r)
	if err != nil {
		t.Fatalf("MarshalReportSARIF: %v", err)
	}
	html, err := projection.MarshalReportHTML(r)
	if err != nil {
		t.Fatalf("MarshalReportHTML: %v", err)
	}
	return resultsink.Result{
		Report:      r,
		Projections: resultsink.Projections{OpenVEX: vex, SARIF: sarif, HTML: html},
	}
}

// TestNoop_Discards asserts the no-op sink is a safe default: it accepts a Result
// and returns nil without writing anything.
func TestNoop_Discards(t *testing.T) {
	var sink resultsink.ResultSink = resultsink.NewNoop()
	if err := sink.Publish(context.Background(), fixtureResult(t)); err != nil {
		t.Fatalf("Noop.Publish: %v", err)
	}
}

// TestLocal_WritesAllArtifacts asserts the local sink writes report.json plus every
// projection (driven from one Report) into its directory.
func TestLocal_WritesAllArtifacts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out") // non-existent subdir → MkdirAll path
	var sink resultsink.ResultSink = resultsink.NewLocal(dir)
	res := fixtureResult(t)
	if err := sink.Publish(context.Background(), res); err != nil {
		t.Fatalf("Local.Publish: %v", err)
	}

	for _, name := range []string{
		resultsink.FileReportJSON,
		resultsink.FileOpenVEX,
		resultsink.FileSARIF,
		resultsink.FileReportHTML,
	} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("expected artifact %s: %v", name, err)
		}
		if info.Size() == 0 {
			t.Fatalf("artifact %s is empty", name)
		}
	}

	// report.json on disk must be the canonical Report.
	b, err := os.ReadFile(filepath.Join(dir, resultsink.FileReportJSON))
	if err != nil {
		t.Fatalf("read report.json: %v", err)
	}
	var got report.Report
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("report.json does not parse: %v", err)
	}
	if got.SchemaVersion != report.SchemaVersion {
		t.Fatalf("report.json schema: got %q, want %q", got.SchemaVersion, report.SchemaVersion)
	}
}

// TestLocal_SkipsEmptyProjections asserts a nil projection is not written as an
// empty file (only report.json + present projections appear).
func TestLocal_SkipsEmptyProjections(t *testing.T) {
	dir := t.TempDir()
	res := fixtureResult(t)
	res.Projections.SARIF = nil
	res.Projections.HTML = nil
	if err := resultsink.NewLocal(dir).Publish(context.Background(), res); err != nil {
		t.Fatalf("Local.Publish: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, resultsink.FileSARIF)); !os.IsNotExist(err) {
		t.Fatalf("SARIF should not have been written when empty")
	}
	if _, err := os.Stat(filepath.Join(dir, resultsink.FileOpenVEX)); err != nil {
		t.Fatalf("OpenVEX should have been written: %v", err)
	}
}

func TestLocal_EmptyDirErrors(t *testing.T) {
	if err := (&resultsink.Local{}).Publish(context.Background(), fixtureResult(t)); err == nil {
		t.Fatalf("expected error for empty Dir")
	}
}
