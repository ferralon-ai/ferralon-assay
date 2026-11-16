package github_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// everyVerdictReport holds one finding per verdict and undetermined rows from every cause group.
func everyVerdictReport() report.Report {
	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.6"}
	b := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		ReachableCandidate(report.Advisory{ID: "CVE-2023-0001", Source: "nvd"}, &pkg, "net/http.Handler → text.Vuln", "").
		NotExploitable(report.Advisory{ID: "CVE-2023-0002", Source: "nvd"}, &pkg, verdict.BasisSymbolAbsent, "vulnerable symbol absent").
		Disqualified(report.Advisory{ID: "CVE-2023-0003", Source: "nvd"}, &pkg, verdict.BasisVersionNotAffected, "version below first affected")
	for i, reason := range []string{
		report.ReasonScanCutShort, report.ReasonScanCutShort, report.ReasonPackageVersionUnresolved,
		report.ReasonRefutationWithheld, report.ReasonGoToolchainNotScanned, "some_new_reason",
	} {
		b.Undetermined(report.Advisory{ID: "CVE-2023-010" + string(rune('0'+i)), Source: "nvd"}, nil, reason)
	}
	return b.WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).Build()
}

// TestVerdictWording_Golden pins the technician-facing wording of the job summary and annotations for
// a report with every verdict and several undetermined causes, and for a partial (cut short) scan.
// Regenerate with UPDATE_GOLDEN=1.
func TestVerdictWording_Golden(t *testing.T) {
	for name, r := range map[string]report.Report{"every_verdict": everyVerdictReport(), "partial_scan": cutShortReport()} {
		dir := t.TempDir()
		var ann bytes.Buffer
		sink := &ghsink.Tier0Summary{SummaryPath: filepath.Join(dir, "s.md"), Annotations: &ann}
		if err := sink.Publish(context.Background(), resultsink.Result{Report: r}); err != nil {
			t.Fatal(err)
		}
		sum, err := os.ReadFile(filepath.Join(dir, "s.md"))
		if err != nil {
			t.Fatal(err)
		}
		got := string(sum) + "\n--- annotations ---\n" + ann.String()
		golden := filepath.Join("testdata", name+".golden.md")
		if os.Getenv("UPDATE_GOLDEN") != "" {
			if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Errorf("%s differs from %s:\n%s", name, golden, got)
		}
	}
}
