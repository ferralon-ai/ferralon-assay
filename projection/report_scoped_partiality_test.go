package projection_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// A limit bounded to one package names that package and the location inside it on every surface, so
// two such limits never render as one limit stated twice.
func TestReportProjections_ScopedLimitNamesPackageAndPath(t *testing.T) {
	r := partialSARIFReport(
		report.PartialityNote{Reason: "cgo", Ecosystem: "Go", Package: "pkg:golang/example.com/a", Path: "example.com/a/native"},
		report.PartialityNote{Reason: "cgo", Ecosystem: "Go", Package: "pkg:golang/example.com/b", Path: "example.com/b/native"},
	)

	log, err := projection.ProjectReportSARIF(r)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	seen := map[string]string{}
	for _, res := range log.Runs[0].Results {
		if res.RuleID != projection.PartialCoverageRuleID || res.Properties == nil {
			continue
		}
		pkg, _ := res.Properties.Scanner["package"].(string)
		path, _ := res.Properties.Scanner["path"].(string)
		seen[pkg] = path
	}
	for pkg, path := range map[string]string{"pkg:golang/example.com/a": "example.com/a/native", "pkg:golang/example.com/b": "example.com/b/native"} {
		if seen[pkg] != path {
			t.Errorf("SARIF: limit on %s has path %q, want %q; seen %v", pkg, seen[pkg], path, seen)
		}
	}

	out, err := projection.ProjectReportHTML(r)
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	html := string(out)
	if i := strings.Index(html, `id="report-data"`); i >= 0 {
		html = html[:i]
	}
	for _, want := range []string{"pkg:golang/example.com/a", "example.com/a/native", "pkg:golang/example.com/b", "example.com/b/native"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML: limit panel does not name %q", want)
		}
	}
}
