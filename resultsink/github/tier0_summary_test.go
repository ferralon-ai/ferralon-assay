package github_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// fixtureReport builds a Report covering the three GROUNDED verdicts so the summary and
// annotation paths are both exercised. The fourth (undetermined) has its own fixtures in
// undetermined_disclosure_test.go, where the point is that it is never folded into these counts.
func fixtureReport() report.Report {
	goPkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"}
	npmPkg := report.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	return report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		ReachableCandidate(report.Advisory{ID: "CVE-2023-39325", Source: "nvd"}, &goPkg, "net/http.Handler → x/text.Vuln", "candidate").
		ReachableCandidate(report.Advisory{ID: "CVE-2021-23337", Source: "nvd"}, &npmPkg, "app.handler → lodash.template", "candidate").
		NotExploitable(report.Advisory{ID: "GO-2022-0322", Source: "osv"}, &goPkg, verdict.BasisSymbolAbsent, "vulnerable symbol absent").
		Disqualified(report.Advisory{ID: "CVE-2020-0001", Source: "nvd"}, &goPkg, verdict.BasisVersionNotAffected, "resolved version below first affected").
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()
}

func newResult() resultsink.Result {
	return resultsink.Result{Report: fixtureReport()}
}

// TestTier0_WritesSummaryAndAnnotations asserts Publish appends GFM to the
// step-summary file and emits a ::warning file=...:: line for each candidate.
func TestTier0_WritesSummaryAndAnnotations(t *testing.T) {
	summaryPath := filepath.Join(t.TempDir(), "summary.md")
	var annotations bytes.Buffer

	sink := &ghsink.Tier0Summary{SummaryPath: summaryPath, Annotations: &annotations, Workspace: "/work"}
	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	summary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	s := string(summary)
	for _, want := range []string{
		"## " + brand.Tier0SummaryHeading, // brand-derived, not hardcoded — see brand/brand_identity.go
		"github.com/example/widget",
		"Reachable candidate",
		"| Reachable candidate | 2 |",
		"| Not exploitable | 1 |",
		"| Disqualified | 1 |",
		"CVE-2023-39325",
		"net/http.Handler",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q\n---\n%s", want, s)
		}
	}

	ann := annotations.String()
	annLines := strings.Count(ann, "::warning")
	if annLines != 2 {
		t.Fatalf("want 2 warning annotations, got %d:\n%s", annLines, ann)
	}
	if !strings.Contains(ann, "::warning file=go.mod::") {
		t.Errorf("missing Go manifest annotation:\n%s", ann)
	}
	if !strings.Contains(ann, "::warning file=package.json::") {
		t.Errorf("missing npm manifest annotation:\n%s", ann)
	}
	if !strings.Contains(ann, "CVE-2023-39325") {
		t.Errorf("annotation missing advisory id:\n%s", ann)
	}
	// inv. 5: never "error", never "affected", never "exploitable" (without negation).
	for _, forbidden := range []string{"::error", "affected"} {
		if strings.Contains(ann, forbidden) || strings.Contains(s, forbidden) {
			t.Errorf("inv.5 violation: surface contains %q", forbidden)
		}
	}
}

// TestTier0_ForkedPR_NoToken asserts the sink runs identically with no token set —
// the forked-PR condition. It performs no API call and produces the same output.
func TestTier0_ForkedPR_NoToken(t *testing.T) {
	// Simulate a forked-PR Actions env: summary path present, token absent.
	for _, k := range []string{ghsink.EnvToken, ghsink.EnvActions, ghsink.EnvStepSummary, ghsink.EnvWorkspace} {
		t.Setenv(k, "")
	}
	summaryPath := filepath.Join(t.TempDir(), "summary.md")
	t.Setenv(ghsink.EnvActions, "true")
	t.Setenv(ghsink.EnvStepSummary, summaryPath)
	// GITHUB_TOKEN deliberately left empty (forked-PR read-only / absent).

	env := ghsink.DetectEnv()
	if env.Token != "" {
		t.Fatalf("expected empty token in forked-PR fixture, got %q", env.Token)
	}

	var annotations bytes.Buffer
	sink := ghsink.NewTier0Summary(env)
	sink.Annotations = &annotations // redirect stdout to buffer for assertion

	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("Publish with no token: %v", err)
	}

	if _, err := os.Stat(summaryPath); err != nil {
		t.Fatalf("summary not written on forked-PR path: %v", err)
	}
	if !strings.Contains(annotations.String(), "::warning") {
		t.Fatalf("annotations not emitted on forked-PR path:\n%s", annotations.String())
	}
}

// TestTier0_NoCandidates_NoAnnotations asserts that a clean Report (no candidates)
// still writes a summary but emits zero annotations.
func TestTier0_NoCandidates_NoAnnotations(t *testing.T) {
	goPkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"}
	r := report.NewBuilder(report.Subject{Repo: "github.com/example/clean", ResolvedCommit: "def456"}).
		Disqualified(report.Advisory{ID: "CVE-2020-0001", Source: "nvd"}, &goPkg, verdict.BasisVersionNotAffected, "out of range").
		WithProvenance(report.Provenance{CommitSHA: "def456", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()

	summaryPath := filepath.Join(t.TempDir(), "summary.md")
	var annotations bytes.Buffer
	sink := &ghsink.Tier0Summary{SummaryPath: summaryPath, Annotations: &annotations}
	if err := sink.Publish(context.Background(), resultsink.Result{Report: r}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if strings.Contains(annotations.String(), "::warning") {
		t.Errorf("expected no annotations for a candidate-free report, got:\n%s", annotations.String())
	}
	summary, _ := os.ReadFile(summaryPath)
	if !strings.Contains(string(summary), "No reachable candidates") {
		t.Errorf("expected clean headline, got:\n%s", summary)
	}
}

// TestTier0_NoSummaryPath_AnnotationsStillEmit asserts that with no step-summary
// path (not inside Actions) the sink skips the summary but still emits annotations.
func TestTier0_NoSummaryPath_AnnotationsStillEmit(t *testing.T) {
	var annotations bytes.Buffer
	sink := &ghsink.Tier0Summary{SummaryPath: "", Annotations: &annotations}
	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !strings.Contains(annotations.String(), "::warning") {
		t.Fatalf("annotations should emit without a summary path:\n%s", annotations.String())
	}
}

// TestTier0_AnnotationEscaping asserts a candidate path containing command-breaking
// characters is percent-encoded in the workflow command.
func TestTier0_AnnotationEscaping(t *testing.T) {
	goPkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"}
	r := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc"}).
		ReachableCandidate(report.Advisory{ID: "CVE-X", Source: "nvd"}, &goPkg, "a\nb%c", "d").
		Build()
	var annotations bytes.Buffer
	sink := &ghsink.Tier0Summary{Annotations: &annotations}
	if err := sink.Publish(context.Background(), resultsink.Result{Report: r}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	line := annotations.String()
	if strings.Contains(line, "a\nb") {
		t.Errorf("newline not escaped in annotation data: %q", line)
	}
	if !strings.Contains(line, "%0A") || !strings.Contains(line, "%25") {
		t.Errorf("expected percent-encoded data, got: %q", line)
	}
}
