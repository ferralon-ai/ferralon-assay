package github_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
)

func renderedTier0Result(t *testing.T, res resultsink.Result) string {
	t.Helper()
	summaryPath := filepath.Join(t.TempDir(), "summary.md")
	sink := &ghsink.Tier0Summary{SummaryPath: summaryPath, Annotations: io.Discard}
	if err := sink.Publish(context.Background(), res); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	b, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	return string(b)
}

// Each dependency fetch outcome renders in the job summary with its registry and its fix, before
// the counts it qualifies; the PR comment renders none of them, since it never names a registry.
func TestTier0_DependencyFetchOutcomes(t *testing.T) {
	since := time.Date(2026, 10, 27, 9, 30, 0, 0, time.UTC)
	const reg = "https://npm.corp.example/api/npm"
	cases := []struct {
		name string
		note resultsink.DependencyFetchNote
		want []string
	}{
		{
			name: "credential rejected",
			note: resultsink.DependencyFetchNote{Registry: reg, Outcome: resultsink.DependencyFetchCredentialRejected, Package: "pkg:npm/left-pad@1.3.0", Hint: "renew the token."},
			want: []string{"`" + reg + "` refused the token this run sent (HTTP 401 or 403) for `pkg:npm/left-pad@1.3.0`, so the run fails.", "Renew the token."},
		},
		{
			name: "missing credential",
			note: resultsink.DependencyFetchNote{Registry: reg, Outcome: resultsink.DependencyFetchMissingCredential, Hint: "set NPM_TOKEN."},
			want: []string{"`" + reg + "` asked for a token this run did not have.", "Set NPM_TOKEN."},
		},
		{
			name: "held",
			note: resultsink.DependencyFetchNote{Registry: reg, Outcome: resultsink.DependencyFetchHeld, HeldRuns: 1, Since: since, Hint: "wait."},
			want: []string{"`" + reg + "` served nothing on this run, so the advisory cursor holds (1 held run since 2026-10-27 09:30 UTC).", "Wait."},
		},
		{
			name: "stalled",
			note: resultsink.DependencyFetchNote{Registry: reg, Outcome: resultsink.DependencyFetchStalled, HeldRuns: 3, Since: since, Hint: "check it."},
			want: []string{"`" + reg + "` has served nothing on 3 cve-watch runs since 2026-10-27 09:30 UTC, holding the advisory cursor, so the run fails.", "Check it."},
		},
		{
			name: "unknown outcome is stated, not dropped",
			note: resultsink.DependencyFetchNote{Registry: reg, Outcome: "brand_new"},
			want: []string{"`" + reg + "`: `brand_new`."},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := resultsink.Result{Report: emptyReport(), DependencyFetch: []resultsink.DependencyFetchNote{tc.note}}
			s := renderedTier0Result(t, res)
			for _, w := range append([]string{"**Dependency code.**"}, tc.want...) {
				if !strings.Contains(s, w) {
					t.Errorf("summary missing %q\n---\n%s", w, s)
				}
			}
			if i, j := strings.Index(s, "**Dependency code.**"), strings.Index(s, "| Verdict | Count |"); i < 0 || j < 0 || i > j {
				t.Errorf("the dependency code block must precede the counts (block@%d, table@%d)", i, j)
			}
			if body := renderedTier1Body(t, res); strings.Contains(body, reg) || strings.Contains(body, "Dependency code.") {
				t.Errorf("the PR comment must not name a registry\n---\n%s", body)
			}
		})
	}
}

func TestTier0_NoDependencyFetchNotes_NoBlock(t *testing.T) {
	if s := renderedTier0Result(t, resultsink.Result{Report: emptyReport()}); strings.Contains(s, "Dependency code.") {
		t.Errorf("a run whose fetch needs nothing must render no block\n---\n%s", s)
	}
}

// The scan-level dependency code notes read as did-not-run disclosures with a fix, on both
// surfaces, and never fall to the generic "incomplete" arm.
func TestBothSurfaces_DependencyCodeNotes(t *testing.T) {
	cases := []struct {
		name string
		note report.PartialityNote
		want []string
		not  []string
	}{
		{
			name: "missing credential fallback",
			note: report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm", Detail: "policy_refused: pkg:npm/left-pad@1.3.0: missing-credential"},
			want: []string{"The scan read none of its npm dependency code (`policy_refused: pkg:npm/left-pad@1.3.0: missing-credential`), as with dependency code off", "give the scan step the registry's token variable"},
		},
		{
			name: "rejected credential fallback",
			note: report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm", Detail: "policy_refused: pkg:npm/left-pad@1.3.0: credential-rejected"},
			want: []string{"A registry refused the token the run sent: renew the token", "curation proxy"},
		},
		{
			name: "other policy refusal",
			note: report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm", Detail: "policy_refused: pkg:npm/left-pad@1.3.0: non-https"},
			want: []string{"The fetch policy refused a package for the reason named"},
		},
		{
			name: "unreachable registry",
			note: report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm", Detail: "registry_unreachable: pkg:npm/left-pad@1.3.0"},
			want: []string{"check that it is up and reachable from the runner"},
		},
		{
			name: "integrity mismatch",
			note: report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm", Detail: "integrity_mismatch: pkg:npm/left-pad@1.3.0"},
			want: []string{"did not match the lockfile's integrity hash"},
		},
		{
			name: "inventory failure has no hint",
			note: report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm", Detail: "inventory_failed"},
			want: []string{"The scan read none of its npm dependency code (`inventory_failed`)"},
			not:  []string{"ran out of time"},
		},
		{
			name: "inventory cut off by the deadline",
			note: report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm", Detail: "inventory_failed: cancelled"},
			want: []string{"ran out of time or the run was cancelled", "ASSAY_DEPENDENCY_TIMEOUT"},
		},
		{
			name: "fetch cut off by the deadline",
			note: report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm", Detail: "cancelled: pkg:npm/left-pad@1.3.0"},
			want: []string{"ran out of time or the run was cancelled", "ASSAY_DEPENDENCY_TIMEOUT"},
		},
		{
			name: "other fetch failure",
			note: report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm", Detail: "fetch_failed: pkg:npm/left-pad@1.3.0"},
			want: []string{"check the runner's network and that the dependency cache directory is writable"},
		},
		{
			name: "not fetched",
			note: report.PartialityNote{Reason: report.ReasonDependencyNotFetched, Ecosystem: "npm"},
			want: []string{"last assessed on a run that did not read all the npm dependency code the lockfile pins", "A later run that reads that code assesses them again."},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := emptyReport(tc.note)
			if tc.note.Reason == report.PartialReasonDependencyCodeUnavailable {
				r.DependencyCode = fellBack(tc.note.Detail)
			}
			for name, s := range bothSurfaces(t, r) {
				for _, w := range append([]string{"Partial coverage"}, tc.want...) {
					if !strings.Contains(s, w) {
						t.Errorf("%s: missing %q\n---\n%s", name, w, s)
					}
				}
				for _, w := range tc.not {
					if strings.Contains(s, w) {
						t.Errorf("%s: has %q\n---\n%s", name, w, s)
					}
				}
				if strings.Contains(s, "analysis was incomplete") {
					t.Errorf("%s: fell to the generic arm\n---\n%s", name, s)
				}
			}
		})
	}
}

// fellBack is the DependencyCode of a run whose own fetch fell back for the cause detail names,
// as stamp records it alongside its dependency_code_unavailable note.
func fellBack(detail string) *report.DependencyCode {
	kind, rest, _ := strings.Cut(detail, ": ")
	return &report.DependencyCode{Source: report.DependencyCodeSourceFetch, Cause: &report.DependencyCodeCause{Kind: kind, Detail: rest}}
}

// A cve-watch run carries the dependency_code_unavailable notes of the earlier runs whose verdicts
// it keeps. Only the run's own fall-back says this scan read none of its code, and every note of
// the ecosystem renders as one line.
func TestBothSurfaces_CarriedDependencyCodeNotes(t *testing.T) {
	note := func(detail string) report.PartialityNote {
		return report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm", Detail: detail}
	}
	const (
		unreachable = "registry_unreachable: pkg:npm/left-pad@1.3.0"
		missing     = "policy_refused: pkg:npm/left-pad@1.3.0: missing-credential"
		rejected    = "policy_refused: pkg:npm/%40corp/b@2.0.0: credential-rejected"
	)
	read := &report.DependencyCode{Source: report.DependencyCodeSourceFetch}
	cases := []struct {
		name    string
		dc      *report.DependencyCode
		notes   []report.PartialityNote
		want    []string
		not     []string
		earlier int
		readNo  int
	}{
		{
			name:    "run read its code, one carried note",
			dc:      read,
			notes:   []report.PartialityNote{note(unreachable)},
			want:    []string{"Some verdicts below were reached on an earlier run that did not read its npm dependency code (`" + unreachable + "`)", "check that it is up and reachable from the runner"},
			earlier: 1,
		},
		{
			name:    "run read its code, carried notes with different causes",
			dc:      read,
			notes:   []report.PartialityNote{note(missing), note(rejected)},
			want:    []string{"(`" + rejected + "`; `" + missing + "`)", "give the scan step the registry's token variable", "renew the token"},
			earlier: 1,
		},
		{
			name:    "non-JS run on a shared ref carries the note",
			dc:      nil,
			notes:   []report.PartialityNote{note(unreachable)},
			want:    []string{"reached on an earlier run that did not read its npm dependency code (`" + unreachable + "`)"},
			earlier: 1,
		},
		{
			name:    "run fell back and carries an earlier note",
			dc:      fellBack(rejected),
			notes:   []report.PartialityNote{note(missing), note(rejected)},
			want:    []string{"The scan read none of its npm dependency code (`" + rejected + "`)", "Some were reached on an earlier run that did not read it either (`" + missing + "`)", "give the scan step the registry's token variable", "renew the token"},
			earlier: 1,
			readNo:  1,
		},
		{
			name:   "run fell back, no earlier note",
			dc:     fellBack(unreachable),
			notes:  []report.PartialityNote{note(unreachable)},
			want:   []string{"The scan read none of its npm dependency code (`" + unreachable + "`)"},
			not:    []string{"earlier run"},
			readNo: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := emptyReport(tc.notes...)
			r.DependencyCode = tc.dc
			for name, s := range bothSurfaces(t, r) {
				for _, w := range tc.want {
					if !strings.Contains(s, w) {
						t.Errorf("%s: missing %q\n---\n%s", name, w, s)
					}
				}
				for _, w := range tc.not {
					if strings.Contains(s, w) {
						t.Errorf("%s: has %q\n---\n%s", name, w, s)
					}
				}
				if got := strings.Count(s, "earlier run that did not read"); got != tc.earlier {
					t.Errorf("%s: %d earlier-run lines, want %d\n---\n%s", name, got, tc.earlier, s)
				}
				if got := strings.Count(s, "The scan read none of its"); got != tc.readNo {
					t.Errorf("%s: %d read-none lines, want %d\n---\n%s", name, got, tc.readNo, s)
				}
			}
		})
	}
}
