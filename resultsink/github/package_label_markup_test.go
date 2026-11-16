package github_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
)

// A package label carries ReadPin.Source, a repo path the PR head controls. It must reach the
// step summary and the sticky comment as inert text: the code span holds, a pipe does not split
// the cell, and an @mention or link inside the span does not render.
func TestPackageLabel_AuthorControlledSourceIsInert(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   string // the exact cell the label must render as
	}{
		{"backtick breakout", "x`/requirements.txt", "| ``django (read 1.8.2 in x`/requirements.txt, not resolved)`` |"},
		{"pipe", "a|b/requirements.txt", "| `django (read 1.8.2 in a\\|b/requirements.txt, not resolved)` |"},
		{"mention", "@octo/requirements.txt", "| `django (read 1.8.2 in @octo/requirements.txt, not resolved)` |"},
		{"link", "[click](https://example.invalid)/requirements.txt", "| `django (read 1.8.2 in [click](https://example.invalid)/requirements.txt, not resolved)` |"},
		{
			"the review's combined probe",
			"x`[click](https://example.invalid) @octo|cat`/requirements.txt",
			"| ``django (read 1.8.2 in x`[click](https://example.invalid) @octo\\|cat`/requirements.txt, not resolved)`` |",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := report.Package{Ecosystem: "PyPI", Name: "django",
				ReadPins: &[]report.ReadPin{{Version: "1.8.2", Source: tc.source}}}
			r := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
				ReachableCandidate(report.Advisory{ID: "CVE-2023-0001", Source: "nvd"}, &pkg, "app.handler → django.vuln", "candidate").
				Build()
			surfaces := map[string]string{
				"tier0 summary": renderedTier0Summary(t, r),
				"tier1 comment": renderedTier1Body(t, resultsink.Result{Report: r}),
			}
			for name, body := range surfaces {
				if !strings.Contains(body, tc.want) {
					t.Errorf("%s: cell %q not found\n---\n%s", name, tc.want, body)
				}
			}
		})
	}
}
