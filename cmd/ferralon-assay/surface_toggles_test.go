package main

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/resultsink/github"
)

// The env var names action.yml exports on the run step for the output surfaces, duplicated here on
// purpose: a typo on either side of that seam would silently ignore an operator's opt-out.
const (
	pagesEnv        = "ASSAY_PAGES"
	codeScanningEnv = "ASSAY_CODE_SCANNING"
	prCommentEnv    = "ASSAY_PR_COMMENT"
	issueEnv        = "ASSAY_ISSUE"
)

// TestSurfaceToggles proves the CLI reads the four output-surface env vars and parses them with
// the documented semantics: Pages opt-in on "true"/"1" only; each other surface off only on an
// explicit "false"/"0".
func TestSurfaceToggles(t *testing.T) {
	cases := []struct {
		name                           string
		pages, codeScanning, pr, issue string
		want                           github.Toggles
	}{
		{name: "all unset → defaults", want: github.Toggles{}},
		{name: "pages on", pages: "true", want: github.Toggles{Pages: true}},
		{name: "pages junk stays off", pages: "yes", want: github.Toggles{}},
		{name: "action.yml all-on values", pages: "0", codeScanning: "1", pr: "1", issue: "1", want: github.Toggles{}},
		{name: "action.yml all-off values", codeScanning: "0", pr: "0", issue: "0",
			want: github.Toggles{DisableCodeScanning: true, DisablePRComment: true, DisableIssue: true}},
		{name: "explicit false", codeScanning: "false", want: github.Toggles{DisableCodeScanning: true}},
		{name: "opt-out junk stays on", pr: "no", want: github.Toggles{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(pagesEnv, c.pages)
			t.Setenv(codeScanningEnv, c.codeScanning)
			t.Setenv(prCommentEnv, c.pr)
			t.Setenv(issueEnv, c.issue)
			if got := surfaceToggles(); got != c.want {
				t.Errorf("surfaceToggles() = %+v, want %+v", got, c.want)
			}
		})
	}
}
