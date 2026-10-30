package github_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
)

const builtinOnlyLead = "**This is not a vulnerability scan.**"

// builtinOnlyCause is the notice's stated cause. The engine renders it for CLI, library and Action
// runs alike, so it states the fact and names no Action input.
const builtinOnlyCause = "no advisory corpus policy defined this run"

// TestBothSurfaces_BuiltinOnly_HeadlineSaysNotAScan: a run that evaluated only the built-in test
// advisories opens, above the verdict headline, by saying it is not a vulnerability scan and how many
// test advisories it evaluated. Every other work set, and an unrecorded one, renders no notice.
func TestBothSurfaces_BuiltinOnly_HeadlineSaysNotAScan(t *testing.T) {
	cases := []struct {
		name  string
		intel *report.IntelProvenance
		want  string // "" = no notice
	}{
		{
			name:  "built-in set",
			intel: &report.IntelProvenance{WorkSetSource: report.WorkSetBuiltinLanguageSet, WorkSetSize: 10},
			want:  "This run evaluated only 10 test advisories built into the scanner",
		},
		{
			name:  "built-in set of one",
			intel: &report.IntelProvenance{WorkSetSource: report.WorkSetBuiltinLanguageSet, WorkSetSize: 1},
			want:  "This run evaluated only 1 test advisory built into the scanner",
		},
		{
			name:  "built-in set, size not recorded",
			intel: &report.IntelProvenance{WorkSetSource: report.WorkSetBuiltinLanguageSet},
			want:  "This run evaluated only a small set of test advisories built into the scanner",
		},
		{
			name:  "corpus policy",
			intel: &report.IntelProvenance{WorkSetSource: "builtin_language_set_union_policy", WorkSetSize: 412, CorpusPolicy: "full"},
		},
		{
			name:  "OSV query",
			intel: &report.IntelProvenance{WorkSetSource: report.WorkSetOSVQuery, WorkSetSize: 7},
		},
		{
			name:  "library run records no work set",
			intel: &report.IntelProvenance{SignalsDigest: "sha256:abc"},
		},
		{
			name: "no intel block",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := noManifestReport()
			r.Provenance.Intel = tc.intel
			for surface, s := range bothSurfaces(t, r) {
				lead := strings.Index(s, builtinOnlyLead)
				if tc.want == "" {
					if lead >= 0 {
						t.Errorf("%s: a run with a real work set carries the built-in-only notice\n---\n%s", surface, s)
					}
					continue
				}
				if lead < 0 || !strings.Contains(s, tc.want) {
					t.Errorf("%s: missing the built-in-only notice %q\n---\n%s", surface, tc.want, s)
					continue
				}
				if !strings.Contains(s, builtinOnlyCause) || strings.Contains(s, "builtin-test-advisories-only") {
					t.Errorf("%s: the notice must state %q and name no Action input\n---\n%s", surface, builtinOnlyCause, s)
				}
				if verdict := strings.Index(s, "**Partial coverage"); verdict < lead {
					t.Errorf("%s: the notice must precede the verdict headline\n---\n%s", surface, s)
				}
			}
		})
	}
}
