package main

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestCVEWatchIntel: an earnest cve-watch pass that added OSV advisories to a built-in work set is not
// stamped built-in only, so its Report does not headline as "not a vulnerability scan"; a pass that
// added nothing new, or ran on any other work set, keeps the resolved stamp.
func TestCVEWatchIntel(t *testing.T) {
	builtin := workSet{
		source:     report.WorkSetBuiltinLanguageSet,
		advisories: []assessment.VulnRef{{ID: "GO-2021-0113"}, {ID: "GO-2022-0322"}},
	}
	policy := workSet{source: workSetSourceBuiltinUnionPolicy, advisories: builtin.advisories}
	cases := []struct {
		name       string
		ws         workSet
		newIDs     []string
		wantSource string
		wantSize   int
	}{
		{"built-in plus new OSV ids", builtin, []string{"GO-2024-0001", "GO-2024-0002"}, workSetSourceBuiltinUnionOSV, 4},
		{"a new id already in the set counts once", builtin, []string{"GO-2021-0113", "GO-2024-0001", "GO-2024-0001"}, workSetSourceBuiltinUnionOSV, 3},
		{"only ids already in the set stay built-in", builtin, []string{"GO-2022-0322"}, report.WorkSetBuiltinLanguageSet, 2},
		{"policy work set is left as resolved", policy, []string{"GO-2024-0001"}, workSetSourceBuiltinUnionPolicy, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := report.IntelProvenance{WorkSetSource: tc.ws.source, WorkSetSize: len(tc.ws.advisories), CorpusPolicy: "p"}
			got := cveWatchIntel(in, tc.ws, tc.newIDs)
			if got.WorkSetSource != tc.wantSource || got.WorkSetSize != tc.wantSize {
				t.Errorf("got %s/%d, want %s/%d", got.WorkSetSource, got.WorkSetSize, tc.wantSource, tc.wantSize)
			}
			if got.CorpusPolicy != "p" {
				t.Errorf("CorpusPolicy dropped: %+v", got)
			}
		})
	}
}
