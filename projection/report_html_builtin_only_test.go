package projection_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestReportHTML_BuiltinOnly_Banner: report.html opens with "not a vulnerability scan" exactly when
// the pass evaluated only the built-in test advisories.
func TestReportHTML_BuiltinOnly_Banner(t *testing.T) {
	cases := []struct {
		name  string
		intel *report.IntelProvenance
		want  string // "" = no banner
	}{
		{"built-in set", &report.IntelProvenance{WorkSetSource: report.WorkSetBuiltinLanguageSet, WorkSetSize: 3}, "This run evaluated only 3 test advisories built into the scanner"},
		{"corpus policy", &report.IntelProvenance{WorkSetSource: "builtin_language_set_union_policy", WorkSetSize: 40}, ""},
		{"no intel block", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fixtureReport()
			r.Provenance.Intel = tc.intel
			b, err := projection.ProjectReportHTML(r)
			if err != nil {
				t.Fatalf("ProjectReportHTML: %v", err)
			}
			html := string(b)
			has := strings.Contains(html, `id="builtin-only"`)
			if tc.want == "" {
				if has {
					t.Errorf("banner rendered for a run with a real work set")
				}
				return
			}
			if !has || !strings.Contains(html, "This is not a vulnerability scan") || !strings.Contains(html, tc.want) {
				t.Errorf("banner missing %q", tc.want)
			}
			// The engine renders this for every caller, so it states the cause and names no Action input.
			if !strings.Contains(html, "no advisory corpus policy defined this run") || strings.Contains(html, "builtin-test-advisories-only") {
				t.Errorf("banner must state that no corpus policy defined the work set, and name no Action input")
			}
		})
	}
}
