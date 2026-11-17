package github_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

func declaredReport(rows ...[]string) report.Report {
	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"}
	b := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"})
	for i, assumptions := range rows {
		b.AddFinding(report.AdvisoryFinding{
			Advisory: report.Advisory{ID: "GO-2099-000" + string(rune('1'+i)), Source: "osv"},
			Package:  &pkg,
			Verdict:  report.VerdictNotExploitable,
			Evidence: report.EvidenceSummary{Basis: verdict.BasisSymbolAbsent, Detail: "no reachable path", Assumptions: assumptions},
		})
	}
	return b.Build()
}

// A not_exploitable that holds only under a declaration says so on the comment, beside the counts;
// a row without one adds nothing.
func TestBothSurfaces_DeclaredAssumptions(t *testing.T) {
	const a, b = `library-entrypoints "none": no code outside the build imports example.com/m/lib`, `second declaration`
	tests := []struct {
		name string
		rows [][]string
		want []string
		none bool
	}{
		{name: "one assumption", rows: [][]string{{a}},
			want: []string{"`GO-2099-0001` holds only under the stated assumption: `" + a + "`"}},
		{name: "several assumptions on one row", rows: [][]string{{a, b}},
			want: []string{
				"`GO-2099-0001` holds only under the stated assumption: `" + a + "`",
				"`GO-2099-0001` holds only under the stated assumption: `" + b + "`",
			}},
		{name: "shared assumption names every row", rows: [][]string{{a}, nil, {a}},
			want: []string{"`GO-2099-0001`, `GO-2099-0003` hold only under the stated assumption: `" + a + "`"}},
		{name: "none", rows: [][]string{nil}, none: true},
		{name: "metacharacters stay literal", rows: [][]string{{"[x](https://example.invalid) <img src=x onerror=1> **b** a`b | c\nd"}},
			want: []string{"``[x](https://example.invalid) <img src=x onerror=1> **b** a`b | c d``"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for surface, s := range bothSurfaces(t, declaredReport(tc.rows...)) {
				if tc.none {
					if strings.Contains(s, assumptionsLabel) || strings.Contains(s, "only under the stated assumption") {
						t.Errorf("%s: block without an assumption\n---\n%s", surface, s)
					}
					continue
				}
				i := strings.Index(s, assumptionsLabel)
				if i < 0 {
					t.Fatalf("%s: no assumptions block\n---\n%s", surface, s)
				}
				if j := strings.Index(s, "| Verdict"); j >= 0 && j < i {
					t.Errorf("%s: the assumptions block must precede the counts table\n---\n%s", surface, s)
				}
				for _, w := range tc.want {
					if !strings.Contains(s, w) {
						t.Errorf("%s: missing %q\n---\n%s", surface, w, s)
					}
				}
			}
		})
	}
}
