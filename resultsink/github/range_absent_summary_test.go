package github_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// rangeAbsentFinding is a reachable advisory the scan left undetermined because the advisory gives no
// range the version axis can check.
func rangeAbsentFinding(id string, pkg *report.Package, entry string, bounds ...report.AdvisoryBound) report.AdvisoryFinding {
	f := report.AdvisoryFinding{
		Advisory:           report.Advisory{ID: id, Source: "corpus"},
		Package:            pkg,
		Verdict:            report.VerdictUndetermined,
		UndeterminedReason: report.ReasonAdvisoryRangeAbsent,
		Evidence: report.EvidenceSummary{
			Detail:         report.UndeterminedDetail(report.ReasonAdvisoryRangeAbsent),
			ReachablePath:  entry + " → requests.get",
			AdvisoryBounds: bounds,
		},
	}
	if entry != "" {
		f.Evidence.EntryPoint = &report.EntryPoint{Symbol: entry, Kind: "http_route"}
	}
	return f
}

func rangeAbsentReport(findings ...report.AdvisoryFinding) report.Report {
	b := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"})
	for _, f := range findings {
		b.AddFinding(f)
	}
	return b.WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).Build()
}

// TestTier0Summary_RangeAbsentSection: a range-absent advisory keeps its path, so the summary names
// it in words a reader can act on rather than folding it into the "Not assessed" count.
func TestTier0Summary_RangeAbsentSection(t *testing.T) {
	requests := &report.Package{Ecosystem: "PyPI", Name: "requests", Version: "2.32.3"}
	cases := []struct {
		name    string
		finding report.AdvisoryFinding
		want    []string
		mustNot []string
	}{
		{
			name:    "no range at all",
			finding: rangeAbsentFinding("PYSEC-2015-17", requests, "app.views.fetch"),
			want: []string{
				"### Reachable, with no version range to check",
				"- `requests` 2.32.3 (PyPI) is reachable from `app.views.fetch` and is named in PYSEC-2015-17. " +
					"The advisory does not give a version range Assay can check 2.32.3 against. " +
					"Confirm with the advisory or the maintainer whether 2.32.3 is affected.",
			},
			mustNot: []string{"it records:", "fixed"},
		},
		{
			name:    "introduced only",
			finding: rangeAbsentFinding("GHSA-aaaa", requests, "app.views.fetch", report.AdvisoryBound{Introduced: "2.0.0"}),
			want:    []string{"check 2.32.3 against; it records: introduced 2.0.0, no fix. Confirm"},
		},
		{
			name: "last affected, and a second range",
			finding: rangeAbsentFinding("GHSA-bbbb", requests, "app.views.fetch",
				report.AdvisoryBound{Introduced: "1.0.0", LastAffected: "1.2.0"}, report.AdvisoryBound{LastAffected: "2.31.0"}),
			want:    []string{"; it records: introduced 1.0.0, last affected 1.2.0; last affected 2.31.0. Confirm"},
			mustNot: []string{"no fix"},
		},
		{
			name:    "version not determined",
			finding: rangeAbsentFinding("GHSA-cccc", &report.Package{Ecosystem: "Maven", Name: "com.example:widget"}, "com.example.Api.handle"),
			want: []string{
				"- `com.example:widget` version not determined (Maven) is reachable from `com.example.Api.handle`",
				"version range Assay can check the installed version against. Confirm with the advisory or the maintainer whether the installed version is affected.",
			},
		},
		{
			name: "pinned but not resolved",
			finding: rangeAbsentFinding("GHSA-dddd",
				&report.Package{Ecosystem: "PyPI", Name: "requests", Version: ">=2.0", PartialReason: "source_unpinned"}, "app.views.fetch"),
			want:    []string{"`requests` version not determined (PyPI)"},
			mustNot: []string{">=2.0", "&gt;=2"},
		},
		{
			name:    "no entry point: the path",
			finding: rangeAbsentFinding("GHSA-eeee", requests, ""),
			want:    []string{"is reachable along ` → requests.get` and"},
		},
		{
			name: "advisory data is escaped",
			finding: rangeAbsentFinding("GHSA-<img src=x>*[x](y)", &report.Package{Ecosystem: "npm", Name: "evil`<b>pkg", Version: "1.0.0\n# Owned"},
				"main`` x", report.AdvisoryBound{Introduced: "<script>_a_"}),
			want: []string{
				"named in GHSA-&lt;img src=x&gt;\\*\\[x\\](y).",
				"- ``evil`<b>pkg`` 1.0.0 # Owned (npm) is reachable from ```main`` x```",
				"it records: introduced &lt;script&gt;\\_a\\_, no fix",
			},
			mustNot: []string{"<img", "<script", "\n# Owned"},
		},
		{
			name:    "a line break in a code span",
			finding: rangeAbsentFinding("GHSA-ffff", requests, "main\n\n# Owned"),
			want:    []string{"is reachable from `main  # Owned` and"},
			mustNot: []string{"\n# Owned"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := renderedTier0Summary(t, rangeAbsentReport(tc.finding))
			for _, w := range tc.want {
				if !strings.Contains(body, w) {
					t.Errorf("summary missing %q\n---\n%s", w, body)
				}
			}
			for _, w := range tc.mustNot {
				if strings.Contains(body, w) {
					t.Errorf("summary contains %q\n---\n%s", w, body)
				}
			}
			if !strings.Contains(body, "| Not assessed (no verdict established) | 1 |") {
				t.Errorf("range-absent row left the counts table\n---\n%s", body)
			}
		})
	}
}

// TestTier0Summary_RangeAbsentSectionOnlyForThatReason: other undetermined rows and candidates do not
// enter the section, and a scan with none renders no heading.
func TestTier0Summary_RangeAbsentSectionOnlyForThatReason(t *testing.T) {
	r := rangeAbsentReport(report.AdvisoryFinding{
		Advisory:           report.Advisory{ID: "CVE-2023-39325", Source: "corpus"},
		Verdict:            report.VerdictUndetermined,
		UndeterminedReason: report.ReasonGoToolchainNotScanned,
		Evidence:           report.EvidenceSummary{Detail: report.UndeterminedDetail(report.ReasonGoToolchainNotScanned)},
	})
	if body := renderedTier0Summary(t, r); strings.Contains(body, "no version range to check") || strings.Contains(body, "CVE-2023-39325 ") {
		t.Errorf("non-range-absent row rendered in the range-absent section\n---\n%s", body)
	}
}

// TestTier0Summary_RangeAbsentSectionOrder: rows render in advisory-id order, independent of report order.
func TestTier0Summary_RangeAbsentSectionOrder(t *testing.T) {
	pkg := &report.Package{Ecosystem: "PyPI", Name: "requests", Version: "2.32.3"}
	// Built by hand: the report builder already orders advisories, and a report from elsewhere may not.
	r := rangeAbsentReport()
	r.Advisories = []report.AdvisoryFinding{rangeAbsentFinding("PYSEC-2", pkg, "a"), rangeAbsentFinding("PYSEC-1", pkg, "a")}
	body := renderedTier0Summary(t, r)
	if i, j := strings.Index(body, "named in PYSEC-1"), strings.Index(body, "named in PYSEC-2"); i < 0 || j < 0 || i > j {
		t.Errorf("rows out of order\n---\n%s", body)
	}
}
