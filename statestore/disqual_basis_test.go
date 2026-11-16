package statestore

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// oldShapeReport is report.json as a scanner through v0.6.0 committed it: intake disqualifications
// carry their grounds in the detail line only, with no basis.
func oldShapeReport(schema string, rows ...string) []byte {
	return []byte(`{"schema_version": "` + schema + `", "subject": {"repo": "r", "resolved_commit": "c"},
	  "sbom": {"packages": []},
	  "advisories": [` + strings.Join(rows, ",") + `],
	  "provenance": {"commit_sha": "c", "analyzer_version": "v0.6.0", "advisory_cursor": "", "timestamp": "2026-11-01T00:00:00Z"}}`)
}

func disqRow(id, basis, detail string) string {
	b := ""
	if basis != "" {
		b = `"basis": "` + basis + `", `
	}
	return `{"advisory": {"id": "` + id + `", "source": "osv"}, "verdict": "disqualified", "evidence": {` + b + `"detail": "` + detail + `"}}`
}

// TestDecodeReport_OldShapeDisqualificationsReadWithTheirBasis: a StateStore written before every
// disqualification carried a basis still reads, and each empty-basis disqualification reads with the
// basis its detail line names. Without the backfill, Validate's grounds rule would refuse the whole
// document and every baseline, cve-watch and reanalyze read of an existing install would fail.
func TestDecodeReport_OldShapeDisqualificationsReadWithTheirBasis(t *testing.T) {
	const (
		ecosystem = "the advisory targets a different ecosystem than this codebase; no version or symbol comparison was performed"
		manifest  = "the advisory's package is not installed by the build: its dependency manifest or build graph has no entry for it; no version or symbol comparison was performed"
		legacy    = "the advisory's package is absent from this codebase's dependency manifest; no version or symbol comparison was performed"
		version   = "resolved dependency version is outside the advisory's affected range"
	)
	rows := []string{
		disqRow("GO-1", "", ecosystem),
		disqRow("GO-2", "", manifest),
		disqRow("GO-3", "", legacy),
		disqRow("GO-4", "", manifest+" (per advisory GO-4, record 0123abcd)"),
		disqRow("GO-5", "version_not_in_affected_range", version),
		`{"advisory": {"id": "GO-7", "source": "osv"}, "verdict": "not_exploitable", "evidence": {"basis": "vulnerable_symbol_unreachable", "detail": "no path"}}`,
	}
	want := map[string]verdict.NonExploitableBasis{
		"GO-1": verdict.BasisAdvisoryEcosystemMismatch,
		"GO-2": verdict.BasisNoManifestEntry,
		"GO-3": verdict.BasisNoManifestEntry,
		"GO-4": verdict.BasisNoManifestEntry,
		"GO-5": verdict.BasisVersionNotAffected,
		"GO-7": verdict.BasisSymbolUnreachable,
	}
	for _, schema := range []string{report.SchemaVersion, report.SchemaVersionV2} {
		t.Run(schema, func(t *testing.T) {
			got, err := decodeReport(oldShapeReport(schema, rows...))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(got.Advisories) != len(want) {
				t.Fatalf("advisories = %d, want %d", len(got.Advisories), len(want))
			}
			for _, f := range got.Advisories {
				if f.Evidence.Basis != want[f.Advisory.ID] {
					t.Errorf("%s basis = %q, want %q", f.Advisory.ID, f.Evidence.Basis, want[f.Advisory.ID])
				}
			}
		})
	}
}

// TestDecodeReport_UngroundedRowsStayRefused: the backfill names only a basis the detail states. A
// version or symbol disqualification without its basis, one whose detail names no axis, and a not_exploitable with no basis, are refused at
// the boundary rather than given grounds nobody recorded.
func TestDecodeReport_UngroundedRowsStayRefused(t *testing.T) {
	for _, tc := range []struct{ name, row string }{
		{"disqualified on an unnamed axis", disqRow("GO-1", "", "disqualified on an axis that is neither a version nor a symbol comparison; neither comparison was performed")},
		{"version disqualification with no basis", disqRow("GO-1", "", "resolved dependency version is outside the advisory's affected range")},
		{"disqualified with no detail", `{"advisory": {"id": "GO-1", "source": "osv"}, "verdict": "disqualified", "evidence": {}}`},
		{"not_exploitable with no basis", `{"advisory": {"id": "GO-1", "source": "osv"}, "verdict": "not_exploitable", "evidence": {"detail": "the vulnerable symbol is absent from the built artifact"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeReport(oldShapeReport(report.SchemaVersion, tc.row)); err == nil {
				t.Fatal("decode accepted an ungrounded row")
			}
		})
	}
}
