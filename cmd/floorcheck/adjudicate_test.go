package main

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
)

func TestAdjudicatedRules(t *testing.T) {
	und := ledgerRow("A-1", "m@v1", "unknown", "undetermined", "x", "")
	reach := ledgerRow("CVE-1", "m@v1", "reachable", "reachable_candidate", "", "")
	for _, tc := range []struct {
		name, rows, want string // want is a substring of the error; empty means valid
	}{
		{"seeded unknown", und, ""},
		{"concluded with evidence and bound_to", adjudicate(und), ""},
		{"featured while unknown", reach + reviewYAML(StatusReal, "    featured: true\n"), "adjudicated.status is unknown"},
		{"featured and adjudicated, path real", adjudicate(reach) + reviewYAML(StatusReal, "    featured: true\n"), ""},
		{"featured, adjudicated, path unreviewed", adjudicate(reach) + reviewYAML(StatusUnreviewed, "    featured: true\n"), "only a real path may be featured"},
		{"conclusion without evidence", strings.Replace(adjudicate(und), `evidence: "x.go:1", `, "", 1), "needs by, date and evidence"},
		{"conclusion without reviewer", strings.Replace(adjudicate(und), "by: Eric, ", "", 1), "needs by, date and evidence"},
		{"conclusion without bound_to", strings.Replace(adjudicate(und), ", bound_to: "+testBoundYAML, "", 1), "needs a bound_to"},
		{"reviewer's fields on unknown", strings.Replace(und, "{status: unknown}", "{status: unknown, by: Eric}", 1), "set a status or clear them"},
		{"bad status", strings.Replace(und, "{status: unknown}", "{status: maybe}", 1), `adjudicated status "maybe"`},
		{"no adjudicated block", strings.Replace(und, "    adjudicated: {status: unknown}\n", "", 1), `adjudicated status ""`},
	} {
		_, err := parseLedger([]byte(ledgerHeaderYAML + tc.rows))
		if (err == nil) != (tc.want == "") || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestBoundDiffsAndSeedReset(t *testing.T) {
	a, b := "scip-go gomod app . app/x/Handler().", "scip-go gomod m v1 m/p/Parse()."
	f := rcFinding("A-1", a, b)
	f.Evidence.SymbolConfidence = report.SymbolConfidenceHigh
	rep := report.Report{Advisories: []report.AdvisoryFinding{f}}
	in := scanInputs{Commit: "c1", AssayVersion: "v1", AssayCommit: "abc", CorpusRelease: "corpus-1", GoVersion: "1.23.12"}
	hdr := LedgerHeader{Target: "app"}
	l := seedLedger(hdr, rep, Evidence{}, nil, in)
	row := &l.Rows[0]
	if row.Adjudicated.Status != TruthUnknown || row.PathReview.BoundTo == nil || row.PathReview.BoundTo.Symbol != "m/p.Parse" || row.PathReview.BoundTo.SymbolConfidence != "high" {
		t.Fatalf("seeded row = %+v, %+v", row.Adjudicated, row.PathReview.BoundTo)
	}
	// A person reviews and adjudicates the row, and features it.
	row.PathReview.Status, row.PathReview.By, row.PathReview.Date, row.PathReview.Note = StatusReal, "Eric", "2026-11-16", "ok"
	row.Adjudicated = Adjudicated{Status: TruthReachable, By: "Eric", Date: "2026-11-16", Evidence: "x.go:1", BoundTo: row.PathReview.BoundTo}
	row.Featured = true
	if err := row.validatePathReview(true); err != nil {
		t.Fatal(err)
	}
	if err := row.validateAdjudicated(); err != nil {
		t.Fatal(err)
	}
	rows := engineRows(rep.Advisories)
	if d := boundDiffs(l, rows, in); len(d) != 0 {
		t.Fatalf("unchanged inputs differ: %v", d)
	}
	for _, tc := range []struct {
		name   string
		change func(*scanInputs)
		field  string
	}{
		{"corpus release", func(i *scanInputs) { i.CorpusRelease = "corpus-2" }, "bound_to.analysis.corpus_release"},
		{"go toolchain", func(i *scanInputs) { i.GoVersion = "1.24.0" }, "bound_to.analysis.go_version"},
		{"assay version", func(i *scanInputs) { i.AssayVersion = "v2" }, "bound_to.analysis.assay_version"},
		{"assay commit", func(i *scanInputs) { i.AssayCommit = "def" }, "bound_to.analysis.assay_commit"},
		{"target commit", func(i *scanInputs) { i.Commit = "c2" }, "bound_to.target"},
	} {
		now := in
		tc.change(&now)
		d := boundDiffs(l, rows, now)
		if len(d) != 2 || !strings.Contains(d[0], "path_review "+tc.field) || !strings.Contains(d[1], "adjudicated "+tc.field) || !strings.Contains(d[0], "A-1 | m@v1 | app") {
			t.Errorf("%s: lines = %q, want the path review and the adjudication, naming %s", tc.name, d, tc.field)
		}
		// seed -update resets both reviews and the featured flag.
		reset := seedLedger(hdr, rep, Evidence{}, &l, now)
		if r := reset.Rows[0]; r.PathReview.Status != StatusUnreviewed || r.PathReview.By != "" || r.Adjudicated.Status != TruthUnknown || r.Featured {
			t.Errorf("%s: seed -update kept a stale review: %+v %+v featured=%v", tc.name, r.PathReview, r.Adjudicated, r.Featured)
		}
	}
	// A symbol evidence change is named too, and an unreviewed path is not held to its inputs.
	f.Evidence.SymbolConfidence = report.SymbolConfidenceModerate
	if d := boundDiffs(l, engineRows([]report.AdvisoryFinding{f}), in); len(d) != 2 || !strings.Contains(d[0], "bound_to.symbol_confidence") {
		t.Errorf("symbol evidence lines = %q", d)
	}
	l.Rows[0].PathReview.Status, l.Rows[0].Adjudicated, l.Rows[0].Featured = StatusUnreviewed, Adjudicated{Status: TruthUnknown}, false
	if d := boundDiffs(l, rows, scanInputs{Commit: "other"}); len(d) != 0 {
		t.Errorf("an unreviewed row was held to its inputs: %v", d)
	}
}

func TestIncompleteScan(t *testing.T) {
	var rows []LedgerRow
	pkgs := []report.Package{}
	for _, p := range []string{"a", "b", "c", "d", "e"} {
		rows = append(rows, LedgerRow{Advisory: []string{"X-" + p}, Package: "m/" + p + "@v1"})
		pkgs = append(pkgs, report.Package{Name: "m/" + p, Version: "v1"})
	}
	rows = append(rows, LedgerRow{Advisory: []string{"X-std"}, Package: "stdlib@go1.23.12"}, LedgerRow{Advisory: []string{"X-none"}, Package: "-"})
	l := Ledger{Rows: rows}
	toolFailure := report.PartialityNote{Reason: "tool_failure", Detail: "go list failed"}
	for _, tc := range []struct {
		name    string
		pkgs    []report.Package
		partial []report.PartialityNote
		matched int
		want    []string // a substring per failure, in order
	}{
		{"complete", pkgs, nil, len(rows), nil},
		{"empty inventory", nil, nil, len(rows), []string{"package inventory is empty"}},
		{"inventory short by more than the tolerance", pkgs[:1], nil, len(rows), []string{"lacks 4 of the ledger's 5 component instances"}},
		{"inventory short within the tolerance", pkgs[:2], nil, len(rows), nil},
		{"tool failure", pkgs, []report.PartialityNote{toolFailure}, len(rows), []string{"tool or toolchain failure occurred during the scan: tool_failure: go list failed"}},
		{"localized tool failure", pkgs, []report.PartialityNote{{Reason: "tool_failure:dependency_code_unavailable"}}, len(rows), []string{"tool_failure:dependency_code_unavailable"}},
		{"an inherent limit is not a failure", pkgs, []report.PartialityNote{{Reason: "reflection"}}, len(rows), nil},
		{"rows unmatched", pkgs, nil, len(rows) - 2, []string{"answers 5 of the ledger's 7 rows"}},
	} {
		got := incompleteScan(report.Report{SBOM: report.SBOM{Packages: tc.pkgs}, Partiality: tc.partial}, l, tc.matched)
		if len(got) != len(tc.want) {
			t.Errorf("%s: failures = %+v, want %d", tc.name, got, len(tc.want))
			continue
		}
		for i, f := range got {
			if f.Kind != KindIncompleteScan || !strings.Contains(f.Detail, tc.want[i]) {
				t.Errorf("%s: failure %d = %s: %s, want %q", tc.name, i, f.Kind, f.Detail, tc.want[i])
			}
		}
	}
}

// TestShowcaseRefusesIncompleteAndStale is the smoke test of the new rules: one scan that passes, then
// the same scan emptied, cut short and re-read under another corpus release, each failing the pinned
// check with its own line while the floating one only reports.
func TestShowcaseRefusesIncompleteAndStale(t *testing.T) {
	const sha = "020ab5f34703ea523895ab004825dbfa6f7de060"
	sc := &Showcase{Policy: "full", CorpusRelease: "corpus-92d72057330c", GoVersion: "1.23.12", GOOS: "linux", GOARCH: "amd64"}
	tg := Target{Repo: "o/app", Language: "go", Ref: sha}
	hdr := LedgerHeader{Target: "app", Repo: "o/app", UpstreamSHA: sha, GoVersion: "1.23.12", CorpusRelease: "corpus-92d72057330c", GOOS: "linux", GOARCH: "amd64"}
	row := LedgerRow{Advisory: []string{"GO-1"}, Package: "golang.org/x/text@v0.3.6", Target: "app", Adjudicated: Adjudicated{Status: TruthUnknown},
		EngineExpected: Engine{Verdict: report.VerdictNotExploitable, Reason: "vulnerable_symbol_unreachable"}}
	lg := &Ledger{Header: hdr, Rows: []LedgerRow{row}}
	meta := ok()
	meta.CorpusRelease = sc.CorpusRelease
	full := reportJSON(neGrounded, "")
	full = strings.Replace(full, `"packages":[]`, `"packages":[{"ecosystem":"Go","name":"golang.org/x/text","version":"v0.3.6"}]`, 1)

	if r := evaluateShowcase(tg, sc, laneShowcase, lg, nil, withReport(meta, full)); !r.Pass {
		t.Fatalf("a complete scan failed: %+v", r.Failures)
	}
	stale := *lg
	stale.Rows = []LedgerRow{row}
	stale.Rows[0].Adjudicated = Adjudicated{Status: TruthNotReachable, By: "Eric", Date: "2026-11-16", Evidence: "x.go:1",
		BoundTo: &BoundTo{Target: "app@abc", Component: row.Package, Analysis: Analysis{AssayVersion: "ferralon-assay/main-test", CorpusRelease: "corpus-000000000000", GoVersion: "1.23.12"}}}
	for _, tc := range []struct {
		name, rep string
		lg        *Ledger
		want      string
	}{
		{"empty inventory", strings.Replace(full, `"packages":[{"ecosystem":"Go","name":"golang.org/x/text","version":"v0.3.6"}]`, `"packages":[]`, 1), lg, "package inventory is empty"},
		{"cut short", reportJSON(neGrounded+","+cutShort, cutShortNote), lg, "stopped at its time limit"},
		{"corpus release changed", full, &stale, "bound_to.analysis.corpus_release"},
	} {
		pinned := evaluateShowcase(tg, sc, laneShowcase, tc.lg, nil, withReport(meta, tc.rep))
		var lines []string
		for _, f := range pinned.Failures {
			lines = append(lines, f.Detail+" "+strings.Join(f.Findings, " "))
		}
		if pinned.Pass || !strings.Contains(strings.Join(lines, "\n"), tc.want) {
			t.Errorf("%s: pinned = pass %v, failures %q, want %q", tc.name, pinned.Pass, lines, tc.want)
		}
		if floating := evaluateShowcase(tg, sc, laneShowcaseFloating, tc.lg, nil, withReport(meta, tc.rep)); !floating.Pass {
			t.Errorf("%s: the floating scan failed: %+v", tc.name, floating.Failures)
		}
	}
}
