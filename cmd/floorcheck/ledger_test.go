package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

const ledgerHeaderYAML = `schema: ferralon.floor-ledger.v1
header:
  target: app
  repo: o/app
  upstream_sha: 0123456789abcdef0123456789abcdef01234567
  entry_packages: ["./..."]
  goos: linux
  goarch: amd64
  build_tags: []
  cgo: false
  test_scope: tests excluded
  go_version: 1.23.12
  corpus_release: corpus-92d72057330c
  comparator: {name: govulncheck, version: v1.9.0, db_timestamp: "2026-11-11T02:51:11Z", evidence: evidence/app.govulncheck.json}
rows:
`

func ledgerRow(advisory, pkg, observed, verdict, reason, gap string) string {
	r := "  - advisory: [" + advisory + "]\n    package: " + pkg + "\n    target: app\n    comparator_observed: " + observed +
		"\n    basis: b\n    source: s\n    adjudicated: {status: unknown}\n    engine_expected: {verdict: " + verdict + ", reason: " + reason + "}\n"
	if gap != "" {
		r += "    gap: \"" + gap + "\"\n"
	}
	return r
}

func TestParseLedger(t *testing.T) {
	good := ledgerRow("CVE-1, GHSA-1", "m@v1", "reachable", "reachable_candidate", "", "") + reviewYAML(StatusUnreviewed, "")
	for _, tc := range []struct {
		name, rows, want string // want is a substring of the error; empty means valid
	}{
		{"valid", good, ""},
		{"gap on disagreement", ledgerRow("A-1", "m@v1", "reachable", "undetermined", "refutation_withheld", "#790"), ""},
		{"disagreement without a gap", ledgerRow("A-1", "m@v1", "reachable", "undetermined", "refutation_withheld", ""), "needs a gap"},
		{"unknown observation claims nothing", ledgerRow("A-1", "m@v1", "unknown", "undetermined", "x", ""), ""},
		{"duplicate row", good + good, "duplicate row"},
		{"unsorted alias set", ledgerRow("GHSA-1, CVE-1", "m@v1", "unknown", "undetermined", "x", ""), "not sorted"},
		{"bad observation", ledgerRow("A-1", "m@v1", "maybe", "undetermined", "x", ""), "comparator_observed \"maybe\""},
		{"unknown field", good + "    colour: red\n", "colour"},
	} {
		_, err := parseLedger([]byte(ledgerHeaderYAML + tc.rows))
		if (err == nil) != (tc.want == "") || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	if _, err := parseLedger([]byte(strings.Replace(ledgerHeaderYAML, "upstream_sha: 0123", "upstream_sha: 123", 1) + good)); err == nil {
		t.Error("a short upstream_sha was accepted")
	}
}

func TestDisagrees(t *testing.T) {
	ne := Engine{Verdict: report.VerdictNotExploitable, Reason: "vulnerable_symbol_unreachable"}
	oor := Engine{Verdict: report.VerdictDisqualified, Reason: "version_not_in_affected_range"}
	und := Engine{Verdict: report.VerdictUndetermined, Reason: "refutation_withheld"}
	rc := Engine{Verdict: report.VerdictReachableCandidate}
	for _, tc := range []struct {
		truth string
		e     Engine
		want  bool
	}{
		{TruthReachable, rc, false}, {TruthReachable, und, true}, {TruthReachable, ne, true},
		{TruthNotReachable, ne, false}, {TruthNotReachable, und, true}, {TruthNotReachable, rc, true},
		{TruthOutOfRange, oor, false}, {TruthOutOfRange, ne, true},
		{TruthUnknown, und, false}, {TruthConditional, rc, false},
		{TruthReachable, Engine{Verdict: VerdictNotEmitted}, true}, {TruthNotReachable, Engine{Verdict: VerdictNotEmitted}, false},
	} {
		if got := disagrees(tc.truth, tc.e); got != tc.want {
			t.Errorf("disagrees(%s, %s) = %v, want %v", tc.truth, tc.e, got, tc.want)
		}
	}
}

func finding(id, pkg, version string, v report.Verdict, reason string, aliases ...string) report.AdvisoryFinding {
	f := report.AdvisoryFinding{Advisory: report.Advisory{ID: id, Source: "osv", Aliases: aliases}, Verdict: v,
		Package: &report.Package{Ecosystem: "Go", Name: pkg, Version: version}}
	if v == report.VerdictUndetermined {
		f.UndeterminedReason = reason
	} else {
		f.Evidence.Basis = verdictBasis(reason)
	}
	return f
}

func TestEngineRows(t *testing.T) {
	rows := engineRows([]report.AdvisoryFinding{
		finding("GHSA-1", "m", "v1", report.VerdictNotExploitable, "vulnerable_symbol_unreachable", "CVE-1"),
		finding("CVE-1", "m", "v1", report.VerdictUndetermined, "refutation_withheld", "GHSA-1", "GO-1"),
		finding("CVE-1", "m", "v2", report.VerdictDisqualified, "version_not_in_affected_range"),
		finding("CVE-2", "n", "v1", report.VerdictDisqualified, "version_not_in_affected_range"),
	})
	var got []string
	for _, r := range rows {
		got = append(got, rowKey(r.Advisory, r.Package, "app")+" = "+r.Engine.String())
	}
	want := []string{
		"CVE-1 / GHSA-1 / GO-1 | m@v1 | app = undetermined/refutation_withheld", // one alias set; the stronger verdict wins
		"CVE-1 | m@v2 | app = disqualified/version_not_in_affected_range",       // another package instance, another row
		"CVE-2 | n@v1 | app = disqualified/version_not_in_affected_range",
	}
	if !slices.Equal(got, want) {
		t.Errorf("rows =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestCompareLedger(t *testing.T) {
	l := Ledger{Header: LedgerHeader{Target: "app"}, Rows: []LedgerRow{
		{Advisory: []string{"A-1"}, Package: "m@v1", Target: "app", EngineExpected: Engine{Verdict: report.VerdictUndetermined, Reason: "refutation_withheld"}},
		{Advisory: []string{"A-2"}, Package: "m@v1", Target: "app", EngineExpected: Engine{Verdict: report.VerdictUndetermined, Reason: "x"}},
		{Advisory: []string{"A-3"}, Package: "m@v1", Target: "app", EngineExpected: Engine{Verdict: report.VerdictReachableCandidate}},
		{Advisory: []string{"A-5"}, Package: "m@v1", Target: "app", EngineExpected: Engine{Verdict: VerdictNotEmitted}}, // still silent: no difference
		{Advisory: []string{"A-6"}, Package: "m@v1", Target: "app", EngineExpected: Engine{Verdict: VerdictNotEmitted}}, // the engine now sees it
	}}
	scan := []engineRow{
		{Advisory: []string{"A-1"}, Package: "m@v1", Engine: Engine{Verdict: report.VerdictNotExploitable, Reason: "static_refutation"}}, // an improvement is still a change
		{Advisory: []string{"A-3"}, Package: "m@v1", Engine: Engine{Verdict: report.VerdictReachableCandidate}},                          // unchanged
		{Advisory: []string{"A-4"}, Package: "m@v1", Engine: Engine{Verdict: report.VerdictUndetermined, Reason: "x"}},
		{Advisory: []string{"A-6"}, Package: "m@v1", Engine: Engine{Verdict: report.VerdictReachableCandidate}},
	}
	want := []string{
		"changed: A-1 | m@v1 | app: undetermined/refutation_withheld -> not_exploitable/static_refutation",
		"missing: A-2 | m@v1 | app: ledger undetermined/x, scan emitted no row",
		"extra: A-4 | m@v1 | app: not in the ledger, scan emitted undetermined/x",
		"changed: A-6 | m@v1 | app: not_emitted -> reachable_candidate",
	}
	if got := compareLedger(l, scan).Lines; !slices.Equal(got, want) {
		t.Errorf("diff =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if d := compareLedger(l, []engineRow{scan[1], {Advisory: []string{"A-1"}, Package: "m@v1", Engine: l.Rows[0].EngineExpected},
		{Advisory: []string{"A-2"}, Package: "m@v1", Engine: l.Rows[1].EngineExpected},
		{Advisory: []string{"A-6"}, Package: "m@v1", Engine: Engine{Verdict: VerdictNotEmitted}}}); len(d.Lines) != 0 {
		t.Errorf("identical rows differ: %v", d.Lines)
	}
}

const vulnStream = `{"config":{"scanner_name":"govulncheck","scanner_version":"v1.9.0","db":"https://vuln.go.dev","db_last_modified":"2026-11-11T02:51:11Z","go_version":"go1.23.12","scan_level":"symbol","scan_mode":"source"}}
{"progress":{"message":"Scanning"}}
{"osv":{"id":"GO-1","aliases":["CVE-1","GHSA-1"]}}
{"osv":{"id":"GO-2","aliases":["CVE-2"]}}
{"osv":{"id":"GO-3","aliases":["CVE-3"]}}
{"finding":{"osv":"GO-1","fixed_version":"v1.1.0","trace":[{"module":"m","version":"v1.0.0"}]}}
{"finding":{"osv":"GO-1","fixed_version":"v1.1.0","trace":[{"module":"m","version":"v1.0.0","package":"m/p"}]}}
{"finding":{"osv":"GO-1","fixed_version":"v1.1.0","trace":[{"module":"m","version":"v1.0.0","package":"m/p","function":"Parse","receiver":"Parser"},{"module":"app","version":"","package":"app/x","function":"main"}]}}
{"finding":{"osv":"GO-2","trace":[{"module":"n","version":"v2.0.0","package":"n/q"}]}}
{"finding":{"osv":"GO-3","trace":[{"module":"o","version":"v1.0.0"}]}}
`

func TestDerive(t *testing.T) {
	ev, err := normalizeGovulncheck(strings.NewReader(vulnStream), "govulncheck")
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Findings) != 3 || ev.Findings[0].Level != levelSymbol || ev.Findings[0].Symbols[0] != "m/p.Parser.Parse" || ev.Findings[0].CalledFrom != "app/x.main" {
		t.Fatalf("evidence = %+v", ev.Findings)
	}
	oor := Engine{Verdict: report.VerdictDisqualified, Reason: "version_not_in_affected_range"}
	und := Engine{Verdict: report.VerdictUndetermined, Reason: "refutation_withheld"}
	for _, tc := range []struct {
		name  string
		row   engineRow
		truth string
		basis string
		src   string
	}{
		{"symbol", engineRow{Advisory: []string{"CVE-1", "GHSA-1"}, Package: "m@v1.0.0", Engine: und}, TruthReachable, "m/p.Parser.Parse", "govulncheck v1.9.0"},
		{"alias match only", engineRow{Advisory: []string{"GHSA-1"}, Package: "m@v1.0.0", Engine: und}, TruthReachable, "", "govulncheck v1.9.0"},
		{"package", engineRow{Advisory: []string{"CVE-2"}, Package: "n@v2.0.0", Engine: und}, TruthNotReachable, "imported, vulnerable function not called", "govulncheck v1.9.0"},
		{"module", engineRow{Advisory: []string{"GO-3"}, Package: "o@v1.0.0", Engine: und}, TruthNotReachable, "required, vulnerable package never imported", "govulncheck v1.9.0"},
		{"other version of the module", engineRow{Advisory: []string{"GO-3"}, Package: "o@v0.9.0", Engine: oor}, TruthOutOfRange, "outside", "assay version comparison"},
		{"stdlib", engineRow{Advisory: []string{"GO-1"}, Package: "stdlib@go1.23.12", Engine: und}, TruthUnknown, "depends on toolchain", "ledger rule"},
		{"no view", engineRow{Advisory: []string{"CVE-9"}, Package: "m@v1.0.0", Engine: und}, TruthUnknown, "no view", "govulncheck v1.9.0"},
	} {
		truth, basis, src := derive(tc.row, ev)
		if truth != tc.truth || !strings.Contains(basis, tc.basis) || !strings.Contains(src, tc.src) {
			t.Errorf("%s: derive = %s / %s / %s, want %s / %q / %q", tc.name, truth, basis, src, tc.truth, tc.basis, tc.src)
		}
	}
}

func TestParseShowcaseTargets(t *testing.T) {
	const sha = "020ab5f34703ea523895ab004825dbfa6f7de060"
	base := func(show string) string {
		return `{"policy":"published-24h","targets":[{"repo":"d/x","language":"go"}],"showcase":` + show + `}`
	}
	good := `{"policy":"full","corpus_release":"corpus-92d72057330c","go_version":"1.23.12","goos":"linux","goarch":"amd64","targets":[{"repo":"o/app","language":"go","ref":"` + sha + `"}]}`
	for _, tc := range []struct{ name, show, want string }{
		{"valid", good, ""},
		{"floating corpus", strings.Replace(good, "corpus-92d72057330c", "main", 1), "not a corpus release tag"},
		{"floating toolchain", strings.Replace(good, "1.23.12", "1.23", 1), "not an exact Go release"},
		{"branch ref", strings.Replace(good, sha, "main", 1), "not a full commit id"},
		{"not go", strings.Replace(good, `"language":"go","ref"`, `"language":"python","ref"`, 1), "Go's"},
	} {
		_, err := parseTargets([]byte(base(tc.show)))
		if (err == nil) != (tc.want == "") || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestShowcasePinnedFailsFloatingReports is the lane's smoke test: the same scan against the same
// ledger fails the pinned scan and only reports on the floating one.
func TestShowcasePinnedFailsFloatingReports(t *testing.T) {
	const sha = "020ab5f34703ea523895ab004825dbfa6f7de060"
	sc := &Showcase{Policy: "full", CorpusRelease: "corpus-92d72057330c", GoVersion: "1.23.12", GOOS: "linux", GOARCH: "amd64"}
	tg := Target{Repo: "o/app", Language: "go", Ref: sha}
	hdr := LedgerHeader{Target: "app", Repo: "o/app", UpstreamSHA: sha, GoVersion: "1.23.12", CorpusRelease: "corpus-92d72057330c", GOOS: "linux", GOARCH: "amd64"}
	row := LedgerRow{Advisory: []string{"GO-1"}, Package: "m@v1", Target: "app",
		EngineExpected: Engine{Verdict: report.VerdictNotExploitable, Reason: "vulnerable_symbol_unreachable"}}
	lg := &Ledger{Header: hdr, Rows: []LedgerRow{row}}
	sr := withReport(ok(), reportJSON(neGrounded, ""))

	// An improvement or a regression is the same difference: the row the ledger expects is not what was emitted.
	changed := *lg
	changed.Rows = []LedgerRow{row}
	changed.Rows[0].Package = "golang.org/x/text@v0.3.6"
	changed.Rows[0].EngineExpected = Engine{Verdict: report.VerdictUndetermined, Reason: "refutation_withheld"}

	pinned := evaluateShowcase(tg, sc, laneShowcase, &changed, nil, sr)
	if pinned.Pass || len(pinned.failureFindings()) != 1 ||
		!strings.Contains(pinned.failureFindings()[0], "undetermined/refutation_withheld -> not_exploitable/vulnerable_symbol_unreachable") {
		t.Errorf("pinned = pass %v, lines %v", pinned.Pass, pinned.failureFindings())
	}
	floating := evaluateShowcase(tg, sc, laneShowcaseFloating, &changed, nil, sr)
	if !floating.Pass || len(floating.Drift) != 1 {
		t.Errorf("floating = pass %v, drift %v", floating.Pass, floating.Drift)
	}
	if missing := evaluateShowcase(tg, sc, laneShowcase, nil, nil, sr); missing.Pass {
		t.Error("a showcase target with no ledger passed")
	}
	stale := changed
	stale.Header.CorpusRelease = "corpus-000000000000"
	if r := evaluateShowcase(tg, sc, laneShowcase, &stale, nil, sr); r.Pass || !strings.Contains(r.failureFindings()[0], "corpus_release") {
		t.Errorf("a ledger for another corpus release passed: %v", r.failureFindings())
	}
}

// verdictBasis converts a test reason string to the evidence basis type.
func verdictBasis(s string) verdict.NonExploitableBasis { return verdict.NonExploitableBasis(s) }
