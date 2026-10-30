package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// reportJSON is a hand-written report.json holding the given advisories[] and partiality[] members.
func reportJSON(advisories, partiality string) string {
	return `{"schema_version":"tegron.report.v3",
"subject":{"repo":"ferralon-demo/x","resolved_commit":"abc"},
"sbom":{"packages":[]},
"advisories":[` + advisories + `],
"partiality":[` + partiality + `],
"provenance":{"commit_sha":"abc","analyzer_version":"ferralon-assay/main-test","advisory_cursor":"","timestamp":"2026-10-29T00:00:00Z"}}`
}

const (
	neGrounded   = `{"advisory":{"id":"GO-1","source":"osv"},"package":{"ecosystem":"Go","name":"golang.org/x/text","version":"v0.3.6","direct":true},"verdict":"not_exploitable","evidence":{"basis":"vulnerable_symbol_unreachable","detail":"no path"}}`
	neUngrounded = `{"advisory":{"id":"GO-2","source":"osv"},"verdict":"not_exploitable","evidence":{"detail":"nothing found"}}`
	neUnknown    = `{"advisory":{"id":"GO-3","source":"osv"},"verdict":"not_exploitable","evidence":{"basis":"looked_hard"}}`
	disqVersion  = `{"advisory":{"id":"GO-4","source":"osv"},"verdict":"disqualified","evidence":{"basis":"version_not_in_affected_range"}}`
	disqIntake   = `{"advisory":{"id":"GO-5","source":"osv"},"verdict":"disqualified","evidence":{"detail":"no version or symbol comparison was performed"}}`
	disqStatic   = `{"advisory":{"id":"GO-6","source":"osv"},"verdict":"disqualified","evidence":{"basis":"static_refutation"}}`
	undetA       = `{"advisory":{"id":"GO-7","source":"osv"},"verdict":"undetermined","undetermined_reason":"advisory_symbol_absent","evidence":{}}`
	undetB       = `{"advisory":{"id":"GO-8","source":"osv"},"verdict":"undetermined","undetermined_reason":"advisory_symbol_absent","evidence":{}}`
	undetC       = `{"advisory":{"id":"GO-9","source":"osv"},"verdict":"undetermined","undetermined_reason":"package_version_unresolved","evidence":{}}`
	cutShort     = `{"advisory":{"id":"GO-10","source":"osv"},"verdict":"undetermined","undetermined_reason":"scan_cut_short","evidence":{}}`
	cutShortNote = `{"reason":"scan_cut_short","detail":"1 of 4 advisories were not assessed: the scan reached its 22m limit"}`
)

func intp(i int) *int { return &i }

func ok() Meta { return Meta{Repo: "ferralon-demo/x", Outcome: "success", ExitCode: intp(0)} }

func withReport(m Meta, rep string) *scanResult {
	return &scanResult{meta: m, report: []byte(rep), hasReport: true}
}

func kinds(fs []Failure) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Kind)
	}
	return out
}

func TestGroundsOf(t *testing.T) {
	for _, tc := range []struct {
		v     report.Verdict
		basis verdict.NonExploitableBasis
		want  grounds
	}{
		{report.VerdictNotExploitable, verdict.BasisSymbolUnreachable, groundsPresent},
		{report.VerdictNotExploitable, verdict.BasisSymbolAbsent, groundsPresent},
		{report.VerdictNotExploitable, verdict.BasisVersionNotAffected, groundsPresent},
		{report.VerdictNotExploitable, verdict.BasisStaticRefutation, groundsPresent},
		{report.VerdictNotExploitable, verdict.BasisNone, groundsMissing},
		{report.VerdictNotExploitable, "looked_hard", groundsMissing},
		{report.VerdictDisqualified, verdict.BasisVersionNotAffected, groundsPresent},
		{report.VerdictDisqualified, verdict.BasisSymbolAbsent, groundsPresent},
		{report.VerdictDisqualified, verdict.BasisNone, groundsUnverifiable},
		{report.VerdictDisqualified, verdict.BasisStaticRefutation, groundsMissing},
		{report.VerdictReachableCandidate, verdict.BasisNone, groundsNotChecked},
		{report.VerdictUndetermined, verdict.BasisNone, groundsNotChecked},
		{report.VerdictMaliciousPresent, verdict.BasisNone, groundsNotChecked},
	} {
		f := report.AdvisoryFinding{Verdict: tc.v, Evidence: report.EvidenceSummary{Basis: tc.basis}}
		if got := groundsOf(f); got != tc.want {
			t.Errorf("%s/%q: grounds = %d, want %d", tc.v, tc.basis, got, tc.want)
		}
	}
}

func TestEvaluate(t *testing.T) {
	tg := Target{Repo: "ferralon-demo/x", Language: "go"}
	for _, tc := range []struct {
		name         string
		sr           *scanResult
		pass         bool
		kinds        []string
		findings     []string // the first failure's findings
		unverifiable []string
		reasons      []ReasonCount
		truncated    bool
	}{
		{name: "grounded not_exploitable passes", sr: withReport(ok(), reportJSON(neGrounded, "")), pass: true},
		{name: "ungrounded not_exploitable fails", sr: withReport(ok(), reportJSON(neGrounded+","+neUngrounded, "")),
			kinds: []string{KindUngroundedNE}, findings: []string{"GO-2"}},
		{name: "unknown basis is no grounds", sr: withReport(ok(), reportJSON(neUnknown, "")),
			kinds: []string{KindUngroundedNE}, findings: []string{"GO-3"}},
		{name: "disqualified with a version basis passes", sr: withReport(ok(), reportJSON(disqVersion, "")), pass: true},
		{name: "disqualified without a basis is unverifiable, not failed", sr: withReport(ok(), reportJSON(disqIntake, "")),
			pass: true, unverifiable: []string{"GO-5"}},
		{name: "disqualified on a refutation basis fails", sr: withReport(ok(), reportJSON(disqStatic, "")),
			kinds: []string{KindUngroundedDisq}, findings: []string{"GO-6"}},
		{name: "undetermined is counted with its reason", sr: withReport(ok(), reportJSON(undetA+","+undetC+","+undetB, "")),
			pass: true, reasons: []ReasonCount{{"advisory_symbol_absent", 2}, {"package_version_unresolved", 1}}},
		{name: "a truncated scan fails", sr: withReport(ok(), reportJSON(neGrounded+","+cutShort, cutShortNote)),
			kinds: []string{KindTruncated}, truncated: true, reasons: []ReasonCount{{"scan_cut_short", 1}}},
		{name: "malformed JSON", sr: withReport(ok(), `{"schema_version":`), kinds: []string{KindMalformed}},
		{name: "unknown schema version", sr: withReport(ok(), strings.Replace(reportJSON("", ""), "tegron.report.v3", "tegron.report.v9", 1)),
			kinds: []string{KindMalformed}},
		{name: "a report that fails its own validation", sr: withReport(ok(), reportJSON(`{"advisory":{"id":"GO-11","source":"osv"},"verdict":"exploitable","evidence":{}}`, "")),
			kinds: []string{KindMalformed}},
		{name: "no result at all", sr: nil, kinds: []string{KindNoResult}},
		{name: "scanner exited non-zero but published", sr: withReport(Meta{Outcome: "failure", ExitCode: intp(1)}, reportJSON(neGrounded, "")),
			kinds: []string{KindScanFailed}},
		{name: "scanner exited non-zero without a report", sr: &scanResult{meta: Meta{Outcome: "failure", ExitCode: intp(1)}},
			kinds: []string{KindScanFailed}},
		{name: "job stopped mid-scan", sr: &scanResult{meta: Meta{Outcome: "cancelled"}}, kinds: []string{KindScanFailed}},
		{name: "scan step never ran", sr: &scanResult{meta: Meta{Outcome: "skipped"}}, kinds: []string{KindScanFailed}},
		{name: "a clean exit with no report", sr: &scanResult{meta: ok()}, kinds: []string{KindNoReport}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := evaluate(tg, "published-24h", tc.sr)
			if res.Pass != tc.pass {
				t.Fatalf("pass = %v, want %v (failures %+v)", res.Pass, tc.pass, res.Failures)
			}
			if got := strings.Join(kinds(res.Failures), ","); got != strings.Join(tc.kinds, ",") {
				t.Errorf("failure kinds = %q, want %q", got, strings.Join(tc.kinds, ","))
			}
			if tc.findings != nil && strings.Join(res.Failures[0].Findings, ",") != strings.Join(tc.findings, ",") {
				t.Errorf("findings = %v, want %v", res.Failures[0].Findings, tc.findings)
			}
			if strings.Join(res.Unverifiable, ",") != strings.Join(tc.unverifiable, ",") {
				t.Errorf("unverifiable = %v, want %v", res.Unverifiable, tc.unverifiable)
			}
			if tc.reasons != nil && !equalReasons(res.TopUndetermined, tc.reasons) {
				t.Errorf("top reasons = %v, want %v", res.TopUndetermined, tc.reasons)
			}
			if res.ScanTruncated != tc.truncated {
				t.Errorf("truncated = %v, want %v", res.ScanTruncated, tc.truncated)
			}
		})
	}
}

func equalReasons(a, b []ReasonCount) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTopReasonCounts(t *testing.T) {
	got := topReasonCounts(map[string]int{"b": 2, "a": 2, "c": 5, "d": 1}, 3)
	want := []ReasonCount{{"c", 5}, {"a", 2}, {"b", 2}}
	if !equalReasons(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTargets(t *testing.T) {
	for _, tc := range []struct {
		name, json, err string
	}{
		{"valid", `{"policy":"published-24h","targets":[{"repo":"o/a","language":"go","ref":"baseline"}],"excluded":[{"repo":"o/b","reason":"no build"}]}`, ""},
		{"full policy refused", `{"policy":"full","targets":[{"repo":"o/a","language":"go"}]}`, "bounded"},
		{"no policy", `{"targets":[{"repo":"o/a","language":"go"}]}`, "policy is required"},
		{"no targets", `{"policy":"published-24h","targets":[]}`, "no targets"},
		{"unknown language", `{"policy":"published-24h","targets":[{"repo":"o/a","language":"cobol"}]}`, "language"},
		{"repo without owner", `{"policy":"published-24h","targets":[{"repo":"a","language":"go"}]}`, "owner/name"},
		{"option-shaped ref", `{"policy":"published-24h","targets":[{"repo":"o/a","language":"go","ref":"--upload-pack=x"}]}`, "ref"},
		{"duplicate name", `{"policy":"published-24h","targets":[{"repo":"o/a","language":"go"},{"repo":"p/a","language":"go"}]}`, "share the name"},
		{"misspelt key", `{"policy":"published-24h","targets":[{"repo":"o/a","langauge":"go"}]}`, "unknown field"},
		{"excluded and targeted", `{"policy":"published-24h","targets":[{"repo":"o/a","language":"go"}],"excluded":[{"repo":"o/a","reason":"x"}]}`, "both"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseTargets([]byte(tc.json))
			switch {
			case tc.err == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
				t.Fatalf("error = %v, want one containing %q", err, tc.err)
			}
		})
	}
}

func TestMatrixOutput(t *testing.T) {
	tg, err := parseTargets([]byte(`{"policy":"published-24h","targets":[{"repo":"o/a","language":"python","ref":"baseline","include_house_canaries":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := matrixOutput(tg)
	if err != nil {
		t.Fatal(err)
	}
	want := `matrix={"include":[{"repo":"o/a","name":"a","language":"python","ref":"baseline","include_house_canaries":true}]}` + "\npolicy=published-24h\n"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestAlert(t *testing.T) {
	failing := func(n int) Summary {
		s := Summary{RunURL: "https://example.test/run/1"}
		for i := 0; i < n; i++ {
			s.Repos = append(s.Repos, RepoResult{Repo: "o/r" + string(rune('a'+i)),
				Failures: []Failure{{Kind: KindUngroundedNE, Findings: []string{"GO-2", "GO-3"}}}})
		}
		s.Repos = append(s.Repos, RepoResult{Repo: "o/ok", Pass: true})
		return s
	}
	for _, tc := range []struct {
		n     int
		lines int
		has   string
	}{
		{0, 0, ""},
		{1, 3, "ra: 2 not_exploitable without grounds (GO-2 and 1 more)."},
		{2, 4, "rb: 2 not_exploitable"},
		{5, 4, "4 more repos failed"},
	} {
		text := failing(tc.n).alert()
		lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
		if text == "" {
			lines = nil
		}
		if len(lines) != tc.lines || len(lines) > alertBullets {
			t.Errorf("%d failing: %d lines, want %d:\n%s", tc.n, len(lines), tc.lines, text)
		}
		if tc.n > 0 && lines[len(lines)-1] != "• Run: https://example.test/run/1" {
			t.Errorf("%d failing: last line %q is not the run link", tc.n, lines[len(lines)-1])
		}
		if !strings.Contains(text, tc.has) {
			t.Errorf("%d failing: alert lacks %q:\n%s", tc.n, tc.has, text)
		}
	}
}

// TestCheckSmoke runs `floorcheck check` over a results directory laid out as the workflow's
// download step lays it out, and checks the exit status and the files it writes.
func TestCheckSmoke(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("targets.json", `{"policy":"published-24h","targets":[
		{"repo":"o/good","language":"go"},{"repo":"o/bad","language":"python"},{"repo":"o/gone","language":"java"}],
		"excluded":[{"repo":"o/skip","reason":"no build files"}]}`)
	write("results/floor-scan-good/meta.json", `{"repo":"o/good","policy":"published-24h","assay_commit":"0123456789abcdef","outcome":"success","exit_code":0,"duration_seconds":75}`)
	write("results/floor-scan-good/report.json", reportJSON(neGrounded+","+disqIntake+","+undetA, ""))
	write("results/floor-scan-bad/meta.json", `{"repo":"o/bad","policy":"published-24h","assay_commit":"0123456789abcdef","outcome":"success","exit_code":0,"duration_seconds":9}`)
	write("results/floor-scan-bad/report.json", reportJSON(neUngrounded, ""))

	out := func(name string) string { return filepath.Join(dir, name) }
	var stdout, stderr bytes.Buffer
	code := run([]string{"check", "-targets", out("targets.json"), "-results", out("results"),
		"-summary", out("s.json"), "-markdown", out("s.md"), "-alert", out("a.txt"),
		"-assay-commit", "0123456789abcdef", "-run-url", "https://example.test/run/9"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit %d, want 1; stdout %s stderr %s", code, stdout.String(), stderr.String())
	}
	for name, want := range map[string][]string{
		"s.json": {`"schema": "ferralon.floor-summary.v1"`, `"pass": false`, `"ungrounded_not_exploitable"`, `"no_result"`, `"unverifiable"`},
		"s.md": {"FAIL — 2 of 3 repos failed", "| dotnet | **no target** |", "| good | go | `0123456789ab` | published-24h | not_exploitable 1 · disqualified 1 · undetermined 1 | `advisory_symbol_absent` 1 | no | 1m15s | pass |",
			"**bad** — `ungrounded_not_exploitable`: 1 not_exploitable without grounds: GO-2", "o/skip: no build files"},
		"a.txt": {"failed on 2 of 3 demo repos", "• Run: https://example.test/run/9"},
	} {
		data, err := os.ReadFile(out(name))
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range want {
			if !strings.Contains(string(data), w) {
				t.Errorf("%s lacks %q:\n%s", name, w, data)
			}
		}
	}

	// The same run with the failing repos dropped passes and writes no alert.
	write("targets.json", `{"policy":"published-24h","targets":[{"repo":"o/good","language":"go"}]}`)
	stdout.Reset()
	if code := run([]string{"check", "-targets", out("targets.json"), "-results", out("results"),
		"-summary", out("s.json"), "-markdown", out("s.md"), "-alert", out("b.txt")}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, want 0; stdout %s", code, stdout.String())
	}
	if _, err := os.Stat(out("b.txt")); !os.IsNotExist(err) {
		t.Errorf("a passing run wrote an alert (stat err %v)", err)
	}
}

func TestRunUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, args := range [][]string{nil, {"nope"}, {"check"}, {"check", "-results", "x", "-targets", "/nonexistent/targets.json"}} {
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("run(%q) = %d, want 2", args, code)
		}
	}
}

// TestShippedTargets keeps floor/targets.json valid: the workflow's build job reads it with the
// same parser and fails the run on an invalid file.
func TestShippedTargets(t *testing.T) {
	tg, err := loadTargets(filepath.Join("..", "..", "floor", "targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if tg.Policy == unboundedPolicy {
		t.Fatalf("shipped policy is %q", tg.Policy)
	}
}
