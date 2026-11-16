package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// fakeRunner stands in for git and the scanner: each fixture's scan writes the report given for its
// output directory's name and exits with the given code.
type fakeRunner struct {
	reports     map[string][]byte
	codes       map[string]int
	checkoutErr map[string]error
	// afterScan runs in a fixture's output directory once its scan is done.
	afterScan map[string]func(outDir string)
	requests  []scanRequest
	checkouts []string
}

func (r *fakeRunner) checkout(_ context.Context, repo, commit, dir string) error {
	r.checkouts = append(r.checkouts, repo+"@"+commit+" -> "+filepath.Base(dir))
	return r.checkoutErr[filepath.Base(dir)]
}

func (r *fakeRunner) scan(_ context.Context, req scanRequest) (int, error) {
	r.requests = append(r.requests, req)
	name := filepath.Base(req.OutDir)
	if data, ok := r.reports[name]; ok {
		if err := os.WriteFile(filepath.Join(req.OutDir, fileReport), data, 0o644); err != nil {
			return 0, err
		}
	}
	if f := r.afterScan[name]; f != nil {
		f(req.OutDir)
	}
	return r.codes[name], nil
}

func fakeScanner(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ferralon-assay")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func argValue(args []string, flag string) string {
	if i := slices.Index(args, flag); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, _ := strings.Cut(kv, "="); k == key {
			return v, true
		}
	}
	return "", false
}

func TestRunFixtures(t *testing.T) {
	leaked := map[string]string{"GITHUB_TOKEN": "secret", "GH_TOKEN": "secret", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "secret",
		"ASSAY_OSV_WORK_SET": "1", "ASSAY_ADVISORY_SIGNALS": "/x", "FERRALON_LINK_TO_CONSOLE": "1", "GOEXPERIMENT": "x", "GOTOOLCHAIN": "local"}
	for k, v := range leaked {
		t.Setenv(k, v)
	}
	t.Setenv("GOFLAGS", "-mod=mod")
	t.Setenv("GOWORK", "/elsewhere/go.work")
	t.Setenv("GOMODCACHE", "/cache/mod")
	f := newTestFloor(t)
	f.fixture(t, "met", scenarioYAML(sharedIntel())+"scan:\n  flags: [\"-language\", \"go\"]\n", expectYAML)
	f.fixture(t, "regressed", scenarioYAML(sharedIntel()), strings.Replace(strings.Replace(expectYAML,
		"truth: reachable", "truth: unreachable", 1), "floor: reachable_candidate", "floor: not_exploitable", 1))
	f.fixture(t, "failed", scenarioYAML(sharedIntel()), expectYAML)
	f.fixture(t, "unverified", scenarioYAML(strings.Replace(sharedIntel(), sha("corpus"), sha("tampered"), 1)), expectYAML)
	write(t, f.fixtures, "not-a-fixture/README", "x")
	rep := floorReport(t, []report.AdvisoryFinding{fv("GO-1", rc)})
	fr := &fakeRunner{reports: map[string][]byte{"met": rep, "regressed": rep, "failed": rep}, codes: map[string]int{"failed": 3}}
	out := t.TempDir()
	scanner := fakeScanner(t)
	var stdout, stderr bytes.Buffer
	code := runFixtures(context.Background(), []string{"--out", out, "--fixtures-root", f.fixtures, "--scanner", scanner,
		"--work", t.TempDir()}, fr, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit %d, want 1 (a regression, beside incomplete fixtures)\n%s", code, stderr.String())
	}
	if len(fr.requests) != 3 {
		t.Fatalf("%d scans, want 3: an unverified fixture is never scanned", len(fr.requests))
	}

	req := fr.requests[slices.IndexFunc(fr.requests, func(r scanRequest) bool { return filepath.Base(r.OutDir) == "met" })]
	realRoot, _ := filepath.EvalSymlinks(f.root)
	for flag, want := range map[string]string{
		"-subject-repo":           "o/r",
		"-revision":               testCommit,
		"-commit":                 testCommit,
		"-advisory-corpus":        filepath.Join(realRoot, testCorpusRel),
		"-advisory-signals":       filepath.Join(realRoot, "intel/corpus-test/signals.json.gz"),
		"-advisory-corpus-policy": "full",
		"-scan-timeout":           "22m",
		"-out":                    filepath.Join(out, "met"),
	} {
		if got := argValue(req.Args, flag); got != want {
			t.Errorf("%s %q, want %q", flag, got, want)
		}
	}
	if req.Args[0] != "baseline" || !slices.Contains(req.Args, "-require-advisory-corpus") ||
		!slices.Equal(req.Args[len(req.Args)-2:], []string{"-language", "go"}) {
		t.Errorf("args %q: want baseline, -require-advisory-corpus, and scan.flags last", req.Args)
	}
	for key, want := range map[string]string{"GOTOOLCHAIN": "go1.23.12", "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0",
		"ASSAY_ISSUE": "0", "ASSAY_PR_COMMENT": "0", "ASSAY_CODE_SCANNING": "0", "GOFLAGS": "", "GOWORK": "off", "GOMODCACHE": "/cache/mod"} {
		if got, ok := envValue(req.Env, key); !ok || got != want {
			t.Errorf("env %s=%q (set %v), want %q", key, got, ok, want)
		}
	}
	for k := range leaked {
		if v, ok := envValue(req.Env, k); ok && !(k == "GOTOOLCHAIN" && v == "go1.23.12") {
			t.Errorf("the scanner inherits %s=%s", k, v)
		}
	}
	for _, kv := range req.Env {
		if k, _, _ := strings.Cut(kv, "="); slices.Contains([]string{"GOFLAGS", "GOWORK"}, k) && kv != "GOFLAGS=" && kv != "GOWORK=off" {
			t.Errorf("the scanner inherits %s", kv)
		}
	}
	if p, _ := envValue(req.Env, "PATH"); !strings.HasPrefix(p, filepath.Dir(scanner)+string(os.PathListSeparator)) {
		t.Errorf("PATH %q does not lead with the scanner's directory", p)
	}

	outcomes := map[string]string{}
	for _, name := range []string{"met", "regressed", "failed", "unverified"} {
		data, err := os.ReadFile(filepath.Join(out, name, fileResult))
		if err != nil {
			t.Fatal(err)
		}
		var r FixtureResult
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		outcomes[name] = r.Outcome + " " + strings.Join(kinds(r.Incomplete), ",")
	}
	want := map[string]string{"met": "pass ", "regressed": "regressed ", "failed": "incomplete scan_failed", "unverified": "incomplete intel_unverified"}
	for k, v := range want {
		if outcomes[k] != v {
			t.Errorf("%s: %q, want %q", k, outcomes[k], v)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "met", fileReport)); err != nil {
		t.Errorf("report.json not kept: %v", err)
	}
	var sum RunSummary
	data, err := os.ReadFile(filepath.Join(out, fileSummaryJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Exit != 1 || len(sum.Fixtures) != 4 {
		t.Errorf("summary exit %d over %d fixtures", sum.Exit, len(sum.Fixtures))
	}
	md, err := os.ReadFile(filepath.Join(out, fileSummaryMD))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"# Floor run: regressed", "## Regressed", "regressed: GO-1 m@v1: floor not_exploitable, observed reachable_candidate [below_floor]", "## Incomplete", "intel_unverified"} {
		if !strings.Contains(string(md), s) {
			t.Errorf("summary.md lacks %q:\n%s", s, md)
		}
	}
}

// TestRunOutDirectory: a run never mixes into an earlier observation, and never overwrites the one it
// diffs against.
func TestRunOutDirectory(t *testing.T) {
	f := newTestFloor(t)
	f.fixture(t, "a", scenarioYAML(sharedIntel()), expectYAML)
	out := t.TempDir()
	write(t, out, fileSummaryMD, "stale")
	args := []string{"--out", out, "--fixtures-root", f.fixtures, "--scanner", fakeScanner(t)}
	var stdout, stderr bytes.Buffer
	if code := runFixtures(context.Background(), args, &fakeRunner{}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit %d, want 2 (no report)\n%s", code, stderr.String())
	}
	if md, _ := os.ReadFile(filepath.Join(out, fileSummaryMD)); strings.Contains(string(md), "stale") {
		t.Error("summary.md from an earlier run survived")
	}
	fr := &fakeRunner{}
	if code := runFixtures(context.Background(), args, fr, &stdout, &stderr); code != 2 || len(fr.requests) != 0 ||
		!strings.Contains(stderr.String(), "already holds an observation") {
		t.Errorf("reused --out: exit %d, %d scans, want 2 and none\n%s", code, len(fr.requests), stderr.String())
	}
	stderr.Reset()
	same := filepath.Join(t.TempDir(), "obs")
	if code := runFixtures(context.Background(), []string{"--out", same, "--prior", same + "/", "--fixtures-root", f.fixtures,
		"--scanner", fakeScanner(t)}, &fakeRunner{}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "same directory") {
		t.Errorf("--prior == --out: exit %d\n%s", code, stderr.String())
	}
}

// TestRunKeepsOutcomeOnWriteFailure: losing a fixture's result.json is incomplete, never a pass, and
// never hides a regression already judged.
func TestRunKeepsOutcomeOnWriteFailure(t *testing.T) {
	f := newTestFloor(t)
	f.fixture(t, "a", scenarioYAML(sharedIntel()), expectYAML)
	f.fixture(t, "b", scenarioYAML(sharedIntel()), strings.Replace(strings.Replace(expectYAML,
		"truth: reachable", "truth: unreachable", 1), "floor: reachable_candidate", "floor: not_exploitable", 1))
	rep := floorReport(t, []report.AdvisoryFinding{fv("GO-1", rc)})
	blockResult := func(outDir string) {
		if err := os.Mkdir(filepath.Join(outDir, fileResult), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name     string
		fixtures []string
		blocked  string
		want     int
	}{
		{"a passing fixture's result is lost", []string{"a"}, "a", 2},
		{"a regressed fixture's result is lost", []string{"b", "a"}, "b", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fr := &fakeRunner{reports: map[string][]byte{"a": rep, "b": rep}, afterScan: map[string]func(string){tc.blocked: blockResult}}
			out := t.TempDir()
			var stdout, stderr bytes.Buffer
			args := append([]string{"--out", out, "--fixtures-root", f.fixtures, "--scanner", fakeScanner(t)}, tc.fixtures...)
			code := runFixtures(context.Background(), args, fr, &stdout, &stderr)
			if code != tc.want || len(fr.requests) != len(tc.fixtures) {
				t.Fatalf("exit %d after %d scans, want %d after %d\n%s", code, len(fr.requests), tc.want, len(tc.fixtures), stderr.String())
			}
			data, err := os.ReadFile(filepath.Join(out, fileSummaryJSON))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), KindObservationFailed) {
				t.Errorf("summary does not name the lost observation:\n%s", data)
			}
		})
	}
}

func TestRunNamedFixturesAndPrior(t *testing.T) {
	f := newTestFloor(t)
	f.fixture(t, "a", scenarioYAML(sharedIntel()), expectYAML)
	f.fixture(t, "b", scenarioYAML(sharedIntel()), expectYAML)
	prior := t.TempDir()
	write(t, prior, "a/report.json", string(floorReport(t, []report.AdvisoryFinding{fv("GO-1", rc), fv("GO-2", und)})))
	fr := &fakeRunner{reports: map[string][]byte{"a": floorReport(t, []report.AdvisoryFinding{fv("GO-1", rc), fv("GO-2", rc)})}}
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := runFixtures(context.Background(), []string{"a", "--out", out, "--fixtures-root", f.fixtures, "--scanner", fakeScanner(t),
		"--prior", prior}, fr, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}
	if len(fr.requests) != 1 {
		t.Errorf("%d scans, want only the named fixture", len(fr.requests))
	}
	var r FixtureResult
	data, _ := os.ReadFile(filepath.Join(out, "a", fileResult))
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Drift) != 1 || r.Drift[0].Advisory != "GO-2" || r.Drift[0].Change != ChangeChanged {
		t.Errorf("drift %+v, want GO-2 changed", r.Drift)
	}

	fr = &fakeRunner{checkoutErr: map[string]error{"b": errors.New("no such commit")}}
	if code := runFixtures(context.Background(), []string{"b", "--out", t.TempDir(), "--fixtures-root", f.fixtures, "--scanner", fakeScanner(t)},
		fr, &stdout, &stderr); code != 2 {
		t.Errorf("checkout failure: exit %d, want 2", code)
	}
	for _, bad := range [][]string{{"--fixtures-root", f.fixtures}, {"../a", "--out", out, "--fixtures-root", f.fixtures, "--scanner", fakeScanner(t)}} {
		if code := runFixtures(context.Background(), bad, &fakeRunner{}, &stdout, &stderr); code != 2 {
			t.Errorf("%q: exit %d, want 2", bad, code)
		}
	}
}

func TestCheckVerbDispatch(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"--report", "r.json", "fx"}, true},
		{[]string{"-report=r.json", "fx"}, true},
		{[]string{"fx", "--report", "r.json"}, true},
		{[]string{"-targets", "t.json", "-results", "DIR"}, false},
		{[]string{"-reports", "x"}, false},
		{[]string{"report"}, false},
	} {
		if got := hasReportFlag(tc.args); got != tc.want {
			t.Errorf("hasReportFlag(%q) = %v, want %v", tc.args, got, tc.want)
		}
	}
	// The targets contract is still what `check` without --report runs.
	absent := filepath.Join(t.TempDir(), "absent-targets.json")
	for _, args := range [][]string{{"check"}, {"check", "-targets", absent, "-results", t.TempDir()}} {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != 2 || strings.Contains(stderr.String(), "--report") ||
			!(strings.Contains(stderr.String(), "-results is required") || strings.Contains(stderr.String(), "absent-targets.json")) {
			t.Errorf("%q: exit %d, stderr %q: want the targets contract's error", args, code, stderr.String())
		}
	}
}

// TestCheckoutRefusesOptionRepo: a repo argument that reads as a git option is a repository name to
// git, never an option, so the R1 reproducer runs nothing; a plain repository still checks out.
func TestCheckoutRefusesOptionRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	src := t.TempDir()
	gitRun := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=f@x", "-c", "user.name=f", "-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %q: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	gitRun(src, "init", "-q")
	gitRun(src, "commit", "-q", "--allow-empty", "-m", "x")
	commit := gitRun(src, "rev-parse", "HEAD")

	marker := filepath.Join(t.TempDir(), "MARKER")
	err := execRunner{}.checkout(context.Background(), "--upload-pack=touch "+marker+"; echo #://h/o/r", commit, filepath.Join(t.TempDir(), "w"))
	if err == nil {
		t.Error("checked out from an option")
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("git ran the repo argument as --upload-pack")
	}
	dst := filepath.Join(t.TempDir(), "w")
	if err := (execRunner{}).checkout(context.Background(), src, commit, dst); err != nil {
		t.Fatalf("plain checkout: %v", err)
	}
	if err := (execRunner{}).checkout(context.Background(), src, "-q", dst); err == nil {
		t.Error("checked out a commit that is not 40-hex")
	}
}

func TestCheckFixtureVerb(t *testing.T) {
	f := newTestFloor(t)
	dir := f.fixture(t, "fx", scenarioYAML(sharedIntel()), expectYAML)
	tmp := t.TempDir()
	write(t, tmp, "met.json", string(floorReport(t, []report.AdvisoryFinding{fv("GO-1", rc)})))
	write(t, tmp, "regressed.json", string(floorReport(t, []report.AdvisoryFinding{fv("GO-1", ne)})))
	write(t, tmp, "prior.json", string(floorReport(t, []report.AdvisoryFinding{fv("GO-1", und), fv("GO-2", und)})))
	for _, tc := range []struct {
		name    string
		args    []string
		exit    int
		outcome string
	}{
		{"met", []string{"check", "--report", filepath.Join(tmp, "met.json"), dir}, 0, OutcomePass},
		{"regressed", []string{"check", dir, "--report", filepath.Join(tmp, "regressed.json")}, 1, OutcomeRegressed},
		{"no report", []string{"check", "--report", filepath.Join(tmp, "absent.json"), dir}, 2, OutcomeIncomplete},
		{"with prior", []string{"check", "--report", filepath.Join(tmp, "met.json"), "--prior", filepath.Join(tmp, "prior.json"), dir}, 0, OutcomePass},
		{"explicit floor root", []string{"check", "--report", filepath.Join(tmp, "met.json"), "--floor-root", f.root, dir}, 0, OutcomePass},
		{"wrong floor root", []string{"check", "--report", filepath.Join(tmp, "met.json"), "--floor-root", tmp, dir}, 2, OutcomeIncomplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, &stdout, &stderr); code != tc.exit {
				t.Errorf("exit %d, want %d\n%s", code, tc.exit, stderr.String())
			}
			var r FixtureResult
			if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
				t.Fatalf("stdout is not a result: %v\n%s", err, stdout.String())
			}
			if r.Outcome != tc.outcome {
				t.Errorf("outcome %s, want %s", r.Outcome, tc.outcome)
			}
			if !strings.HasPrefix(stderr.String(), "fx: "+tc.outcome) {
				t.Errorf("stderr summary %q", stderr.String())
			}
		})
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"check", "--report", filepath.Join(tmp, "met.json"), "--prior", filepath.Join(tmp, "absent.json"), dir}, &stdout, &stderr); code != 2 {
		t.Errorf("unreadable --prior: exit %d, want 2", code)
	}
}

func TestListVerb(t *testing.T) {
	f := newTestFloor(t)
	f.fixture(t, "b", laneScenario("java", `  jdk: "17"`), "x")
	f.fixture(t, "a", scenarioYAML(sharedIntel()), "x")
	f.fixture(t, "c", laneScenario("python", `  python: "3.12"`), "x")
	write(t, f.fixtures, "d/notes.txt", "x")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"list", "--fixtures-root", f.fixtures}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	want := `[{"name":"a","lang":"go","go":"1.23.12","jdk":"","node":"","python":""},` +
		`{"name":"b","lang":"java","go":"","jdk":"17","node":"","python":""},` +
		`{"name":"c","lang":"python","go":"","jdk":"","node":"","python":"3.12"}]`
	if got := strings.TrimSpace(stdout.String()); got != want {
		t.Errorf("list =\n%s\nwant\n%s", got, want)
	}
	f.fixture(t, "e", strings.Replace(scenarioYAML(sharedIntel()), "1.23.12", "1.23", 1), "x")
	stdout.Reset()
	if code := run([]string{"list", "--fixtures-root", f.fixtures}, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
		t.Errorf("invalid scenario: exit %d, stdout %q; want 2 and no matrix", code, stdout.String())
	}
	stdout.Reset()
	if code := run([]string{"list", "--fixtures-root", t.TempDir()}, &stdout, &stderr); code != 0 || strings.TrimSpace(stdout.String()) != "[]" {
		t.Errorf("empty list: exit %d, %q", code, stdout.String())
	}
	if code := run([]string{"list", "--fixtures-root", filepath.Join(f.root, "absent")}, &stdout, &stderr); code != 2 {
		t.Errorf("missing root: exit %d, want 2", code)
	}
}

func TestValidateVerb(t *testing.T) {
	f := newTestFloor(t)
	f.fixture(t, "good", scenarioYAML(sharedIntel()), expectYAML)
	f.fixture(t, "tampered", scenarioYAML(strings.Replace(sharedIntel(), sha("corpus"), sha("tampered"), 1)), expectYAML)
	for _, tc := range []struct {
		args []string
		exit int
		want string
	}{
		{[]string{"validate", "--fixtures-root", f.fixtures}, 2, "good: ok\ntampered: intel_unverified: intel.corpus: "},
		{[]string{"validate", "good", "--fixtures-root", f.fixtures}, 0, "good: ok\nvalidate: 1 of 1 fixtures load\n"},
		{[]string{"validate", "--fixtures-root", f.fixtures, "--floor-root", t.TempDir(), "good"}, 2, "good: intel_unverified"},
		{[]string{"validate", "--fixtures-root", f.fixtures, "../good"}, 2, ""},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(tc.args, &stdout, &stderr); code != tc.exit || !strings.HasPrefix(stdout.String(), tc.want) {
			t.Errorf("%q: exit %d, stdout %q; want %d, %q", tc.args, code, stdout.String(), tc.exit, tc.want)
		}
	}
}

func TestDiffVerb(t *testing.T) {
	oldDir, newDir := t.TempDir(), t.TempDir()
	moved := rcFinding("GO-5", "a", "c")
	write(t, oldDir, "x/report.json", string(floorReport(t, []report.AdvisoryFinding{
		fv("GO-1", und), fv("GO-2", ne), rcFinding("GO-5", "a", "b"), fv("GO-6", ne), fv("GO-7", rc)})))
	write(t, newDir, "x/report.json", string(floorReport(t, []report.AdvisoryFinding{
		fv("GO-1", rc), moved, func() report.AdvisoryFinding {
			f := fv("GO-6", ne)
			f.Evidence.Basis = "vulnerable_symbol_absent"
			return f
		}(), fv("GO-7", rc), fv("GO-8", und)})))
	write(t, oldDir, "gone/report.json", string(floorReport(t, nil)))
	write(t, newDir, "broken/report.json", "{")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"diff", oldDir, newDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	want := strings.Join([]string{
		"== broken: not compared: no readable report on either side: old: no report.json; new: report.json does not decode: unexpected end of JSON input",
		"== gone: not compared: new: no report.json",
		"== x: 5 changes",
		"  changed GO-1 m@v1: undetermined/advisory_symbol_absent -> reachable_candidate",
		"  removed GO-2 m@v1: not_exploitable/vulnerable_symbol_unreachable -> -",
		"  changed GO-5 m@v1: reachable_candidate path " + pathSHA([]string{"a", "b"}) + " -> reachable_candidate path " + pathSHA([]string{"a", "c"}),
		"  changed GO-6 m@v1: not_exploitable/vulnerable_symbol_unreachable -> not_exploitable/vulnerable_symbol_absent",
		"  added GO-8 m@v1: - -> undetermined/advisory_symbol_absent",
	}, "\n") + "\n"
	if stdout.String() != want {
		t.Errorf("diff =\n%s\nwant\n%s", stdout.String(), want)
	}

	stdout.Reset()
	if code := run([]string{"diff", "--json", oldDir, newDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("--json exit %d", code)
	}
	var ds []FixtureDiff
	if err := json.Unmarshal(stdout.Bytes(), &ds); err != nil || len(ds) != 3 || len(ds[2].Changes) != 5 {
		t.Errorf("--json: %v, %+v", err, ds)
	}
	for _, args := range [][]string{{"diff", oldDir, filepath.Join(newDir, "absent")}, {"diff", oldDir}} {
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
}

func TestScanEnvPathWithoutInheritedPath(t *testing.T) {
	for _, base := range [][]string{nil, {"PATH="}} {
		p, _ := envValue(scanEnv(base, ScenarioBuild{}, "/scanner"), "PATH")
		if p != "/scanner" {
			t.Errorf("base %q: PATH %q, want only the scanner directory (an empty entry puts the working directory on PATH)", base, p)
		}
	}
}
