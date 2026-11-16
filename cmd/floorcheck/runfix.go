package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// Files a run writes into its observation directory.
const (
	fileResult      = "result.json"
	fileScanLog     = "scan.log"
	fileSummaryJSON = "summary.json"
	fileSummaryMD   = "summary.md"
	// RunSummarySchema names a run's summary.json.
	RunSummarySchema = "ferralon.floor-run-summary.v1"
)

// parseInterspersed parses flags that may follow positional arguments, as in
// `run gitea traefik --out DIR`, returning the positionals in order.
func parseInterspersed(flags *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := flags.Parse(args); err != nil {
			return nil, err
		}
		rest := flags.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		if rest[0] == "--" {
			return append(pos, rest[1:]...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// hasReportFlag reports whether a check invocation uses the fixture contract (--report) rather than
// the targets contract (-results).
func hasReportFlag(args []string) bool {
	return slices.ContainsFunc(args, func(a string) bool {
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		return strings.HasPrefix(a, "-") && name == "report"
	})
}

// runCheckFixture implements `floorcheck check --report report.json [--prior report.json] <fixture>`:
// compare an existing report with a fixture's expectations, no scan.
func runCheckFixture(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	reportPath := flags.String("report", "", "the report.json to compare (required)")
	priorPath := flags.String("prior", "", "an earlier report.json the unexpected findings are diffed against")
	outPath := flags.String("out", "", "write the result JSON here instead of stdout")
	floorRoot := flags.String("floor-root", "", "the floor directory shared intel resolves under (default: the fixture's grandparent)")
	pos, err := parseInterspersed(flags, args)
	if err != nil {
		return 2
	}
	if *reportPath == "" || len(pos) != 1 {
		fmt.Fprintln(stderr, "usage: floorcheck check --report report.json [--prior report.json] [--out FILE] <fixture-dir>")
		return 2
	}
	dir, err := filepath.Abs(pos[0])
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	root := *floorRoot
	if root == "" {
		root = filepath.Dir(filepath.Dir(dir))
	}
	var prior *report.Report
	if *priorPath != "" {
		p, err := readReportFile(*priorPath)
		if err != nil {
			fmt.Fprintln(stderr, "floorcheck: --prior:", err)
			return 2
		}
		prior = &p
	}
	var res FixtureResult
	fx, err := loadFixture(dir, root, defaultRules)
	if err != nil {
		res = incompleteResult(filepath.Base(dir), nil, []Failure{{Kind: loadKind(err), Detail: err.Error()}})
	} else {
		obs := observation{}
		obs.report, err = os.ReadFile(*reportPath)
		switch {
		case err == nil:
			obs.hasReport = true
		case !errors.Is(err, fs.ErrNotExist):
			fmt.Fprintln(stderr, "floorcheck:", err)
			return 2
		}
		res = compareFixture(fx, obs, prior, *priorPath, defaultRules)
	}
	js, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	js = append(js, '\n')
	if *outPath != "" {
		err = os.WriteFile(*outPath, js, 0o644)
	} else {
		_, err = stdout.Write(js)
	}
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	writeResultText(stderr, res)
	return res.exit()
}

func readReportFile(path string) (report.Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return report.Report{}, err
	}
	return decodeReport(data)
}

// writeResultText is the human summary of one fixture.
func writeResultText(w io.Writer, r FixtureResult) {
	fmt.Fprintf(w, "%s: %s\n", r.Fixture, r.Outcome)
	for _, f := range r.Incomplete {
		fmt.Fprintf(w, "  incomplete: %s: %s\n", f.Kind, f.Detail)
	}
	for _, e := range r.Expectations {
		if e.Outcome == OutcomeIncomplete && len(r.Incomplete) > 0 && e.Reason == "" {
			continue
		}
		line := fmt.Sprintf("  %s %s %s (truth %s, floor %s)", e.Outcome, e.Advisory, e.Package, e.Truth, e.Floor)
		if e.Compared != nil {
			line += ": observed " + string(e.Compared.Verdict)
			if e.Compared.Basis != "" {
				line += "/" + string(e.Compared.Basis)
			}
		}
		if e.Reason != "" {
			line += " [" + e.Reason + "]"
		}
		if e.StaleReview {
			line += " [stale review: path_sha " + e.ReviewPathSHA + " no longer matches]"
		}
		fmt.Fprintln(w, line)
	}
	if r.DriftBase != "" {
		fmt.Fprintf(w, "  drift vs %s: %d changes among %d unexpected findings\n", r.DriftBase, len(r.Drift), r.Unexpected)
	} else {
		fmt.Fprintf(w, "  %d unexpected findings (no prior observation)\n", r.Unexpected)
	}
}

// fixtureNames is every fixture directory (one holding scenario.yaml) under root, sorted.
func fixtureNames(root string) ([]string, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, e.Name(), fileScenario)); err == nil {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// ListEntry is one fixture in `floorcheck list`: what the CI matrix needs to set the job up. Every
// key is always present; a toolchain the fixture's lane does not use is "".
type ListEntry struct {
	Name   string `json:"name"`
	Lang   string `json:"lang"`
	Go     string `json:"go"`
	JDK    string `json:"jdk"`
	Node   string `json:"node"`
	Python string `json:"python"`
}

// runList implements `floorcheck list`: every fixture's name, lang and toolchain pins as a JSON array,
// for the CI matrix. It reads and validates each scenario.yaml, and fails on any it cannot.
func runList(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("fixtures-root", "floor/fixtures", "the fixtures directory")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	names, err := fixtureNames(*root)
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	entries := []ListEntry{}
	for _, n := range names {
		var sc Scenario
		if err := decodeStrict(filepath.Join(*root, n, fileScenario), &sc); err != nil {
			fmt.Fprintf(stderr, "floorcheck: %s: %v\n", n, err)
			return 2
		}
		if err := sc.validate(); err != nil {
			fmt.Fprintf(stderr, "floorcheck: %s: %s: %v\n", n, fileScenario, err)
			return 2
		}
		b := sc.Build
		entries = append(entries, ListEntry{Name: n, Lang: sc.Lang, Go: b.Go, JDK: b.JDK, Node: b.Node, Python: b.Python})
	}
	js, _ := json.Marshal(entries)
	fmt.Fprintln(stdout, string(js))
	return 0
}

// runValidate implements `floorcheck validate [fixture…]`: load every fixture and verify every intel
// digest, without checking out or scanning anything. It exits 2 if any fixture fails to load.
func runValidate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("fixtures-root", "floor/fixtures", "the fixtures directory")
	floorRoot := flags.String("floor-root", "", "the floor directory shared intel resolves under (default: the parent of -fixtures-root)")
	names, err := parseInterspersed(flags, args)
	if err != nil {
		return 2
	}
	if *floorRoot == "" {
		*floorRoot = filepath.Dir(filepath.Clean(*root))
	}
	if len(names) == 0 {
		if names, err = fixtureNames(*root); err != nil {
			fmt.Fprintln(stderr, "floorcheck:", err)
			return 2
		}
	}
	if err := checkFixtureNames(names, *root); err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	failed := 0
	for _, n := range names {
		if _, err := loadFixture(filepath.Join(*root, n), *floorRoot, defaultRules); err != nil {
			failed++
			fmt.Fprintf(stdout, "%s: %s: %v\n", n, loadKind(err), err)
			continue
		}
		fmt.Fprintf(stdout, "%s: ok\n", n)
	}
	fmt.Fprintf(stdout, "validate: %d of %d fixtures load\n", len(names)-failed, len(names))
	if failed > 0 {
		return 2
	}
	return 0
}

// checkFixtureNames refuses a fixture argument that is not a single directory name.
func checkFixtureNames(names []string, root string) error {
	for _, n := range names {
		if !filepath.IsLocal(n) || strings.ContainsAny(n, `/\`) {
			return fmt.Errorf("fixture %q is not a name under %s", n, root)
		}
	}
	return nil
}

// runDiff implements `floorcheck diff OLD NEW`: every verdict, basis or path change between two
// observation directories. Informational: it fails only on unreadable inputs.
func runDiff(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("diff", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print the changes as JSON")
	pos, err := parseInterspersed(flags, args)
	if err != nil {
		return 2
	}
	if len(pos) != 2 {
		fmt.Fprintln(stderr, "usage: floorcheck diff [--json] OLD NEW")
		return 2
	}
	ds, err := diffDirs(pos[0], pos[1])
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	if *asJSON {
		if ds == nil {
			ds = []FixtureDiff{}
		}
		js, _ := json.MarshalIndent(ds, "", "  ")
		fmt.Fprintln(stdout, string(js))
		return 0
	}
	writeDiffText(stdout, ds)
	return 0
}

// scanRunner checks out a subject and runs the scanner; tests replace it so they never scan.
type scanRunner interface {
	checkout(ctx context.Context, repo, commit, dir string) error
	scan(ctx context.Context, req scanRequest) (exitCode int, err error)
}

// scanRequest is one scanner invocation.
type scanRequest struct {
	Scanner string
	Args    []string
	Env     []string
	// OutDir is the scan's -out directory; the scanner's output goes to Log.
	OutDir string
	Log    io.Writer
}

// runOptions is a parsed `run`.
type runOptions struct {
	fixtures    []string
	fixtureRoot string
	floorRoot   string
	out         string
	scanner     string
	prior       string
	work        string
	scanTimeout string
}

// runRun implements `floorcheck run [fixture…] --out DIR`.
func runRun(args []string, stdout, stderr io.Writer) int {
	return runFixtures(context.Background(), args, execRunner{}, stdout, stderr)
}

func runFixtures(ctx context.Context, args []string, sr scanRunner, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var o runOptions
	flags.StringVar(&o.out, "out", "", "the observation directory to write (required)")
	flags.StringVar(&o.fixtureRoot, "fixtures-root", "floor/fixtures", "the fixtures directory")
	flags.StringVar(&o.floorRoot, "floor-root", "", "the floor directory shared intel resolves under (default: the parent of -fixtures-root)")
	flags.StringVar(&o.scanner, "scanner", "ferralon-assay", "the scanner binary; its directory goes first on PATH for the analyzers")
	flags.StringVar(&o.prior, "prior", "", "an earlier observation directory the unexpected findings are diffed against")
	flags.StringVar(&o.work, "work", "", "where subject checkouts live and are reused (default: a temporary directory, removed afterwards)")
	flags.StringVar(&o.scanTimeout, "scan-timeout", "22m", "the scanner's own time limit")
	pos, err := parseInterspersed(flags, args)
	if err != nil {
		return 2
	}
	if o.out == "" {
		fmt.Fprintln(stderr, "usage: floorcheck run [fixture…] --out DIR [--fixtures-root DIR] [--floor-root DIR] [--scanner PATH] [--prior DIR] [--work DIR]")
		return 2
	}
	if o.floorRoot == "" {
		o.floorRoot = filepath.Dir(filepath.Clean(o.fixtureRoot))
	}
	o.fixtures = pos
	if len(o.fixtures) == 0 {
		if o.fixtures, err = fixtureNames(o.fixtureRoot); err != nil {
			fmt.Fprintln(stderr, "floorcheck:", err)
			return 2
		}
	}
	if err := checkFixtureNames(o.fixtures, o.fixtureRoot); err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	if err := prepareOut(o); err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	if o.scanner, err = resolveScanner(o.scanner); err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	if o.work == "" {
		tmp, err := os.MkdirTemp("", "floorcheck-work-")
		if err != nil {
			fmt.Fprintln(stderr, "floorcheck:", err)
			return 2
		}
		defer os.RemoveAll(tmp)
		o.work = tmp
	}
	var results []FixtureResult
	for _, name := range o.fixtures {
		res, err := runOne(ctx, o, name, sr)
		if err != nil {
			// The observation is lost, not the outcome: a regression already judged still fails the run.
			fmt.Fprintln(stderr, "floorcheck:", err)
			if res.Fixture == "" {
				res = incompleteResult(name, nil, nil)
			}
			res.Incomplete = append(res.Incomplete, Failure{Kind: KindObservationFailed, Detail: err.Error()})
			if res.Outcome != OutcomeRegressed {
				res.Outcome = OutcomeIncomplete
			}
		}
		writeResultText(stderr, res)
		results = append(results, res)
	}
	code := aggregateExit(results)
	if err := writeSummary(o.out, results); err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		if code == 0 {
			code = 2
		}
	}
	fmt.Fprintf(stdout, "floor: %s — %d fixtures\n", map[int]string{0: "PASS", 1: "REGRESSED", 2: "INCOMPLETE"}[code], len(results))
	return code
}

func resolveScanner(s string) (string, error) {
	p, err := exec.LookPath(s)
	if err != nil {
		return "", fmt.Errorf("scanner %s: %w", s, err)
	}
	return filepath.Abs(p)
}

// prepareOut makes the observation directory ready for this run without mixing in an earlier one: it
// refuses --prior as --out, removes the run's own summary files, and refuses any selected fixture's
// directory that already holds files, since the scanner writes more there than the harness can name.
func prepareOut(o runOptions) error {
	out, err := filepath.Abs(o.out)
	if err != nil {
		return err
	}
	if o.prior != "" {
		prior, err := filepath.Abs(o.prior)
		if err != nil {
			return err
		}
		if prior == out {
			return errors.New("--prior and --out are the same directory; the run would overwrite what it diffs against")
		}
	}
	for _, n := range o.fixtures {
		ents, err := os.ReadDir(filepath.Join(out, n))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if len(ents) > 0 {
			return fmt.Errorf("%s already holds an observation; give --out a fresh directory", filepath.Join(out, n))
		}
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for _, f := range []string{fileSummaryJSON, fileSummaryMD} {
		if err := os.Remove(filepath.Join(out, f)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// runOne loads, checks out, scans and compares one fixture, writing its report.json and result.json.
// The returned error is a failure to write the observation, not a fixture outcome; the result
// returned with it is the comparison, when one was made.
func runOne(ctx context.Context, o runOptions, name string, sr scanRunner) (FixtureResult, error) {
	outDir, err := filepath.Abs(filepath.Join(o.out, name))
	if err != nil {
		return FixtureResult{}, err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return FixtureResult{}, err
	}
	res := func() FixtureResult {
		fx, err := loadFixture(filepath.Join(o.fixtureRoot, name), o.floorRoot, defaultRules)
		if err != nil {
			return incompleteResult(name, nil, []Failure{{Kind: loadKind(err), Detail: err.Error()}})
		}
		target := filepath.Join(o.work, name)
		if err := sr.checkout(ctx, fx.Scenario.Repo, fx.Scenario.Commit, target); err != nil {
			return incompleteResult(name, &fx, []Failure{{Kind: KindCheckoutFailed, Detail: err.Error()}})
		}
		log, err := os.Create(filepath.Join(outDir, fileScanLog))
		if err != nil {
			return incompleteResult(name, &fx, []Failure{{Kind: KindScanFailed, Detail: err.Error()}})
		}
		defer log.Close()
		req := scanRequest{Scanner: o.scanner, Args: scanArgs(fx, target, outDir, o.scanTimeout),
			Env: scanEnv(os.Environ(), fx.Scenario.Build, filepath.Dir(o.scanner)), OutDir: outDir, Log: log}
		var obs observation
		switch code, err := sr.scan(ctx, req); {
		case err != nil:
			obs.scanFailed = "the scanner did not run: " + err.Error()
		case code != 0:
			obs.scanFailed = fmt.Sprintf("the scanner exited %d", code)
		}
		if data, err := os.ReadFile(filepath.Join(outDir, fileReport)); err == nil {
			obs.report, obs.hasReport = data, true
		}
		var prior *report.Report
		priorName := ""
		if o.prior != "" {
			if p, err := readObservedReport(filepath.Join(o.prior, name)); err == nil {
				prior, priorName = &p, filepath.Join(o.prior, name, fileReport)
			}
		}
		return compareFixture(fx, obs, prior, priorName, defaultRules)
	}()
	js, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return res, err
	}
	return res, os.WriteFile(filepath.Join(outDir, fileResult), append(js, '\n'), 0o644)
}

// scanArgs is the scanner's command line for a fixture: the flags floor/scan.sh passes, from the
// scenario, then the scenario's own scan.flags.
func scanArgs(fx Fixture, target, outDir, timeout string) []string {
	repo, _ := subjectRepo(fx.Scenario.Repo)
	args := []string{
		"baseline",
		"-target", target,
		"-out", outDir,
		"-subject-repo", repo,
		"-revision", fx.Scenario.Commit,
		"-commit", fx.Scenario.Commit,
		"-advisory-corpus", fx.CorpusPath,
		"-advisory-corpus-policy", fx.Scenario.Intel.Policy,
	}
	if fx.SignalsPath != "" {
		args = append(args, "-advisory-signals", fx.SignalsPath)
	}
	args = append(args, "-require-advisory-corpus", "-scan-timeout", timeout)
	return append(args, fx.Scenario.Scan.Flags...)
}

// scanEnvAllowed is the caller's environment a scan inherits: where things live (home, temp, caches,
// toolchains) and how to reach module and package proxies. Nothing that steers a verdict passes (no
// ASSAY_*, FERRALON_*, GOFLAGS, GOWORK, GOEXPERIMENT, GODEBUG or toolchain pin), and no credential.
var scanEnvAllowed = []string{
	"PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "SHELL", "TZ", "LANG",
	"GOPATH", "GOMODCACHE", "GOCACHE", "GOPROXY", "GONOSUMDB", "GOPRIVATE", "GONOPROXY", "GOSUMDB",
	"JAVA_HOME", "MAVEN_HOME", "M2_HOME", "MAVEN_OPTS", "GRADLE_HOME", "GRADLE_USER_HOME", "GRADLE_OPTS",
	"NVM_DIR", "PYENV_ROOT",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// scanEnv is the scanner's environment: an allow-listed slice of the caller's, the scanner's GitHub
// surfaces off, Go's own overrides cleared, and the scenario's build pinned.
func scanEnv(base []string, b ScenarioBuild, scannerDir string) []string {
	var env []string
	path := ""
	for _, kv := range base {
		k, v, _ := strings.Cut(kv, "=")
		switch {
		case k == "PATH":
			path = v
		case slices.Contains(scanEnvAllowed, k), strings.HasPrefix(k, "LC_"):
			env = append(env, kv)
		}
	}
	env = append(env, "PATH="+scannerDir+string(os.PathListSeparator)+path, "GOFLAGS=", "GOWORK=off",
		"ASSAY_ISSUE=0", "ASSAY_PR_COMMENT=0", "ASSAY_CODE_SCANNING=0")
	if b.Go != "" {
		env = append(env, "GOTOOLCHAIN=go"+b.Go)
	}
	if b.GOOS != "" {
		env = append(env, "GOOS="+b.GOOS)
	}
	if b.GOARCH != "" {
		env = append(env, "GOARCH="+b.GOARCH)
	}
	if b.CGO != nil {
		env = append(env, "CGO_ENABLED="+map[bool]string{false: "0", true: "1"}[*b.CGO])
	}
	return env
}

// execRunner is the real checkout and scan.
type execRunner struct{}

// checkout leaves dir at commit, detached: it fetches only that commit, and reuses a clean checkout
// already there. A checkout with local changes is refused rather than overwritten.
func (execRunner) checkout(ctx context.Context, repo, commit, dir string) error {
	if !fullCommit.MatchString(commit) {
		return fmt.Errorf("commit %q is not a full 40-hex commit", commit)
	}
	git := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		if err != nil {
			return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(out.String()))
		}
		return strings.TrimSpace(out.String()), nil
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		if st, err := git("status", "--porcelain"); err != nil {
			return err
		} else if st != "" {
			return fmt.Errorf("%s has local changes; refusing to reuse it", dir)
		}
		if head, err := git("rev-parse", "HEAD"); err == nil && head == commit {
			return nil
		}
	} else {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if _, err := git("init", "-q"); err != nil {
			return err
		}
	}
	if _, err := git("fetch", "-q", "--depth", "1", "--", repo, commit); err != nil {
		return err
	}
	if _, err := git("checkout", "-q", "--detach", commit, "--"); err != nil {
		return err
	}
	head, err := git("rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if head != commit {
		return fmt.Errorf("checkout is at %s, want %s", head, commit)
	}
	return nil
}

func (execRunner) scan(ctx context.Context, req scanRequest) (int, error) {
	cmd := exec.CommandContext(ctx, req.Scanner, req.Args...)
	cmd.Env = req.Env
	cmd.Stdout, cmd.Stderr = req.Log, req.Log
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 0, err
	}
	return 0, nil
}

// RunSummary is summary.json: every fixture's outcome, and the lines a person acts on.
type RunSummary struct {
	Schema   string           `json:"schema"`
	Exit     int              `json:"exit"`
	Fixtures []FixtureSummary `json:"fixtures"`
}

// FixtureSummary is one fixture's line of the summary.
type FixtureSummary struct {
	Fixture    string   `json:"fixture"`
	Outcome    string   `json:"outcome"`
	Counts     Counts   `json:"counts"`
	Regressed  []string `json:"regressed,omitempty"`
	Improved   []string `json:"improved,omitempty"`
	Stale      []string `json:"stale_review,omitempty"`
	Incomplete []string `json:"incomplete,omitempty"`
	Unexpected int      `json:"unexpected"`
	Drift      int      `json:"drift"`
}

// Counts is how many expectations reached each outcome.
type Counts struct {
	Regressed  int `json:"regressed"`
	Met        int `json:"met"`
	Improved   int `json:"improved"`
	Incomplete int `json:"incomplete"`
}

func summarizeRun(results []FixtureResult) RunSummary {
	s := RunSummary{Schema: RunSummarySchema, Exit: aggregateExit(results), Fixtures: []FixtureSummary{}}
	for _, r := range results {
		sum := FixtureSummary{Fixture: r.Fixture, Outcome: r.Outcome, Unexpected: r.Unexpected, Drift: len(r.Drift)}
		for _, f := range r.Incomplete {
			sum.Incomplete = append(sum.Incomplete, f.Kind+": "+f.Detail)
		}
		for _, e := range r.Expectations {
			label := e.Advisory + " " + e.Package
			observed := ""
			if e.Compared != nil {
				observed = " observed " + string(e.Compared.Verdict)
			}
			switch e.Outcome {
			case OutcomeRegressed:
				sum.Counts.Regressed++
				sum.Regressed = append(sum.Regressed, fmt.Sprintf("%s: floor %s,%s [%s]", label, e.Floor, observed, e.Reason))
			case OutcomeMet:
				sum.Counts.Met++
			case OutcomeImproved:
				sum.Counts.Improved++
				sum.Improved = append(sum.Improved, fmt.Sprintf("%s: floor %s,%s", label, e.Floor, observed))
			case OutcomeIncomplete:
				sum.Counts.Incomplete++
			}
			if e.StaleReview {
				sum.Stale = append(sum.Stale, label+": review path_sha "+e.ReviewPathSHA+", observed "+cmpOr(e.Compared))
			}
		}
		s.Fixtures = append(s.Fixtures, sum)
	}
	return s
}

func cmpOr(o *Observed) string {
	if o == nil || o.PathSHA == "" {
		return "no path"
	}
	return o.PathSHA
}

func (s RunSummary) markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Floor run: %s\n\n", map[int]string{0: "pass", 1: "regressed", 2: "incomplete"}[s.Exit])
	b.WriteString("| Fixture | Outcome | Regressed | Met | Improved | Incomplete | Unexpected | Drift |\n|---|---|---|---|---|---|---|---|\n")
	for _, f := range s.Fixtures {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d | %d | %d |\n", f.Fixture, f.Outcome, f.Counts.Regressed,
			f.Counts.Met, f.Counts.Improved, f.Counts.Incomplete, f.Unexpected, f.Drift)
	}
	section := func(title string, pick func(FixtureSummary) []string) {
		var lines []string
		for _, f := range s.Fixtures {
			for _, l := range pick(f) {
				lines = append(lines, "- "+f.Fixture+": "+l)
			}
		}
		if len(lines) > 0 {
			fmt.Fprintf(&b, "\n## %s\n\n%s\n", title, strings.Join(lines, "\n"))
		}
	}
	section("Regressed", func(f FixtureSummary) []string { return f.Regressed })
	section("Incomplete", func(f FixtureSummary) []string { return f.Incomplete })
	section("Improved (tighten the floor by hand)", func(f FixtureSummary) []string { return f.Improved })
	section("Stale reviews", func(f FixtureSummary) []string { return f.Stale })
	return b.String()
}

func writeSummary(out string, results []FixtureResult) error {
	s := summarizeRun(results)
	js, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFiles(map[string][]byte{
		filepath.Join(out, fileSummaryJSON): append(js, '\n'),
		filepath.Join(out, fileSummaryMD):   []byte(s.markdown()),
	})
}
