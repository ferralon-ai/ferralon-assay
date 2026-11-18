package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// workflow is the part of .github/workflows/floor.yml the floor run's contract rests on.
type workflow struct {
	On   map[string]yaml.Node `yaml:"on"`
	Jobs map[string]struct {
		If             string `yaml:"if"`
		Needs          any    `yaml:"needs"`
		TimeoutMinutes int    `yaml:"timeout-minutes"`
		Strategy       struct {
			FailFast    *bool  `yaml:"fail-fast"`
			MaxParallel int    `yaml:"max-parallel"`
			Matrix      string `yaml:"matrix"`
		} `yaml:"strategy"`
		Steps []struct {
			Uses string            `yaml:"uses"`
			If   string            `yaml:"if"`
			Run  string            `yaml:"run"`
			Env  map[string]string `yaml:"env"`
			With map[string]string `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func readWorkflow(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "floor.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestFloorWorkflow pins what the floor run promises: it runs only by hand, over a fixture selector;
// every selected fixture's pins are verified before any scan; the fixtures fan out in one bounded
// matrix that never stops on a sibling's failure; observations are uploaded whatever happened; and
// the run reads no secrets and reports nowhere but the run itself.
func TestFloorWorkflow(t *testing.T) {
	data := readWorkflow(t)
	var w workflow
	if err := yaml.Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}

	if len(w.On) != 2 {
		t.Errorf("triggers = %d, want only schedule and workflow_dispatch", len(w.On))
	}
	var schedule []struct {
		Cron string `yaml:"cron"`
	}
	if node, ok := w.On["schedule"]; !ok {
		t.Error("no schedule trigger: the floor runs every fixture nightly")
	} else if err := node.Decode(&schedule); err != nil || len(schedule) != 1 || !regexp.MustCompile(`^\S+ \S+ \* \* \*$`).MatchString(schedule[0].Cron) {
		t.Errorf("schedule %+v (%v): want one daily cron", schedule, err)
	}
	var dispatch struct {
		Inputs map[string]struct {
			Default string `yaml:"default"`
		} `yaml:"inputs"`
	}
	node, ok := w.On["workflow_dispatch"]
	if !ok {
		t.Fatal("no workflow_dispatch trigger")
	}
	if err := node.Decode(&dispatch); err != nil {
		t.Fatal(err)
	}
	if in, ok := dispatch.Inputs["fixtures"]; !ok || in.Default != "" {
		t.Errorf("want a fixtures selector input that defaults to every fixture, got %+v (present %v)", in, ok)
	}

	if strings.Contains(string(data), "secrets.") {
		t.Error("the floor run reads a secret; it scans public repositories with pinned, committed intel")
	}

	steps := func(job string) string {
		j, ok := w.Jobs[job]
		if !ok {
			t.Fatalf("no job %q", job)
		}
		var b strings.Builder
		for _, s := range j.Steps {
			b.WriteString(s.Uses + "\n" + s.If + "\n" + s.Run + "\n")
			for k, v := range s.With {
				b.WriteString(k + ": " + v + "\n")
			}
			for k, v := range s.Env {
				b.WriteString(k + ": " + v + "\n")
			}
		}
		return b.String()
	}
	for _, tc := range []struct{ job, want string }{
		{"plan", "SELECTED: ${{ inputs.fixtures }}"},
		{"plan", `"$fc" validate --fixtures-root cmd/floorcheck/fixtures "${names[@]}"`},
		{"plan", `"$fc" list --fixtures-root cmd/floorcheck/fixtures`},
		{"plan", "actions/upload-artifact@v6"},
		{"fixture", `"$bin/floorcheck" run "$FIXTURE"`},
		{"fixture", "FIXTURE: ${{ matrix.name }}"},
		{"fixture", "go-version: ${{ matrix.go }}"},
		{"fixture", "java-version: ${{ matrix.jdk }}"},
		{"fixture", "node-version: ${{ matrix.node }}"},
		{"fixture", "python-version: ${{ matrix.python }}"},
		{"fixture", "matrix.apt != ''\nset -euo pipefail\nsudo apt-get update -q"},
		{"fixture", "APT_PACKAGES: ${{ matrix.apt }}"},
		{"fixture", "sudo apt-get install -y -q --no-install-recommends $APT_PACKAGES"},
		{"fixture", "actions/upload-artifact@v6\nalways()"},
		{"fixture", "sparse-checkout: cmd/floorcheck/fixtures"},
		{"fixture", "\nalways()\nset -uo pipefail\nmkdir -p \"$RUNNER_TEMP/floor-obs\""},
		{"fixture", "RUN_EXIT: ${{ steps.run.outputs.exit }}"},
		{"fixture", `echo "work_kb=$(du -sk "$RUNNER_TEMP/floor-work"`},
		{"fixture", "df -k --output=used,avail /"},
		{"fixture", `} > "$RUNNER_TEMP/floor-obs/footprint.txt"`},
		{"summary", "pattern: floor-obs-*"},
		{"summary", "GITHUB_STEP_SUMMARY"},
	} {
		if !strings.Contains(steps(tc.job), tc.want) {
			t.Errorf("job %s lacks %q", tc.job, tc.want)
		}
	}

	// The summary job's is the run's only job summary, so it heads the run page.
	if strings.Contains(steps("fixture"), "GITHUB_STEP_SUMMARY") {
		t.Error("the fixture job writes a job summary; the run's summary would trail one per fixture")
	}

	fx := w.Jobs["fixture"]
	if fx.Strategy.Matrix != "${{ fromJSON(needs.plan.outputs.matrix) }}" {
		t.Errorf("fixture matrix = %q, want the plan job's matrix", fx.Strategy.Matrix)
	}
	if fx.Strategy.FailFast == nil || *fx.Strategy.FailFast {
		t.Error("the fixture matrix must set fail-fast: false, so one fixture's failure does not stop the others")
	}
	if fx.Strategy.MaxParallel <= 0 || fx.Strategy.MaxParallel > 40 {
		t.Errorf("max-parallel %d, want 1..40", fx.Strategy.MaxParallel)
	}
	for name, j := range w.Jobs {
		if j.TimeoutMinutes <= 0 {
			t.Errorf("job %s has no timeout", name)
		}
	}
	if !strings.Contains(w.Jobs["summary"].If, "!cancelled()") {
		t.Errorf("summary if %q: want it to run after failed fixtures", w.Jobs["summary"].If)
	}
}

// stepRun is the run script of the named job's step whose script contains marker.
func stepRun(t *testing.T, job, marker string) string {
	t.Helper()
	var w workflow
	if err := yaml.Unmarshal(readWorkflow(t), &w); err != nil {
		t.Fatal(err)
	}
	for _, s := range w.Jobs[job].Steps {
		if strings.Contains(s.Run, marker) {
			return s.Run
		}
	}
	t.Fatalf("job %s has no step running %q", job, marker)
	return ""
}

func needTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
}

// runScript runs script under bash in dir with env added, and returns its exit code.
func runScript(t *testing.T, dir, script string, env ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}

// TestFloorWorkflowSummary runs the summary job's script over observations written as the harness
// writes them: any regression fails the run (1); otherwise anything short of every planned fixture
// passing — an incomplete fixture, a missing or unreadable summary — is incomplete (2); only an
// all-pass run exits 0.
func TestFloorWorkflowSummary(t *testing.T) {
	needTools(t, "bash", "jq", "comm")
	script := stepRun(t, "summary", "GITHUB_STEP_SUMMARY")
	planned := []string{"a", "b", "c"}
	tests := []struct {
		name     string
		outcomes map[string]string // fixture → outcome; "damaged" writes an unreadable summary.json
		want     int
	}{
		{"all pass", map[string]string{"a": OutcomePass, "b": OutcomePass, "c": OutcomePass}, 0},
		{"one regressed", map[string]string{"a": OutcomePass, "b": OutcomeRegressed, "c": OutcomeIncomplete}, 1},
		{"one incomplete", map[string]string{"a": OutcomePass, "b": OutcomeIncomplete, "c": OutcomePass}, 2},
		{"one missing", map[string]string{"a": OutcomePass, "b": OutcomePass}, 2},
		{"one damaged", map[string]string{"a": OutcomePass, "b": "damaged", "c": OutcomePass}, 2},
		{"damaged beside a regression", map[string]string{"a": "damaged", "b": OutcomeRegressed, "c": OutcomePass}, 1},
		{"no observations", map[string]string{}, 2},
		{"all damaged", map[string]string{"a": "damaged", "b": "damaged", "c": "damaged"}, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, outcome := range tc.outcomes {
				d := filepath.Join(dir, "floor-observations", "floor-obs-"+name)
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
				data := []byte("{\"fixtures\": [")
				if outcome != "damaged" {
					var err error
					fs := FixtureSummary{Fixture: name, Outcome: outcome, Counts: Counts{Met: 3}, Unexpected: 7, Drift: 4,
						Expectations: []ExpectSummary{{Advisory: "CVE-9-" + name, Package: "m", Outcome: OutcomeMet, Floor: "reachable_candidate", Observed: "reachable_candidate"}}}
					switch outcome {
					case OutcomeRegressed:
						fs.Counts.Regressed, fs.Regressed = 1, []string{"CVE-1 lost"}
					case OutcomeIncomplete:
						fs.Counts.Incomplete, fs.Incomplete = 1, []string{"CVE-2 unjudged"}
					}
					data, err = json.Marshal(RunSummary{Schema: "x", Fixtures: []FixtureSummary{fs}})
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(d, "summary.json"), data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var inc []ListEntry
			for _, n := range planned {
				inc = append(inc, ListEntry{Name: n})
			}
			matrix, err := json.Marshal(map[string][]ListEntry{"include": inc})
			if err != nil {
				t.Fatal(err)
			}
			code, out := runScript(t, dir, script, "MATRIX="+string(matrix), "GITHUB_STEP_SUMMARY="+filepath.Join(dir, "step.md"))
			if code != tc.want {
				t.Errorf("exit %d, want %d\n%s", code, tc.want, out)
			}
			md, _ := os.ReadFile(filepath.Join(dir, "step.md"))
			if tc.outcomes["c"] == OutcomePass {
				for _, row := range []string{
					"| **c** | **pass** | - | **3** | - | - | **7** | **4** |",
					"| <sub>&nbsp;&nbsp;↳ CVE-9-c</sub><br><sup>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`m`</sup> |  |  | ✓ |  |  | | |",
				} {
					if !strings.Contains(string(md), row) {
						t.Errorf("the table lacks %q:\n%s", row, md)
					}
				}
			}
			verdict := map[int]string{0: "pass", 1: "regressed", 2: "incomplete"}[tc.want]
			if !strings.HasPrefix(string(md), "## ") || !strings.Contains(strings.SplitN(string(md), "\n", 2)[0], "Floor run "+verdict+": ") {
				t.Errorf("the summary does not open on the %s headline:\n%s", verdict, md)
			}
			if tc.want == 1 && !strings.Contains(string(md), "### Regressed\n\n- b: CVE-1 lost") {
				t.Errorf("the summary does not list the regression:\n%s", md)
			}
			for name, outcome := range tc.outcomes {
				if outcome == OutcomeIncomplete && !strings.Contains(string(md), "### Incomplete\n\n- "+name+": CVE-2 unjudged") {
					t.Errorf("the summary does not list %s's incomplete expectation:\n%s", name, md)
				}
			}
			unobserved := 0
			for _, n := range planned {
				if o, ok := tc.outcomes[n]; !ok || o == "damaged" {
					unobserved++
				}
			}
			if hasU := strings.Contains(string(md), fmt.Sprintf("· %d without an observation", unobserved)); hasU != (unobserved > 0) {
				t.Errorf("the headline miscounts the %d fixtures without an observation:\n%s", unobserved, md)
			}
			level := map[int]string{0: "::notice title=Floor run::", 1: "::error title=Floor run::", 2: "::warning title=Floor run::"}[tc.want]
			if !strings.Contains(out, level+strings.TrimPrefix(strings.SplitN(string(md), "\n", 2)[0], "## ")) {
				t.Errorf("the run does not annotate its headline at %q:\n%s", level, out)
			}
		})
	}
}

// TestFloorWorkflowScanTimeoutBound: the plan job refuses a scan budget that would outrun the fixture
// job's own timeout.
func TestFloorWorkflowScanTimeoutBound(t *testing.T) {
	needTools(t, "bash")
	run := stepRun(t, "plan", "SCAN_TIMEOUT")
	i := strings.Index(run, `fc="$RUNNER_TEMP`)
	if i < 0 {
		t.Fatal("the plan step's timeout check no longer precedes floorcheck")
	}
	check := run[:i]
	// A scheduled run has no inputs: every step that reads the budget falls back to one the check admits.
	fallback := regexp.MustCompile(`SCAN_TIMEOUT: \$\{\{ inputs\.scan-timeout \|\| '([^']*)' \}\}`)
	data := string(readWorkflow(t))
	if refs, fbs := strings.Count(data, "inputs.scan-timeout"), fallback.FindAllStringSubmatch(data, -1); len(fbs) != refs {
		t.Errorf("%d of %d scan-timeout reads fall back to a default; a scheduled run would pass an empty budget", len(fbs), refs)
	} else {
		for _, m := range fbs {
			if code, out := runScript(t, t.TempDir(), check, "SCAN_TIMEOUT="+m[1]); code != 0 {
				t.Errorf("scheduled budget %q refused: exit %d\n%s", m[1], code, out)
			}
		}
	}
	for in, want := range map[string]int{"40m": 0, "1m": 0, "60m": 0, "61m": 1, "0m": 1, "2h": 1, "40": 1, "": 1, "40m; true": 1, "0060m": 1, "08m": 1} {
		if code, out := runScript(t, t.TempDir(), check, "SCAN_TIMEOUT="+in); code != want {
			t.Errorf("scan-timeout %q: exit %d, want %d\n%s", in, code, want, out)
		}
	}
	var w workflow
	if err := yaml.Unmarshal(readWorkflow(t), &w); err != nil {
		t.Fatal(err)
	}
	// The job runs setup and checkout, the module warm-up, then the longest scan the plan job admits.
	const maxScan, setup = 60, 15
	if got, want := w.Jobs["fixture"].TimeoutMinutes, maxScan+int(warmTimeout/time.Minute)+setup; got < want {
		t.Errorf("fixture job timeout %dm, want at least %dm: a %dm scan, the %v warm-up and %dm of setup and checkout", got, want, maxScan, warmTimeout, setup)
	}
}

// TestFloorWorkflowMatrixKeys: every matrix key the fixture job reads is a field `floorcheck list`
// emits, so a renamed field cannot silently skip a runtime install.
func TestFloorWorkflowMatrixKeys(t *testing.T) {
	tags := map[string]bool{}
	rt := reflect.TypeFor[ListEntry]()
	for i := range rt.NumField() {
		tag, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		tags[tag] = true
	}
	data := string(readWorkflow(t))
	used := regexp.MustCompile(`matrix\.([a-z_]+)`).FindAllStringSubmatch(data, -1)
	if len(used) == 0 {
		t.Fatal("the workflow reads no matrix key")
	}
	for _, m := range used {
		if !tags[m[1]] {
			t.Errorf("the workflow reads matrix.%s, which floorcheck list does not emit", m[1])
		}
	}
}
