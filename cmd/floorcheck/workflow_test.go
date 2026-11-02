package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// workflow is the part of .github/workflows/floor.yml the floor run's contract rests on.
type workflow struct {
	// On is kept by trigger name: a bare `workflow_dispatch:` decodes to a null node.
	On   map[string]yaml.Node `yaml:"on"`
	Jobs map[string]struct {
		If             string `yaml:"if"`
		TimeoutMinutes int    `yaml:"timeout-minutes"`
		Strategy       struct {
			FailFast *bool  `yaml:"fail-fast"`
			Matrix   string `yaml:"matrix"`
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

func loadWorkflow(t *testing.T) workflow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "floor.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var w workflow
	if err := yaml.Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

// TestFloorWorkflow pins what the floor run promises: a nightly schedule off the hour and a manual
// trigger, a matrix over floor/targets.json with every job bounded at 30 minutes, the summary
// uploaded as an artifact, a Slack alert only on failure and only with its webhook set, and a
// missing demo token that ends the run with a notice instead of a failure.
func TestFloorWorkflow(t *testing.T) {
	w := loadWorkflow(t)

	var schedule []struct {
		Cron string `yaml:"cron"`
	}
	node := w.On["schedule"]
	if err := node.Decode(&schedule); err != nil || len(schedule) != 1 {
		t.Fatalf("want one schedule, got %d (%v)", len(schedule), err)
	}
	fields := strings.Fields(schedule[0].Cron)
	if len(fields) != 5 || strings.ContainsAny(fields[1], ",-/*") || fields[2] != "*" || fields[3] != "*" || fields[4] != "*" {
		t.Errorf("cron %q is not once a day", schedule[0].Cron)
	}
	if m, err := strconv.Atoi(fields[0]); err != nil || m == 0 {
		t.Errorf("cron %q does not run at an off-hour minute", schedule[0].Cron)
	}
	if _, ok := w.On["workflow_dispatch"]; !ok {
		t.Error("no workflow_dispatch trigger")
	}
	if len(w.On) != 2 {
		t.Errorf("triggers = %d, want only schedule and workflow_dispatch", len(w.On))
	}

	for name, j := range w.Jobs {
		if j.TimeoutMinutes <= 0 || j.TimeoutMinutes > 30 {
			t.Errorf("job %s: timeout-minutes %d, want 1..30", name, j.TimeoutMinutes)
		}
	}

	// steps returns the job's steps' run scripts, uses and ifs joined, for substring checks.
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
		{"secrets", "FLOOR_DEMO_TOKEN: ${{ secrets.FLOOR_DEMO_TOKEN }}"},
		{"secrets", "::notice title=Floor run skipped::Secret FLOOR_DEMO_TOKEN is not set"},
		{"build", `floorcheck" matrix -targets floor/targets.json`},
		{"build", "actions/upload-artifact@v4"},
		{"scan", "token: ${{ secrets.FLOOR_DEMO_TOKEN }}"},
		{"scan", "bash assay/floor/scan.sh"},
		{"check", `floorcheck" check -targets floor/targets.json`},
		{"check", "GITHUB_STEP_SUMMARY"},
		{"check", "actions/upload-artifact@v4\n${{ !cancelled() }}"},
		{"check", "path: floor-summary"},
		{"alert", "FLOOR_SLACK_WEBHOOK: ${{ secrets.FLOOR_SLACK_WEBHOOK }}"},
	} {
		if !strings.Contains(steps(tc.job), tc.want) {
			t.Errorf("job %s lacks %q", tc.job, tc.want)
		}
	}

	scan := w.Jobs["scan"]
	if scan.Strategy.Matrix != "${{ fromJSON(needs.build.outputs.matrix) }}" {
		t.Errorf("scan matrix = %q, want the build job's matrix from floor/targets.json", scan.Strategy.Matrix)
	}
	if scan.Strategy.FailFast == nil || *scan.Strategy.FailFast {
		t.Error("scan matrix must set fail-fast: false, so one repo's failure does not stop the others")
	}

	// Gates: the scanning jobs run only with the demo token; the alert only with the webhook, and
	// only when something failed.
	for _, tc := range []struct{ job, want string }{
		{"build", "needs.secrets.outputs.demo-token == 'true'"},
		{"alert", "needs.secrets.outputs.demo-token == 'true'"},
		{"alert", "needs.secrets.outputs.slack == 'true'"},
		{"alert", "needs.check.result == 'failure'"},
		{"alert", "needs.scan.result == 'failure'"},
	} {
		if !strings.Contains(w.Jobs[tc.job].If, tc.want) {
			t.Errorf("job %s if %q lacks %q", tc.job, w.Jobs[tc.job].If, tc.want)
		}
	}
}
