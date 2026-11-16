package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	if len(w.On) != 1 {
		t.Errorf("triggers = %d, want only workflow_dispatch", len(w.On))
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
		{"plan", `"$fc" validate --fixtures-root floor/fixtures "${names[@]}"`},
		{"plan", `"$fc" list --fixtures-root floor/fixtures`},
		{"plan", "actions/upload-artifact@v4"},
		{"fixture", `"$bin/floorcheck" run "$FIXTURE"`},
		{"fixture", "FIXTURE: ${{ matrix.name }}"},
		{"fixture", "go-version: ${{ matrix.go }}"},
		{"fixture", "java-version: ${{ matrix.jdk }}"},
		{"fixture", "node-version: ${{ matrix.node }}"},
		{"fixture", "python-version: ${{ matrix.python }}"},
		{"fixture", "actions/upload-artifact@v4\nalways()"},
		{"summary", "pattern: floor-obs-*"},
		{"summary", "GITHUB_STEP_SUMMARY"},
	} {
		if !strings.Contains(steps(tc.job), tc.want) {
			t.Errorf("job %s lacks %q", tc.job, tc.want)
		}
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
