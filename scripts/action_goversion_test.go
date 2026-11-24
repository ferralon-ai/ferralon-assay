package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestActionHandsOverSubjectGoVersion runs action.yml's scan step verbatim against a stub scanner that
// records the ASSAY_SUBJECT_GO_VERSION it was started with. A set subject-go-version input reaches the
// scanner under that name, over any value the job set; an empty input leaves the job's own value, or
// none, exactly as before the input existed.
func TestActionHandsOverSubjectGoVersion(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	step := scanStep(t)
	if got, want := step.Env["IN_SUBJECT_GO_VERSION"], "${{ inputs.subject-go-version }}"; got != want {
		t.Fatalf("scan step env IN_SUBJECT_GO_VERSION = %q, want %q", got, want)
	}
	if _, ok := step.Env["ASSAY_SUBJECT_GO_VERSION"]; ok {
		t.Fatal("scan step env sets ASSAY_SUBJECT_GO_VERSION directly; an empty input would then erase the job's own value")
	}
	for _, tc := range []struct {
		name  string
		input string // the subject-go-version input, as the step env renders it
		job   string // ASSAY_SUBJECT_GO_VERSION in the job's env; "" leaves it unset
		want  string
	}{
		{name: "neither", want: ""},
		{name: "input alone", input: "go1.22.5", want: "go1.22.5"},
		{name: "job alone", job: "go1.21.3", want: "go1.21.3"},
		{name: "input over job", input: "go1.22.5", job: "go1.21.3", want: "go1.22.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			seen := filepath.Join(root, "goversion")
			stub := "#!/bin/sh\nprintf '%s' \"${ASSAY_SUBJECT_GO_VERSION:-}\" >\"$STUB_GOVERSION\"\n"
			if err := os.WriteFile(filepath.Join(bin, "ferralon-assay-scan"), []byte(stub), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", step.Run)
			cmd.Dir = root
			var env []string
			for _, kv := range os.Environ() {
				if !strings.HasPrefix(kv, "ASSAY_SUBJECT_GO_VERSION=") {
					env = append(env, kv)
				}
			}
			cmd.Env = env
			for k := range step.Env {
				cmd.Env = append(cmd.Env, k+"=")
			}
			cmd.Env = append(cmd.Env,
				"STUB_GOVERSION="+seen, "BIN_DIR="+bin, "PLUGIN_PATH_DIR="+bin, "RUNNER_TEMP="+root,
				"GITHUB_OUTPUT="+filepath.Join(root, "github_output"),
				"IN_MODE=baseline", "IN_TARGET=.", "IN_OUT="+filepath.Join(root, "out"),
				"IN_SUBJECT_GO_VERSION="+tc.input)
			if tc.job != "" {
				cmd.Env = append(cmd.Env, "ASSAY_SUBJECT_GO_VERSION="+tc.job)
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("scan step failed: %v\n%s", err, out)
			}
			got, err := os.ReadFile(seen)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("scanner got ASSAY_SUBJECT_GO_VERSION %q, want %q", got, tc.want)
			}
		})
	}
}
