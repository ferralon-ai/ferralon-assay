package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestActionHandsOverTheJobsGOWORK runs action.yml's scan step verbatim against a stub scanner that
// records the ASSAY_SUBJECT_GOWORK it was started with. An explicit subject-gowork input wins; with
// none, the job's own GOWORK is handed over, so a job that builds with GOWORK=off is scanned with it
// off; with neither, nothing is declared and the scanner discovers the go.work as before.
func TestActionHandsOverTheJobsGOWORK(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	step := scanStep(t)
	if got, want := step.Env["ASSAY_SUBJECT_GOWORK"], "${{ inputs.subject-gowork }}"; got != want {
		t.Fatalf("scan step env ASSAY_SUBJECT_GOWORK = %q, want %q", got, want)
	}
	for _, tc := range []struct {
		name  string
		input string // the subject-gowork input, as the step env renders it
		job   string // the job's GOWORK; "" leaves it unset
		want  string
	}{
		{name: "neither", want: ""},
		{name: "job off", job: "off", want: "off"},
		{name: "job go.work", job: "/work/repo/go.work", want: "/work/repo/go.work"},
		{name: "job auto", job: "auto", want: "auto"}, // the go command's own name for none; the scanner reads it so
		{name: "input over job", input: "go.work", job: "off", want: "go.work"},
		{name: "input alone", input: "off", want: "off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			seen := filepath.Join(root, "gowork")
			stub := "#!/bin/sh\nprintf '%s' \"$ASSAY_SUBJECT_GOWORK\" >\"$STUB_GOWORK\"\n"
			if err := os.WriteFile(filepath.Join(bin, "ferralon-assay-scan"), []byte(stub), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", step.Run)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "GOWORK=")
			for k := range step.Env {
				cmd.Env = append(cmd.Env, k+"=")
			}
			cmd.Env = append(cmd.Env,
				"STUB_GOWORK="+seen, "BIN_DIR="+bin, "PLUGIN_PATH_DIR="+bin, "RUNNER_TEMP="+root,
				"GITHUB_OUTPUT="+filepath.Join(root, "github_output"),
				"IN_MODE=baseline", "IN_TARGET=.", "IN_OUT="+filepath.Join(root, "out"),
				"ASSAY_SUBJECT_GOWORK="+tc.input)
			if tc.job != "" {
				cmd.Env = append(cmd.Env, "GOWORK="+tc.job)
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("scan step failed: %v\n%s", err, out)
			}
			got, err := os.ReadFile(seen)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("scanner got ASSAY_SUBJECT_GOWORK %q, want %q", got, tc.want)
			}
		})
	}
}
