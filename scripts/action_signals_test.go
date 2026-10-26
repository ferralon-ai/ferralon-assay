// Hermetic check that action.yml hands the scanner the signals the bundle step verified. It reads the
// "Run the Ferralon Assay" step from action.yml, runs its shell VERBATIM against a stub scanner that
// records its arguments, and asserts on what the scanner was given — the wiring itself, not a
// transcription of it. No network, no scanner build.
package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type actionStep struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}

// scanStep returns action.yml's scan step.
func scanStep(t *testing.T) actionStep {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []actionStep `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(raw, &action); err != nil {
		t.Fatal(err)
	}
	for _, s := range action.Runs.Steps {
		if s.ID == "run" {
			return s
		}
	}
	t.Fatal("action.yml has no step with id: run")
	return actionStep{}
}

// runScanStep runs the scan step's shell with env and a stub scanner, and returns the arguments the
// scanner was called with, one per line.
func runScanStep(t *testing.T, step actionStep, env ...string) []string {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	argsLog := filepath.Join(root, "args")
	stub := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >\"$STUB_ARGS\"\n"
	if err := os.WriteFile(filepath.Join(bin, "ferralon-assay-scan"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", step.Run)
	cmd.Dir = root
	// Every variable the step declares starts empty, as an unset input renders, so the shell's
	// `set -u` sees the step's whole env; the cases then set what they exercise.
	cmd.Env = os.Environ()
	for k := range step.Env {
		cmd.Env = append(cmd.Env, k+"=")
	}
	cmd.Env = append(cmd.Env,
		"STUB_ARGS="+argsLog, "BIN_DIR="+bin, "PLUGIN_PATH_DIR="+bin, "RUNNER_TEMP="+root,
		"GITHUB_OUTPUT="+filepath.Join(root, "github_output"),
		"IN_MODE=baseline", "IN_TARGET=.", "IN_OUT="+filepath.Join(root, "out"))
	cmd.Env = append(cmd.Env, env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scan step failed: %v\n%s", err, out)
	}
	got, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(got)), "\n")
}

// flagValue returns the value passed after flag, and whether it was passed.
func flagValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// TestActionPassesVerifiedSignals: the scan step reads the bundle step's signals-path output (the
// output fetch-corpus-bundle.sh emits for a verified signals.json.gz) and passes it to the scanner as
// -advisory-signals; with no release read — a pre-checked-out corpus directory — it passes none, so
// the scanner's default, the directory's own signals.json, applies.
func TestActionPassesVerifiedSignals(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	step := scanStep(t)
	if got, want := step.Env["IN_ADVISORY_SIGNALS"], "${{ steps.corpus-bundle.outputs.signals-path }}"; got != want {
		t.Fatalf("scan step env IN_ADVISORY_SIGNALS = %q, want %q", got, want)
	}

	t.Run("bundle route", func(t *testing.T) {
		signals := filepath.Join(t.TempDir(), "signals.json.gz")
		args := runScanStep(t, step, "IN_ADVISORY_CORPUS_REPO=acme/corpus", "IN_ADVISORY_CORPUS_POLICY="+fakePolicy,
			"IN_ADVISORY_SIGNALS="+signals)
		if got, ok := flagValue(args, "-advisory-signals"); !ok || got != signals {
			t.Fatalf("scanner args %q: -advisory-signals = %q (passed %v), want %s", args, got, ok, signals)
		}
	})

	t.Run("corpus directory", func(t *testing.T) {
		tree := t.TempDir()
		args := runScanStep(t, step, "IN_ADVISORY_CORPUS="+tree)
		if got, _ := flagValue(args, "-advisory-corpus"); got != tree {
			t.Fatalf("scanner args %q: -advisory-corpus = %q, want %s", args, got, tree)
		}
		if _, ok := flagValue(args, "-advisory-signals"); ok {
			t.Fatalf("scanner args %q pass -advisory-signals for a corpus directory, overriding its own signals.json", args)
		}
	})
}
