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
// scanner was called with, one per line, and the step's combined output.
func runScanStep(t *testing.T, step actionStep, env ...string) ([]string, string) {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	argsLog := filepath.Join(root, "args")
	// A usage request prints STUB_USAGE and exits non-zero, as Go's flag package does for -h; any
	// other call records its arguments.
	stub := "#!/bin/sh\nif [ \"$2\" = -h ]; then printf '%s\\n' \"$STUB_USAGE\" >&2; exit 2; fi\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done >\"$STUB_ARGS\"\n"
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
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scan step failed: %v\n%s", err, out)
	}
	got, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(got)), "\n"), string(out)
}

// Usage text as Go's flag package prints it: a scanner release that carries -advisory-signals, and
// one that predates it (-advisory-signals-max-age alone must not count as the flag).
const (
	usageWithSignals = "Usage of baseline:\n  -advisory-corpus string\n    \tcorpus\n" +
		"  -advisory-signals string\n    \tsignals\n  -advisory-signals-max-age duration\n    \tage\n"
	usageWithoutSignals = "Usage of baseline:\n  -advisory-corpus string\n    \tcorpus\n" +
		"  -advisory-signals-max-age duration\n    \tage\n"
)

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
// -advisory-signals when the scanner's usage lists that flag. A scanner release that predates it
// scans without the flag, which it would reject outright, and the job log warns. With no release
// read — a pre-checked-out corpus directory — it passes none, so the scanner's default, the
// directory's own signals.json, applies.
func TestActionPassesVerifiedSignals(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	step := scanStep(t)
	if got, want := step.Env["IN_ADVISORY_SIGNALS"], "${{ steps.corpus-bundle.outputs.signals-path }}"; got != want {
		t.Fatalf("scan step env IN_ADVISORY_SIGNALS = %q, want %q", got, want)
	}
	signals := filepath.Join(t.TempDir(), "signals.json.gz")
	tree := t.TempDir()
	cases := []struct {
		name        string
		env         []string
		wantSignals bool
		wantWarning bool
	}{
		{
			name: "bundle route, scanner carries the flag",
			env: []string{"IN_ADVISORY_CORPUS_REPO=acme/corpus", "IN_ADVISORY_CORPUS_POLICY=" + fakePolicy,
				"IN_ADVISORY_SIGNALS=" + signals, "STUB_USAGE=" + usageWithSignals},
			wantSignals: true,
		},
		{
			name: "bundle route, scanner predates the flag",
			env: []string{"IN_ADVISORY_CORPUS_REPO=acme/corpus", "IN_ADVISORY_CORPUS_POLICY=" + fakePolicy,
				"IN_ADVISORY_SIGNALS=" + signals, "STUB_USAGE=" + usageWithoutSignals},
			wantWarning: true,
		},
		{
			name: "corpus directory",
			env:  []string{"IN_ADVISORY_CORPUS=" + tree, "STUB_USAGE=" + usageWithSignals},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, out := runScanStep(t, step, tc.env...)
			got, ok := flagValue(args, "-advisory-signals")
			if ok != tc.wantSignals || (ok && got != signals) {
				t.Fatalf("scanner args %q: -advisory-signals = %q (passed %v), want passed %v", args, got, ok, tc.wantSignals)
			}
			if warned := strings.Contains(out, "::warning title=Advisory signals not passed::"); warned != tc.wantWarning {
				t.Fatalf("warning emitted %v, want %v; output:\n%s", warned, tc.wantWarning, out)
			}
		})
	}
}
