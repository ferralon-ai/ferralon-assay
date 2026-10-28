//go:build unix

package scripts

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// stoppableScanner stands in for the scanner: it says "ready", says "TERM" each time it gets
// SIGTERM, and once the test writes to $STUB_RELEASE writes its Report and SARIF when
// $STUB_PUBLISHES is set, says "exit", and exits 7. Its stdout is the step's.
const stoppableScanner = `#!/usr/bin/env bash
trap 'echo TERM' TERM
cat "$STUB_RELEASE" >/dev/null &
c=$!
echo ready
until wait "$c"; do :; done
if [ -n "$STUB_PUBLISHES" ]; then
  : > "$IN_OUT/report.json"
  : > "$IN_OUT/report.sarif.json"
fi
echo exit
exit 7
`

// TestScanStepForwardsTheRunnersStop runs action.yml's scan step verbatim and stops it the way the
// runner cancels a step: SIGINT to the step's shell, then SIGTERM. The scanner gets TERM once, for
// the first signal only, the shell waits for it to finish publishing, and the step exits with the
// scanner's own status, as it also does when nothing stops it. The out-dir and sarif-file outputs
// are set only when the scanner wrote the files they name.
func TestScanStepForwardsTheRunnersStop(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	step := scanStep(t)
	cases := []struct {
		name      string
		signals   []syscall.Signal
		publishes bool
	}{
		{name: "not stopped", publishes: true},
		{name: "runner cancels", signals: []syscall.Signal{syscall.SIGINT, syscall.SIGTERM}, publishes: true},
		{name: "scanner fails before writing", signals: []syscall.Signal{syscall.SIGINT, syscall.SIGTERM}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "ferralon-assay-scan"), []byte(stoppableScanner), 0o755); err != nil {
				t.Fatal(err)
			}
			release := filepath.Join(root, "release")
			if err := syscall.Mkfifo(release, 0o600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(root, "github_output")

			// A guard against a hang, not a timing assertion: on expiry the whole group is killed,
			// which closes the pipe the test reads from.
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", step.Run)
			cmd.Dir = root
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
			cmd.Env = os.Environ()
			for k := range step.Env {
				cmd.Env = append(cmd.Env, k+"=")
			}
			cmd.Env = append(cmd.Env,
				"STUB_RELEASE="+release, "BIN_DIR="+bin, "PLUGIN_PATH_DIR="+bin, "RUNNER_TEMP="+root,
				"GITHUB_OUTPUT="+output, "IN_MODE=baseline", "IN_TARGET=.", "IN_OUT="+filepath.Join(root, "out"))
			if tc.publishes {
				cmd.Env = append(cmd.Env, "STUB_PUBLISHES=1")
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			lines := bufio.NewScanner(stdout)
			expect := func(want string) {
				t.Helper()
				if !lines.Scan() || lines.Text() != want {
					t.Fatalf("scanner said %q (%v), want %q", lines.Text(), lines.Err(), want)
				}
			}

			expect("ready")
			for i, sig := range tc.signals {
				if err := cmd.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					expect("TERM")
				}
			}
			w, err := os.OpenFile(release, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}

			expect("exit")

			var exit *exec.ExitError
			if err := cmd.Wait(); !errors.As(err, &exit) || exit.ExitCode() != 7 {
				t.Fatalf("step ended %v, want the scanner's own exit status 7", err)
			}
			got, err := os.ReadFile(output)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			for _, key := range []string{"out-dir=", "sarif-file="} {
				if strings.Contains(string(got), key) != tc.publishes {
					t.Errorf("step output %q: %s set = %v, want %v", got, key, !tc.publishes, tc.publishes)
				}
			}
		})
	}
}
